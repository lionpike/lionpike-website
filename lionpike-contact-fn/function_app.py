import json
import logging
import requests
import azure.functions as func
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

KEY_VAULT_URL = "https://lionpike-kv.vault.azure.net/"
RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"
GRAPH_SEND_URL = "https://graph.microsoft.com/v1.0/users/{sender}/sendMail"
SENDER = "pauriccollins@lionpike.com"
RECIPIENT = "info@lionpike.com"

logger = logging.getLogger(__name__)


def get_secrets() -> dict:
    credential = ManagedIdentityCredential()
    client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)
    return {
        "recaptcha_secret": client.get_secret("recaptcha-secret-key").value,
        "tenant_id":        client.get_secret("mailer-tenant-id").value,
        "client_id":        client.get_secret("mailer-client-id").value,
        "client_secret":    client.get_secret("mailer-client-secret").value,
    }


def verify_recaptcha(token: str, secret: str) -> bool:
    response = requests.post(RECAPTCHA_VERIFY_URL, data={
        "secret": secret,
        "response": token,
    })
    result = response.json()
    score = result.get("score", 0)
    logger.info(f"reCAPTCHA score: {score}")
    return result.get("success") and score >= 0.5


def get_graph_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    response = requests.post(url, data={
        "grant_type":    "client_credentials",
        "client_id":     client_id,
        "client_secret": client_secret,
        "scope":         "https://graph.microsoft.com/.default",
    })
    response.raise_for_status()
    return response.json()["access_token"]


def send_email(token: str, name: str, email: str, company: str, message: str) -> None:
    payload = {
        "message": {
            "subject": f"Lion Pike Contact Form — {name}",
            "body": {
                "contentType": "Text",
                "content": (
                    f"Name: {name}\n"
                    f"Email: {email}\n"
                    f"Company: {company}\n\n"
                    f"Message:\n{message}"
                ),
            },
            "toRecipients": [{"emailAddress": {"address": RECIPIENT}}],
        }
    }
    response = requests.post(
        GRAPH_SEND_URL.format(sender=SENDER),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json=payload,
    )
    response.raise_for_status()


@app.route(route="contact", methods=["GET", "POST", "OPTIONS"])
def contact(req: func.HttpRequest) -> func.HttpResponse:
    headers = {
        "Access-Control-Allow-Origin": "https://www.lionpike.com",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
    }

    if req.method == "GET":
        return func.HttpResponse("OK", status_code=200, headers=headers)

    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid request", status_code=400, headers=headers)

    name     = body.get("name", "").strip()
    email    = body.get("email", "").strip()
    company  = body.get("company", "").strip()
    message  = body.get("message", "").strip()
    token    = body.get("recaptcha_token", "").strip()

    if not all([name, email, message, token]):
        return func.HttpResponse("Missing required fields", status_code=400, headers=headers)

    try:
        secrets = get_secrets()

        if not verify_recaptcha(token, secrets["recaptcha_secret"]):
            logger.warning("reCAPTCHA verification failed")
            return func.HttpResponse("reCAPTCHA verification failed", status_code=403, headers=headers)

        graph_token = get_graph_token(
            secrets["tenant_id"],
            secrets["client_id"],
            secrets["client_secret"],
        )
        send_email(graph_token, name, email, company, message)
        logger.info(f"Contact form submitted by {name} ({email})")
        return func.HttpResponse("OK", status_code=200, headers=headers)

    except Exception as e:
        logger.error(f"Contact form error: {e}")
        return func.HttpResponse("Server error", status_code=500, headers=headers)