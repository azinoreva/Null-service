import json, os, firebase_admin
import requests
from firebase_admin import credentials
from firebase_admin import messaging

from app.log import logger


if not firebase_admin._apps:
    try:
        pass
        # logger.info("Firebase admin app not initialized; loading credentials")
        # firebase_config = json.loads(os.getenv("FIREBASE_CONFIG"))
        # cred = credentials.Certificate(firebase_config)
        # firebase_admin.initialize_app(cred)
        # logger.info("Firebase admin app initialized successfully")
    except Exception as exc:  # pragma: no cover - relies on Firebase service
        logger.error("Failed to initialize Firebase admin app", exc_info=exc)
        raise
else:
    logger.info("Firebase admin app already initialized")


def send_to_individual(token:str, title: str, body: str, data: dict = None):
    payload_data = data or {}
    logger.info("Preparing individual notification for token %s with data=%s", token, payload_data)
    message = messaging.Message(
        notification=messaging.Notification(
            title=title,
            body=body
        ),
        data=payload_data,
        token=token
    )

    try:
        logger.info("Sending individual notification %s/%s to token %s", title, body, token)
        response = messaging.send(message)
        logger.info("Individual send response: %s", response)
    except Exception as exc:  # pragma: no cover - relies on Firebase service
        logger.exception("Failed to send Firebase notification to %s", token, exc_info=exc)
        return None
    return response



PROJECT_ID = "chefyard-d29ca"

def send_push(token, title, body, data=None):
    pass
    """url = f"https://fcm.googleapis.com/v1/projects/{PROJECT_ID}/messages:send"
    payload = {
        "message": {
            "token": token,
            "notification": {
                "title": title,
                "body": body
            },
            "data": data or {}
        }
    }
    logger.info("Preparing push request for token %s with payload %s", token, payload)

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        res = requests.post(url, headers=headers, json=payload)
        logger.info("Push response status=%s body=%s", res.status_code, res.text)
        res.raise_for_status()
        the_json = res.json()
        logger.info("Push request succeeded with json %s", the_json)
        return the_json
    except requests.RequestException as exc:
        logger.error("Push request to token %s failed", token, exc_info=exc)
        return None
"""
