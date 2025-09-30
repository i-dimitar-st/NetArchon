import hmac
from hashlib import sha256
from secrets import token_hex

from app.config.config import config

APP_CONFIG = config.get("app")
BEARER_TOKEN = str(APP_CONFIG.get("bearer_token"))
BEARER_TOKEN_HASH = sha256(BEARER_TOKEN.encode()).hexdigest()


def generate_csrf_token() -> str:
    return token_hex(16)


def generate_bearer_token(csrf_token: str) -> str:
    """
    Generate a HMAC token from BEARER_TOKEN_HASH + csrf_token.
    """
    return hmac.new(
        key=BEARER_TOKEN_HASH.encode(),
        msg=csrf_token.encode(),
        digestmod=sha256,
    ).hexdigest()


def decode_and_verify_bearer_token(token: str, csrf_token: str) -> bool:
    """
    Verify provided token matches expected HMAC.
    """
    return hmac.compare_digest(token, generate_bearer_token(csrf_token))
