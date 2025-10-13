from hashlib import sha256
from hmac import compare_digest, new
from os import urandom
from secrets import token_hex

from app.config.config import config

APP_CONFIG = config.get("app")
BEARER_TOKEN = str(APP_CONFIG.get("bearer_token"))


def _randomize_token(token: str) -> str:
    """
    Generate a randomized SHA-256 hash from the given token.
    Parameters:
        token (str): The input token to randomize.
    Returns:
        str: hexadecimal SHA-256 hash token + random bytes.
    """
    return sha256(token.encode() + urandom(16)).hexdigest()


BEARER_TOKEN_HASH = sha256(_randomize_token(BEARER_TOKEN).encode()).hexdigest()


def generate_csrf_token() -> str:
    return token_hex(16)


def generate_bearer_token(csrf_token: str, bearer_token_hash: str = BEARER_TOKEN_HASH) -> str:
    """
    Generate a HMAC-based bearer token using a CSRF token and a server-side secret hash.
    HMAC is computed with SHA-256 using `bearer_token_hash` as key and
    `csrf_token` as message. This links bearer token and CSRF token for verificatoin.
    Parameters:
        csrf_token (str): CSRF token.
        bearer_token_hash (str, optional): Server-side secret hash used as the HMAC key.
            Defaults to the global BEARER_TOKEN_HASH.
    Returns:
        str: A hexadecimal string representing the HMAC-based bearer token.
    """
    return new(
        key=bearer_token_hash.encode(),
        msg=csrf_token.encode(),
        digestmod=sha256,
    ).hexdigest()


def decode_and_verify_bearer_token(token: str, csrf_token: str) -> bool:
    """
    Verify that a provided bearer token is valid for the given CSRF token.
    Compares the provided `token` with the expected HMAC generated from
    the CSRF token using the server-side secret hash. Uses `hmac.compare_digest`
    to prevent timing attacks.
    Parameters:
        token (str): bearer token to verify.
        csrf_token (str): CSRF token 'linked' with the bearer token.
    Returns:
        bool: True valid, else False.
    """
    return compare_digest(token, generate_bearer_token(csrf_token))
