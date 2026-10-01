import base64
import hashlib
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwcrypto import jwe, jwk
from jwcrypto.common import base64url_encode
import jwt

from app.models.user_model import RecoveryPolicy
from app.utils.config import settings
from . import _redis


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def create_passport(user_id, public_key) -> str:
    if isinstance(user_id, bytes):
        user_id = user_id.decode("utf-8")
    if isinstance(public_key, bytes):
        public_key = public_key.decode("utf-8")

    payload = {
        "v": 1,
        "typ": "passport",
        "sub": user_id,
        "pub": public_key,
        "exp": int((datetime.now(timezone.utc) + timedelta(days=30)).timestamp()),
    }

    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = load_private_key().sign(payload_bytes)  # Ed25519

    # Single string: <payload>.<signature>
    return f"{_b64u_encode(payload_bytes)}.{signature.hex()}"


def verify_passport(passport: str) -> dict:
    """Returns the payload if valid, otherwise raises ValueError."""
    try:
        payload_part, sig_part = passport.split(".")
        payload_bytes = _b64u_decode(payload_part)
        signature = bytes.fromhex(sig_part)
        load_private_key().public_key().verify(signature, payload_bytes)
        payload = json.loads(payload_bytes)
    except (AttributeError, ValueError, InvalidSignature):
        raise ValueError("invalid passport")

    if payload.get("typ") != "passport" or payload.get("v") != 1:
        raise ValueError("invalid passport")
    if payload["exp"] < datetime.now(timezone.utc).timestamp():
        raise ValueError("passport expired")

    return payload

bearer_scheme = HTTPBearer(auto_error=False)

REFRESH_TTL_SECONDS = 24 * 60 * 60          # refresh lifetime
BLOCKLIST_TTL_SECONDS = 30 * 24 * 60 * 60   # passport jti block lifetime


SERVER_KEY_DIR = Path(__file__).resolve().parent.parent.parent
SERVER_PRIVATE_KEY_FILE = SERVER_KEY_DIR / "server_private_key.pem"
SERVER_PUBLIC_KEY_FILE = SERVER_KEY_DIR / "server_public_key.pem"


def _server_key_bytes(env_value: str, pem_path: Path, what: str) -> bytes:
    """PEM bytes for the server's Ed25519 key.

    Deployment passes the key base64 encoded in the environment. Locally we
    fall back to the .pem next to the repo, so signing works without having to
    copy the key into .env by hand.
    """
    if env_value:
        return base64.b64decode(env_value)
    if not pem_path.exists():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Server {what} is not configured (set the env var or provide {pem_path.name})",
        )
    return pem_path.read_bytes()


@lru_cache(maxsize=1)
def load_private_key():
    return serialization.load_pem_private_key(
        _server_key_bytes(settings.server_private_key, SERVER_PRIVATE_KEY_FILE,
                          "private key"),
        password=None,
    )


@lru_cache(maxsize=1)
def load_public_key():
    return serialization.load_pem_public_key(
        _server_key_bytes(settings.server_public_key, SERVER_PUBLIC_KEY_FILE,
                          "public key")
    )


def sign_user_id(user_id):
    """Sign a user_id string with the server's private key."""
    if isinstance(user_id, str):
        user_id = user_id.encode("utf-8")
    signature = load_private_key().sign(user_id)
    return signature.hex()


def verify_user_id(user_id, signature_hex):
    """Verify a user_id against a hex-encoded signature."""
    if isinstance(user_id, str):
        user_id = user_id.encode("utf-8")
    signature = bytes.fromhex(signature_hex)
    try:
        load_public_key().verify(signature, user_id)
        return True
    except InvalidSignature:
        return False


def _get_jws_secret() -> str:
    if not settings.jwe_secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JWS secret is not configured",
        )
    return settings.jwe_secret


def _refresh_key(refresh_id: str) -> str:
    return f"refresh:{refresh_id}"


def _blocked_jti_key(jti: str) -> str:
    return f"blocked_jti:{jti}"


async def _decode_jws(token: str) -> dict[str, Any]:
    secret = _get_jws_secret()
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


# ---------------------------------------------------------------------------
# Access tokens
# ---------------------------------------------------------------------------

def create_access_token(
    user_id: str,
    jti: str | None = None,
    expires_minutes: int | None = None,
) -> str:
    exp_minutes = expires_minutes if expires_minutes is not None else settings.jwe_exp_minutes
    secret = _get_jws_secret()
    payload: dict[str, Any] = {
        "sub": user_id,
        "jti": jti or str(uuid4()),
        "iat": int(time.time()),
        "exp": int(time.time()) + (exp_minutes * 60),
        "type": "access",
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def create_annotator_token(annotator_id: str, expires_minutes: int | None = None) -> str:
    exp_minutes = expires_minutes if expires_minutes is not None else settings.jwe_exp_minutes
    secret = _get_jws_secret()
    payload: dict[str, Any] = {
        "sub": annotator_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + (exp_minutes * 60),
        "type": "annotator",
    }
    return jwt.encode(payload, secret, algorithm="HS256")


async def verify_access_token(token: str) -> dict[str, Any]:
    payload = await _decode_jws(token)
    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    if not payload.get("sub"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token subject missing")
    return payload


async def require_jwe_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> dict[str, Any]:
    if not credentials or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    token = credentials.credentials.strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    payload = await verify_access_token(token)
    request.state.user_id = payload.get("sub")
    return payload


async def require_annotator_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> dict[str, Any]:
    if not credentials or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    token = credentials.credentials.strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    payload = await _decode_jws(token)
    if payload.get("type") != "annotator":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong token type")
    if not payload.get("sub"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token subject missing")

    request.state.user_id = payload.get("sub")
    return payload


# ---------------------------------------------------------------------------
# Refresh tokens + session store (B: rotation with reuse detection)
# ---------------------------------------------------------------------------

def create_refresh_token(
    user_id: str,
    jti: str | None = None,
    refresh_id: str | None = None,
    expires_minutes: int | None = None,
) -> str:
    """Mint a refresh token.

    jti is the *session* id: pass the same one the access token carries so a
    single revoke (see revoke_session) kills the whole session, and so the
    reuse check in rotate_refresh_token has something to match on.
    refresh_id identifies this specific token's row in Redis, which is what
    rotation consumes and reuse detection looks for.
    """
    exp_minutes = expires_minutes if expires_minutes is not None else REFRESH_TTL_SECONDS // 60
    secret = _get_jws_secret()
    payload: dict[str, Any] = {
        "sub": user_id,
        "jti": jti or str(uuid4()),
        "rid": refresh_id or secrets.token_urlsafe(32),
        "iat": int(time.time()),
        "exp": int(time.time()) + (exp_minutes * 60),
        "type": "refresh_token",
    }
    return jwt.encode(payload, secret, algorithm="HS256")


async def issue_session(
    user_id: str,
    jti: str | None = None,
    access_expires_minutes: int | None = None,
    refresh_expires_minutes: int | None = None,
) -> dict[str, str]:
    """
    Call this once a caller has been proven to own [user_id] (password, passport
    or invitation). Mints the access+refresh pair and writes the refresh row so
    rotation and reuse detection have something to work with.

    Returns the pair plus the session jti they share.
    """
    session_jti = jti or str(uuid4())
    refresh_id = secrets.token_urlsafe(32)
    refresh_ttl = (
        refresh_expires_minutes * 60
        if refresh_expires_minutes is not None
        else REFRESH_TTL_SECONDS
    )
    refresh_exp = int(time.time()) + refresh_ttl

    await _redis.set(
        _refresh_key(refresh_id),
        json.dumps({"sub": user_id, "jti": session_jti, "exp": refresh_exp}),
        ex=refresh_ttl,
    )

    return {
        "access_token": create_access_token(
            user_id, session_jti, access_expires_minutes
        ),
        "refresh_token": create_refresh_token(
            user_id, session_jti, refresh_id, refresh_expires_minutes
        ),
        "jti": session_jti,
    }


async def verify_refresh_token(
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> dict[str, Any]:
    """FastAPI dependency: returns the refresh payload. Does NOT rotate."""
    if not credentials or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    token = credentials.credentials.strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    payload = await _decode_jws(token)
    if payload.get("type") != "refresh_token":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    if not payload.get("sub") or not payload.get("rid") or not payload.get("jti"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed refresh token")
    return payload


async def rotate_refresh_token(payload: dict[str, Any]) -> dict[str, str]:
    """
    Call this inside the refresh endpoint after verify_refresh_token.
    Returns a fresh access+refresh pair, or raises 401.
    """
    jti = payload["jti"]
    refresh_id = payload["rid"]

    # If the passport jti has been blocked (logout, re-login elsewhere), kill it.
    if await _redis.get(_blocked_jti_key(jti)):
        await _redis.delete(_refresh_key(refresh_id))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session revoked")

    stored = await _redis.get(_refresh_key(refresh_id))
    if stored is None:
        # Refresh row gone: either already rotated or revoked. Treat as reuse.
        await _redis.set(_blocked_jti_key(jti), "1", ex=BLOCKLIST_TTL_SECONDS)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token reuse detected")

    await _redis.delete(_refresh_key(refresh_id))
    return await issue_session(payload["sub"], jti)


async def revoke_session(payload: dict[str, Any]) -> None:
    """
    Logout: block the passport jti and drop the refresh row.
    Everything carrying this jti (access, refresh) dies within one access-TTL.
    """
    jti = payload.get("jti")
    refresh_id = payload.get("rid")
    if jti:
        await _redis.set(_blocked_jti_key(jti), "1", ex=BLOCKLIST_TTL_SECONDS)
    if refresh_id:
        await _redis.delete(_refresh_key(refresh_id))
        

def _derive_encryption_key(password: str, salt: str, salt_version: int = 1) -> jwk.JWK:
    combined = f"{password}:{salt}:{salt_version}".encode("utf-8")
    key_bytes = hashlib.sha256(combined).digest()
    return jwk.JWK(kty="oct", k=base64url_encode(key_bytes))


async def create_encrypted_token(password: str, details: dict) -> dict[str, Any]:
    salt_version = 1
    salt = hashlib.sha256(str(uuid4()).encode()).hexdigest()[:16]
    salt_with_version = f"{salt_version}:{salt}"
    key = _derive_encryption_key(password, salt, salt_version)

    payload: dict[str, Any] = {**details}
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    protected_header = {"alg": "dir", "enc": "A256GCM", "typ": "JWE"}

    token = jwe.JWE(plaintext=plaintext, protected=protected_header)
    token.add_recipient(key)
    encrypted_token = token.serialize(compact=True)

    formatted_token = f"{salt_with_version}:{encrypted_token}"
    return {"security_token": formatted_token, "salt_version": salt_version}


async def decrypt_token(token: str, password: str) -> dict:
    try:
        if len(password) > 20:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must be max 15 characters")

        parts = token.split(":", 2)
        if len(parts) != 3:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format")

        salt_version, salt, jwe_token = parts
        key = _derive_encryption_key(password, salt, salt_version)

        jwe_obj = jwe.JWE()
        jwe_obj.deserialize(jwe_token)
        jwe_obj.decrypt(key)
        payload = json.loads(jwe_obj.payload.decode("utf-8"))
        return {**payload}

    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")




def build_user_details(user_id: str, user_doc: dict) -> dict:
    """The document every user gets back about their own account.

    Signup hands this out directly; /get-details rebuilds it for a user who
    signed in from another app and never saw the signup response. The
    security_token (a JWE of the whole account, keyed with the user's
    plaintext password) is added by the caller, since it must be minted
    fresh for the password that was just supplied.
    """
    return {
        "user_id": user_id,
        "schema_version": int(user_doc.get("schema_version", 1)),
        "recovery_type": user_doc.get("recovery_type", RecoveryPolicy.STANDARD.value)
    }


def hash_password(password: str) -> tuple[str, str]:
    """
    Generate a secure, random 16-byte salt and hash the password using the scrypt algorithm.
    """
    salt = secrets.token_bytes(16)
    password_hash = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=16384,
        r=8,
        p=1,
    )
    salt = base64.b64encode(salt).decode("utf-8")
    password_hash = base64.b64encode(password_hash).decode("utf-8")
    return salt, password_hash    


def verify_password(input_password: str, saved_salt: str, saved_hash: str) -> bool:
    """Re-hashes the input password with the saved salt to verify it."""

    # 1. Decode the Base64 salt back into bytes for hashlib.scrypt
    salt_bytes = base64.b64decode(saved_salt)

    # 2. Hash the input attempt using the raw bytes salt
    new_hash = hashlib.scrypt(
        input_password.encode('utf-8'),
        salt=salt_bytes,
        n=16384, r=8, p=1
    )

    # 3. Encode new_hash to Base64 to match saved_hash format safely
    new_hash_b64 = base64.b64encode(new_hash).decode('utf-8')

    # 4. Use secrets.compare_digest on two string objects to prevent timing attacks
    return secrets.compare_digest(new_hash_b64, saved_hash)

def normalize_phone_number(phone_number: str) -> str:
    #i need it in the format of 2341234567890
    if phone_number.startswith("+"):
        phone_number = phone_number[1:]  # Remove the '+' sign
    if phone_number.startswith("0"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid phone number format. It should not start with '0'. Add country code")
    return phone_number
