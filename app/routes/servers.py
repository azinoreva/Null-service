from __future__ import annotations

import secrets, nanoid, hmac, hashlib, colorsys
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field, ValidationError
from redis.asyncio import Redis
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.utils.auth import require_jwe_auth
from app.utils.config import settings
from app.utils._redis import get_redis_client
from app.utils.db import get_db
from app.utils.limiter import is_allowed, get_client_ip
from app.utils.logger import LoggedAPIRouterMixin
from app.models.server import (
    Server,
    ServerIn,
    list_servers,
    create_server,
    save_server,
    save_owner,
    phone_registered,
    get_owned_server,
    add_user_servers,
    list_user_servers,
)
from app.routes.connections import ServerClass

class LoggedAPIRouter(LoggedAPIRouterMixin, APIRouter):
    pass


router = LoggedAPIRouter(prefix="", tags=["servers"])

OTP_TTL = 300  # 5 minutes
MAX_OTP_ATTEMPTS = 2
SERVER_ID_LEN = 12


# ============================================================
# Storage helpers (saved list lives in the database)
# ============================================================

def _as_str(v) -> Optional[str]:
    if v is None:
        return None
    return v.decode() if isinstance(v, bytes) else str(v)


def _hash_value(value: str) -> str:
    """HMAC-SHA256 keyed with the fixed salt from settings."""
    return hmac.new(
        settings.salt.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def clean_phone(phone: str) -> str:
    phone = phone.strip()
    return phone[1:].strip() if phone.startswith("+") else phone


def hash_phone(phone: str) -> str:
    return _hash_value(clean_phone(phone))


def hash_email(email: str) -> str:
    return _hash_value(email.strip().lower())


def generate_colour(server_id: str) -> str:
    """
    Bright colour derived from the server's nanoid: same ID -> same colour,
    different IDs -> effectively random hues. Saturation and lightness are kept
    in a vivid range so it's never washed out or too dark.
    """
    d = hashlib.sha256(server_id.encode("utf-8")).digest()
    hue = int.from_bytes(d[0:2], "big") / 65535           # full colour wheel
    light = 0.48 + (d[2] / 255) * 0.16                    # 0.48-0.64
    sat = 0.80 + (d[3] / 255) * 0.20                      # 0.80-1.00
    r, g, b = colorsys.hls_to_rgb(hue, light, sat)
    return f"#{round(r * 255):02X}{round(g * 255):02X}{round(b * 255):02X}"


def generate_otp() -> str:
    return f"{secrets.randbelow(900000) + 100000}"


async def send_otp_email(email: str, otp: str, purpose: str) -> None:
    """Plug in your real email provider here."""
    print(f"[DEV] OTP for {purpose} -> {email}: {otp}")


async def verify_otp(redis: Redis, key: str, supplied: str) -> None:
    """Checks the OTP, limits guesses, and deletes it on success."""
    attempts_key = f"{key}:attempts"
    stored = _as_str(await redis.get(key))
    if stored is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    attempts = await redis.incr(attempts_key)
    if attempts == 1:
        await redis.expire(attempts_key, OTP_TTL)
    if attempts > MAX_OTP_ATTEMPTS:
        await redis.delete(key, attempts_key)
        raise HTTPException(status_code=429, detail="Too many attempts. Request a new OTP.")

    if not hmac.compare_digest(stored, str(supplied)):
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    await redis.delete(key, attempts_key)


# ============================================================
# List servers
# ============================================================

class ServerList(BaseModel):
    servers: List[Server]


@router.get("/servers", response_model=ServerList)
async def get_servers(
    user: dict = Depends(require_jwe_auth),
    db: AsyncSession = Depends(get_db),
):
    # `Server` is the output model, so owner fields (phone/email hashes etc.) are dropped automatically.
    servers = []
    for record in await list_servers(db):
        try:
            servers.append(Server(**record))
        except ValidationError:
            continue  # skip malformed records instead of failing the whole list
    return {"servers": servers}


# ============================================================
# Register: step 1 (request OTP)
# ============================================================

class ServerOwner(BaseModel):
    phone: str = Field(..., max_length=16, min_length=12)
    email: EmailStr  # mandatory


# Later add turnstile here
@router.post("/register-server-pre")
async def register_server_pre(
    request: Request,
    server_owner: ServerOwner,
    redis: Redis = Depends(get_redis_client),
):
    phone = clean_phone(server_owner.phone)
    ip = get_client_ip(request)

 
    allowed, message = await is_allowed(redis, phone, ip)
    if not allowed:
        raise HTTPException(status_code=429, detail=message)

    otp = generate_otp()
    await redis.set(f"otp_server:{phone}", otp, ex=OTP_TTL)
    await redis.delete(f"otp_server:{phone}:attempts")
    await send_otp_email(server_owner.email, otp, "server registration")

    return {"message": "OTP sent to your email"}


# ============================================================
# Register: step 2 (verify OTP + save)
# ============================================================

@router.post("/register-server-post", status_code=201)
async def register_server_post(
    server_owner: ServerIn,
    redis: Redis = Depends(get_redis_client),
    db: AsyncSession = Depends(get_db),
):
    phone = clean_phone(server_owner.phone)

    await verify_otp(redis, f"otp_server:{phone}", server_owner.otp)

    phone_hash = hash_phone(phone)
    email_hash = hash_email(server_owner.email)

    # A phone can own at most one server. The unique index on phone_hash is
    # the real guard; this check just gives a clean 409 without an insert.
    if await phone_registered(db, phone_hash):
        raise HTTPException(status_code=409, detail="Server already exists for this phone")

    # Public server fields (owner identity is stripped out and stored separately).
    base = server_owner.model_dump(
        mode="json", exclude={"otp", "phone", "email", "ephemeral"}
    )
    base.pop("server_url", None)

    owner = {
        "server_id": None,  # filled below once the id is settled
        "phone_hash": phone_hash,
        "email_hash": email_hash,
        "phone": None if server_owner.ephemeral else phone,
        "email": None if server_owner.ephemeral else str(server_owner.email),
        "ephemeral": server_owner.ephemeral,
    }

    # A server id collision (or a race on the phone index) surfaces as an
    # IntegrityError; regenerate the id and retry, or 409 if the phone raced.
    server_id = nanoid.generate(size=SERVER_ID_LEN)
    for _ in range(10):
        record = {
            **base,
            "serverId": server_id,
            "serverUrl": server_owner.server_url,
            "colour": generate_colour(server_id),
        }
        owner["server_id"] = server_id
        try:
            await create_server(db, record, owner)
            break
        except IntegrityError:
            await db.rollback()
            if await phone_registered(db, phone_hash):
                raise HTTPException(status_code=409, detail="Server already exists for this phone")
            server_id = nanoid.generate(size=SERVER_ID_LEN)
    else:
        raise HTTPException(status_code=500, detail="Could not allocate a server id")

    return {"message": "Server registered", "server_id": server_id}


# ============================================================
# Update media URL: step 1 (request OTP)
# ============================================================

class MediaUrlOtpRequest(BaseModel):
    email: EmailStr


class MediaUrlUpdate(BaseModel):
    email: EmailStr
    new_email: Optional[EmailStr] = None
    otp: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")
    media_url: Optional[str] = Field(None, max_length=150, pattern=r"^https?://\S+$")
    server_url: Optional[str] = Field(None, max_length=150)


async def _get_owned_server(db: AsyncSession, server_id: str, email: str) -> tuple[dict, dict]:
    owned = await get_owned_server(db, server_id, hash_email(email))
    if owned is None:
        # Same error for "not found" and "wrong email" so IDs/emails can't be probed.
        raise HTTPException(status_code=404, detail="Server not found for this email")
    return owned


@router.post("/servers/{server_id}/media-url/otp")
async def request_media_url_otp(
    server_id: str,
    body: MediaUrlOtpRequest,
    request: Request,
    redis: Redis = Depends(get_redis_client),
    db: AsyncSession = Depends(get_db),
):
    ip = get_client_ip(request)
    if not await is_allowed(redis, server_id, ip):
        raise HTTPException(status_code=403, detail="Not allowed")

    await _get_owned_server(db, server_id, body.email)

    otp = generate_otp()
    key = f"otp_media:{server_id}"
    await redis.set(key, otp, ex=OTP_TTL)
    await redis.delete(f"{key}:attempts")
    await send_otp_email(body.email, otp, "media URL update")

    return {"message": "OTP sent to your email"}


# ============================================================
# Update media URL: step 2 (verify OTP + change)
# ============================================================

@router.post("/servers/{server_id}/media-url")
async def update_media_url(
    server_id: str,
    body: MediaUrlUpdate,
    redis: Redis = Depends(get_redis_client),
    db: AsyncSession = Depends(get_db),
):
    server, owner = await _get_owned_server(db, server_id, body.email)

    if body.media_url is None and body.server_url is None and body.new_email is None:
        raise HTTPException(status_code=400, detail="No server settings to update")
    if body.media_url is not None:
        if not server.get("media"):
            raise HTTPException(status_code=400, detail="This server has no media configured")

    await verify_otp(redis, f"otp_media:{server_id}", body.otp)

    if body.media_url is not None:
        media = dict(server.get("media") or {})
        media["url"] = body.media_url
        server["media"] = media
    if body.server_url is not None:
        server["serverUrl"] = body.server_url
    if body.new_email is not None:
        owner["email_hash"] = hash_email(body.new_email)
        if not owner.get("ephemeral"):
            owner["email"] = str(body.new_email)

    await save_server(db, server)
    await save_owner(db, owner)

    return {
        "message": "Server settings updated",
        "serverId": server_id,
        "media_url": server.get("media", {}).get("url"),
        "server_url": server.get("serverUrl"),
        "email": body.new_email,
    }




  
class Servers(BaseModel):
    server_ids: list[str] = Field(..., description="List of server ids", max_length=500)
@router.post("/add-servers")
async def exchange_servers_add(
    servers: Servers,
    user: dict = Depends(require_jwe_auth), 
    redis: Redis = Depends(get_redis_client)
):
    # save the servers list to redis
    await redis.sadd(f"servers:{user['user_id']}", *servers.server_ids)

    return {
        "message": "Servers saved successfully"
    }

    

class ConfirmServers(BaseModel):
    user_id: str = Field(..., description="User id", max_length=40)
@router.post("/exchange-servers", response_model=Servers)
async def exchange_servers(
    servers: ConfirmServers,
    user: dict = Depends(require_jwe_auth), 
    redis: Redis = Depends(get_redis_client)
):
    # get the servers list from redis
    servers_list = await redis.smembers(f"servers:{servers.user_id}")
    if servers_list:
        return Servers(server_ids=list(servers_list))
    # The client app is to use the very first server it has in common with the other user to send the message. 
    else: 
        return Servers(server_ids=[])


