from __future__ import annotations

import secrets, json, nanoid, hmac, hashlib, colorsys
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field, ValidationError
from redis.asyncio import Redis

from app.utils.auth import require_jwe_auth
from app.utils.config import settings
from app.utils._redis import get_redis_client
from app.utils.limiter import is_allowed, get_client_ip
from app.utils.logger import LoggedAPIRouterMixin
from app.models.server import Server, ServerIn  # ServerIn needs a new `email: EmailStr` field
from app.routes.connections import ServerClass

class LoggedAPIRouter(LoggedAPIRouterMixin, APIRouter):
    pass


router = LoggedAPIRouter(prefix="", tags=["servers"])

OTP_TTL = 300  # 5 minutes
MAX_OTP_ATTEMPTS = 2
SERVER_ID_LEN = 12

# Redis keys for the saved list of servers
SERVERS_KEY = "servers"                  # hash: server_id -> JSON record
PHONE_INDEX_KEY = "servers:phone_hash"   # hash: phone_hash -> server_id (duplicate guard)


# ============================================================
# Storage helpers (saved list lives in Redis, not a JSON file)
# ============================================================

# async def load_servers(redis: Redis) -> list[dict]:
#     raw = await redis.hgetall(SERVERS_KEY)
#     servers = []
#     for v in raw.values():
#         try:
#             servers.append(json.loads(_as_str(v)))
#         except (json.JSONDecodeError, TypeError):
#             continue  # skip corrupt entries rather than failing the whole list
#     return servers

def load_servers()->list[dict]:
    # This is temporary, until we have a proper database
    _l = [{
  "serverId": "K4m_lsBLJIkT",
  "serverUrl": "http://127.0.0.1:5000",
  "serverName": "Test Server",
  "media": {
    "url": "https://example.com/image.jpg",
    "size": 1024,
    "timer": 10,
    "media_type": [
      "image"
    ]
  },
  "maxPayload": 1000,
  "colour": "#FFFFFF",
  "about": "This is a test server... Rules are that you should not add rubbish on this server",
  "categories": [
    "history", "activism", "community", "social"
  ],
  "annotated": False,
  "disabled": False,
  "location": None,
  "serverType": "public"
}]
    return _l

async def get_server(redis: Redis, server_id: str) -> Optional[dict]:
    raw = await redis.hget(SERVERS_KEY, server_id)
    return json.loads(_as_str(raw)) if raw else None


async def save_server(redis: Redis, server: dict) -> None:
    await redis.hset(SERVERS_KEY, server["serverId"], json.dumps(server))


# ============================================================
# Hashing / cleaning helpers
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
    redis: Redis = Depends(get_redis_client),
):
    # `Server` is the output model, so owner fields (phone/email hashes etc.) are dropped automatically.
    servers = []
    for record in load_servers():   # replace later with "await load_servers(redis)"
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
):
    phone = clean_phone(server_owner.phone)

    await verify_otp(redis, f"otp_server:{phone}", server_owner.otp)

    phone_hash = hash_phone(phone)
    email_hash = hash_email(server_owner.email)

    # Reserve the phone first so the same phone can't register twice.
    server_id = nanoid.generate(size=SERVER_ID_LEN)
    if not await redis.hsetnx(PHONE_INDEX_KEY, phone_hash, server_id):
        raise HTTPException(status_code=409, detail="Server already exists for this phone")

    record = server_owner.model_dump(exclude={"otp", "phone", "email"}, mode="json")
    record["serverId"] = server_id
    record["phone_hash"] = phone_hash
    record["email_hash"] = email_hash  # used to authorise later media-url changes
    record["ephemeral"] = server_owner.ephemeral

    if not server_owner.ephemeral:
        record["phone"] = phone
        record["email"] = server_owner.email

    # HSETNX guards against an ID collision; regenerate if it happens.
    record["colour"] = generate_colour(server_id)  # server-assigned, derived from the ID
    while not await redis.hsetnx(SERVERS_KEY, server_id, json.dumps(record)):
        server_id = nanoid.generate(size=SERVER_ID_LEN)
        record["serverId"] = server_id
        record["colour"] = generate_colour(server_id)
    await redis.hset(PHONE_INDEX_KEY, phone_hash, server_id)

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


async def _get_owned_server(redis: Redis, server_id: str, email: str) -> dict:
    server = await get_server(redis, server_id)
    if server and hmac.compare_digest(server.get("email_hash", ""), hash_email(email)):
        return server
    # Same error for "not found" and "wrong email" so IDs/emails can't be probed.
    raise HTTPException(status_code=404, detail="Server not found for this email")


@router.post("/servers/{server_id}/media-url/otp")
async def request_media_url_otp(
    server_id: str,
    body: MediaUrlOtpRequest,
    request: Request,
    redis: Redis = Depends(get_redis_client),
):
    ip = get_client_ip(request)
    if not await is_allowed(redis, server_id, ip):
        raise HTTPException(status_code=403, detail="Not allowed")

    await _get_owned_server(redis, server_id, body.email)

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
):
    server = await _get_owned_server(redis, server_id, body.email)

    if body.media_url is None and body.server_url is None and body.new_email is None:
        raise HTTPException(status_code=400, detail="No server settings to update")
    if body.media_url is not None:
        if not server.get("media"):
            raise HTTPException(status_code=400, detail="This server has no media configured")

    await verify_otp(redis, f"otp_media:{server_id}", body.otp)

    if body.media_url is not None:
        server["media"]["url"] = body.media_url
    if body.server_url is not None:
        server["server_url"] = body.server_url
    if body.new_email is not None:
        server["email_hash"] = hash_email(body.new_email)
        if not server.get("ephemeral"):
            server["email"] = str(body.new_email)
    await save_server(redis, server)

    return {
        "message": "Server settings updated",
        "serverId": server_id,
        "media_url": server.get("media", {}).get("url"),
        "server_url": server.get("server_url"),
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


