from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional
import secrets, string, json

from app.utils.auth import require_jwe_auth
from app.utils.config import settings
from app.utils._redis import get_redis_client
from redis.asyncio import Redis


router = APIRouter()

# ---- Tunables ---------------------------------------------------------------
MIN_EXPIRY_SECONDS       = 600            # 10 minutes
MAX_EXPIRY_SECONDS       = 48 * 60 * 60   # 48 hours
DEFAULT_EXPIRY_SECONDS   = 10 * 60        # preserves previous 10-minute default
MAX_BRUTE_FORCE_DELAY    = 3600           # cap lockout at 1 hour
BRUTE_FORCE_WINDOW       = 3600           # attempt counter resets after 1h
DH_DROP_EXPIRY_SECONDS   = 60 * 60        # unclaimed dh drops live for 1 hour
# -----------------------------------------------------------------------------


class Contact(BaseModel):
    """A contact to send to another user."""
    nickname: str = Field(..., description="The name of the contact", max_length=50)
    title: str = Field(..., description="The title of the contact", max_length=100)
    bio: str = Field(..., description="The bio of the contact", max_length=500)
    public_key: str = Field(..., description="The Ed25519 identity public key of the contact", max_length=128)
    dh_public_key: Optional[str] = Field(
        None,
        description=(
            "The contact's X25519 (Diffie-Hellman) public key, urlsafe base64. "
            "Needed to seal a dh key to them via /dh-drop. Omit if unknown."
        ),
        max_length=128,
    )
    avatar: Optional[str] = Field(None, description="The avatar of the contact", max_length=29000)


class SendContactRequest(BaseModel):
    """Payload for creating a shareable contact."""
    contact: Contact
    expires_in: int = Field(
        DEFAULT_EXPIRY_SECONDS,
        ge=MIN_EXPIRY_SECONDS,
        le=MAX_EXPIRY_SECONDS,
        description="Seconds until the contact link expires (max 48 hours).",
    )
    one_time: bool = Field(
        False,
        description="If true, the contact can only be fetched once, then it's destroyed.",
    )


class ContactKey(BaseModel):
    contact_key: str = Field(..., min_length=10, max_length=11)


# ---- Redis key helpers ------------------------------------------------------
def _data_key(key: str) -> str:      return f"contact:data:{key}"
def _one_time_key(key: str) -> str:  return f"contact:ot:{key}"
def _owner_key(user_id: str) -> str: return f"contact:user:{user_id}"
def _lock_key(user_id: str) -> str:  return f"bruteforce:contact:lock:{user_id}"
def _count_key(user_id: str) -> str: return f"bruteforce:contact:count:{user_id}"


# ---- Brute-force helpers ----------------------------------------------------
async def _enforce_backoff(redis: Redis, user_id: str) -> None:
    """Raise 429 if the user is currently locked out."""
    ttl = await redis.ttl(_lock_key(user_id))
    if ttl and ttl > 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again in {ttl} seconds.",
            headers={"Retry-After": str(ttl)},
        )


async def _record_failure(redis: Redis, user_id: str) -> None:
    """Increment the failure counter and apply exponential backoff."""
    count_key = _count_key(user_id)
    lock_key = _lock_key(user_id)

    attempts = await redis.incr(count_key)
    # Reset the counter window on every failure.
    await redis.expire(count_key, BRUTE_FORCE_WINDOW)

    # 1s, 2s, 4s, 8s, ... capped at MAX_BRUTE_FORCE_DELAY.
    delay = min(2 ** min(attempts - 1, 20), MAX_BRUTE_FORCE_DELAY)
    await redis.set(lock_key, "1", ex=delay)


async def _clear_failures(redis: Redis, user_id: str) -> None:
    await redis.delete(_lock_key(user_id), _count_key(user_id))


# ---- Atomic fetch-and-consume -----------------------------------------------
# Returns the payload, and if the one-time marker exists, deletes both
# the payload and the marker in the same atomic step.
FETCH_SCRIPT = """
local value = redis.call('GET', KEYS[1])
if not value then
    return nil
end
if redis.call('EXISTS', KEYS[2]) == 1 then
    redis.call('DEL', KEYS[1])
    redis.call('DEL', KEYS[2])
end
return value
"""


@router.post("/send_contact")
async def send_contact(
    payload: SendContactRequest,
    user: dict = Depends(require_jwe_auth),
    redis: Redis = Depends(get_redis_client),
):
    """Create a shareable contact link.

    The sender chooses how long the link lives (up to 48 hours) and whether
    it is single-use. If the sender already has a live, reusable link, we
    return it instead of creating a duplicate.
    """
    user_id = user["sub"]

    # Reuse an existing shareable link for this user if there is one.
    existing = await redis.get(_owner_key(user_id))
    if existing:
        ttl = await redis.ttl(_data_key(existing))
        if ttl and ttl > 0:
            return {
                "url": f"https://null.app/{settings.server_id}/c/{existing}",
                "expires_in": ttl,
                "one_time": False,
                "contact_key": existing
            }
        # Stale pointer; clean up and continue to create a new link.
        await redis.delete(_owner_key(user_id))

    key = "-".join("".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(n)) for n in (4, 5))
    contact_data = {
        **payload.contact.model_dump(),
        "contact_id": user_id,
        "server_id": settings.server_id,
    }

    pipe = redis.pipeline()
    pipe.set(_data_key(key), json.dumps(contact_data), ex=payload.expires_in)
    if payload.one_time:
        pipe.set(_one_time_key(key), "1", ex=payload.expires_in)
    else:
        # Only non-one-time links are remembered for reuse.
        pipe.set(_owner_key(user_id), key, ex=payload.expires_in)
    await pipe.execute()

    return {
        "url": f"https://null.app/{settings.server_id}/c/{key}",
        "expires_in": payload.expires_in,
        "one_time": payload.one_time,
        "contact_key": key
    }


@router.post("/get_contact")
async def get_contact(
    payload: ContactKey,
    user: dict = Depends(require_jwe_auth),
    redis: Redis = Depends(get_redis_client),
):
    """Fetch a shared contact by its key, subject to brute-force protection."""
    user_id = user["sub"]

    # Fail fast if we're currently in a backoff window.
    await _enforce_backoff(redis, user_id)

    raw = await redis.eval(
        FETCH_SCRIPT,
        2,
        _data_key(payload.contact_key),
        _one_time_key(payload.contact_key),
    )

    if raw is None:
        await _record_failure(redis, user_id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Contact not found",
        )

    # Legitimate fetch — reset the failure counter.
    await _clear_failures(redis, user_id)
    return json.loads(raw)

class SavingDetailsRebound(Contact):
    contact_key: str = Field(..., max_length=11)
@router.post("/send_contact_rebound")
async def send_contact_rebound(
    payload: SavingDetailsRebound,
    user: dict = Depends(require_jwe_auth),
    redis: Redis = Depends(get_redis_client),
):
    """In this route the user instantly creates this upon recieving to shares his own contact information to the other user """
    user_id = user["sub"]
    contact_data = {
                **payload.contact.model_dump(),
                "contact_id": user_id,
                "server_id": settings.server_id,
            }
        
    pipe = redis.pipeline()
    pipe.set(_data_key(payload.contact_key), json.dumps(contact_data), ex=60)
    pipe.set(_one_time_key(payload.contact_key), "1", ex=60)
    await pipe.execute()
    return {"message": "Contact saved successfully"}






# ---- Inbox (targeted drop) model ---------------------------------------------
class DropContactRequest(BaseModel):
    """Payload for dropping a contact directly into another user's inbox."""
    recipient_id: str = Field(..., description="The user ID of the recipient this contact is for", max_length=128)
    contact: Contact
    expires_in: int = Field(
        DEFAULT_EXPIRY_SECONDS,
        ge=MIN_EXPIRY_SECONDS,
        le=MAX_EXPIRY_SECONDS,
        description="Seconds until this dropped contact expires (max 48 hours).",
    )


# ---- Redis key helper for inbox ----------------------------------------------
def _inbox_key(recipient_id: str) -> str: return f"contact:inbox:{recipient_id}"


# ---- Atomic fetch-and-clear of the whole inbox hash --------------------------
FETCH_INBOX_SCRIPT = """
local vals = redis.call('HGETALL', KEYS[1])
if #vals == 0 then
    return nil
end
redis.call('DEL', KEYS[1])
return vals
"""


@router.post("/drop_contact")
async def drop_contact(
    payload: DropContactRequest,
    user: dict = Depends(require_jwe_auth),
    redis: Redis = Depends(get_redis_client),
):
    """Drop a contact directly into another user's inbox.

    Unlike /send_contact, this doesn't produce a shareable link — the
    contact is addressed straight to `recipient_id` and only that user
    can retrieve it via /check_contact.
    """
    sender_id = user["sub"]

    if payload.recipient_id == sender_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You can't drop a contact for yourself",
        )

    contact_data = {
        **payload.contact.model_dump(),
        "contact_id": sender_id,
        "server_id": settings.server_id,
    }

    inbox_key = _inbox_key(payload.recipient_id)
    pipe = redis.pipeline()
    pipe.hset(inbox_key, sender_id, json.dumps(contact_data))
    pipe.expire(inbox_key, payload.expires_in)
    await pipe.execute()

    return {"message": "Contact dropped successfully"}


@router.post("/check_contact")
async def check_contact(
    user: dict = Depends(require_jwe_auth),
    redis: Redis = Depends(get_redis_client),
):
    """Check the caller's inbox for any contacts left for them.

    If anything is found, it's returned and the inbox is cleared in the
    same atomic step (so a contact is delivered exactly once).
    """
    recipient_id = user["sub"]

    raw = await redis.eval(FETCH_INBOX_SCRIPT, 1, _inbox_key(recipient_id))

    if not raw:
        return {"contacts": []}

    # raw is a flat [sender_id, json_value, sender_id, json_value, ...] list.
    contacts = [json.loads(raw[i + 1]) for i in range(0, len(raw), 2)]
    return {"contacts": contacts}


def _dh_inbox_key(user_id: str) -> str:
    return f"dh_inbox:{user_id}"


class DHDrop(BaseModel):
    recipient_id: str = Field(..., description="The recipient's user id", max_length=40)
    dh_enc_key: str = Field(..., description="The recipient's public dh key, encrypted with the sender's public dh key", max_length=1000)
    dh_enc_nonce: str = Field(..., description="The nonce used to encrypt the dh key", max_length=40)
    expires_in: int = Field(
        DH_DROP_EXPIRY_SECONDS,
        ge=MIN_EXPIRY_SECONDS,
        le=MAX_EXPIRY_SECONDS,
        description=(
            "Seconds until an unclaimed dh drop is garbage collected "
            "(max 48 hours). Claiming it via check_dh_drops always clears early."
        ),
    )

@router.post("/dh-drop")
async def dh_drop(
    dhd: DHDrop,
    user: dict = Depends(require_jwe_auth),
    redis: Redis = Depends(get_redis_client),
):
    """Drop a dh key for a recipient.

    This is a one-way operation, the recipient will need to fetch it, push it to their inbox.

    Every user checks their inbox when they open the app for the first time including check contacts. This way
    we dont need to poll nor send to their servers.
    """
    sender_id = user["sub"]

    if dhd.recipient_id == sender_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You can't drop a dh key for yourself",
        )

    dh_data = {
        "sender_id": sender_id,
        "dh_enc_key": dhd.dh_enc_key,
        "dh_enc_nonce": dhd.dh_enc_nonce,
        "server_id": settings.server_id,
    }

    inbox_key = _dh_inbox_key(dhd.recipient_id)
    pipe = redis.pipeline()
    pipe.hset(inbox_key, sender_id, json.dumps(dh_data))
    pipe.expire(inbox_key, dhd.expires_in)
    await pipe.execute()

    return {"message": "DH key dropped successfully", "expires_in": dhd.expires_in}


@router.post("/clear_dh_inbox")
async def clear_dh_inbox(
    user: dict = Depends(require_jwe_auth),
    redis: Redis = Depends(get_redis_client),
):
    """Wipe the caller's dh inbox without fetching its contents.

    Useful for discarding stale/unwanted dh drops without going through
    check_dh_drops (e.g. the client wants a clean slate).
    """
    recipient_id = user["sub"]
    deleted = await redis.delete(_dh_inbox_key(recipient_id))

    return {"cleared": bool(deleted)}



@router.post("/check_dh_drops")
async def check_dh_drops(
    user: dict = Depends(require_jwe_auth),
    redis: Redis = Depends(get_redis_client),
):
    """Check the caller's inbox for any dh keys left for them.

    Uses the same atomic fetch-and-clear script as check_contact, so a
    dh key is delivered exactly once.
    """
    recipient_id = user["sub"]

    raw = await redis.eval(FETCH_INBOX_SCRIPT, 1, _dh_inbox_key(recipient_id))

    if not raw:
        return {"dh_drops": []}

    dh_drops = [json.loads(raw[i + 1]) for i in range(0, len(raw), 2)]
    return {"dh_drops": dh_drops}