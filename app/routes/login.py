from fastapi import APIRouter, HTTPException, status, Depends
from app.models.user_model import SignIn
from app.utils.auth import decrypt_token, issue_session, normalize_phone_number, verify_password
from pydantic import BaseModel
from app.utils._redis import get_redis_client
from redis.asyncio import Redis
import json

router = APIRouter()


async def account_recovery(blob:str, user_id: str, password: str, redis):
    document = await decrypt_token(token=blob, password=password)
    # The payload is the UserAccount document. It has been serialised a few
    # different ways over time, so accept every spelling of the id and store
    # it back under the "_id" alias the rest of the app expects.
    recovered_id = (
        document.get("_id") or document.get("id") or document.get("user_id")
    )
    if recovered_id != user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if "_id" not in document:
        document["_id"] = recovered_id
        document.pop("id", None)

    # Handle schema version here later. But now save it to redis but first check if document have a phone
    pipe = redis.pipeline()
    pipe.hset("users", recovered_id, json.dumps(document))
    if document.get("phone_number"):
        pipe.hset("phone_numbers", document["phone_number"], recovered_id)
    await pipe.execute()

    return document


class SignInReturn(BaseModel):
    access_token: str
    refresh_token: str
    expires: int
    user_id: str

@router.post("/sign-in", response_model=SignInReturn)
async def sign_in(
    user: SignIn,
    redis: Redis = Depends(get_redis_client)
    ):
    # A user may not have user_id but have phone number
    
    # Check the user_id in Redis or phone number
    user_id = None
    raw_doc = None
    if user.user_id:
        user_id = user.user_id
        raw_doc = await redis.hget("users", user_id)
    elif user.phone_number:
        user_phone = normalize_phone_number(user.phone_number)
        user_id = await redis.hget("phone_numbers", user_phone)
        if user_id:
            raw_doc = await redis.hget("users", user_id)
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not raw_doc and not user.encrypted_document_blob:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if user.encrypted_document_blob:
        user_doc = await account_recovery(blob=user.encrypted_document_blob, user_id=user_id, password=user.password, redis=redis)
    else:
        user_doc = json.loads(raw_doc)

    # Now confirm if the user is legit using password and hash
    if not verify_password(user.password,  user_doc["salt"], user_doc["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Give the user access
    session = await issue_session(user_id, access_expires_minutes=24*60,
                                  refresh_expires_minutes=24*60*7)

    return SignInReturn(
        access_token=session["access_token"],
        refresh_token=session["refresh_token"],
        expires=24*60*60,  # 24 hours in seconds,
        user_id=user_id
    )
