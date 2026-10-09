from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.user_model import SignIn, get_user, get_user_by_phone, save_user
from app.utils.auth import decrypt_token, issue_session, normalize_phone_number, verify_password
from app.utils.db import get_db
from pydantic import BaseModel
from app.utils._redis import get_redis_client
from app.utils.logger import LoggedAPIRouterMixin
from redis.asyncio import Redis

class LoggedAPIRouter(LoggedAPIRouterMixin, APIRouter):
    pass


router = LoggedAPIRouter()


async def account_recovery(blob:str, user_id: str, password: str, db: AsyncSession):
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

    # Handle schema version here later. Restore the user into the database
    # (the phone index lives on the row itself now).
    await save_user(db, document)

    return document


class SignInReturn(BaseModel):
    access_token: str
    refresh_token: str
    expires: int
    user_id: str

@router.post("/sign-in", response_model=SignInReturn)
async def sign_in(
    user: SignIn,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis_client)
    ):
    # A user may not have user_id but have phone number
    
    # Check the user_id in the database or phone number
    user_id = None
    user_doc = None
    if user.user_id:
        user_id = user.user_id
        user_doc = await get_user(db, user_id)
    elif user.phone_number:
        user_phone = normalize_phone_number(user.phone_number)
        user_doc = await get_user_by_phone(db, user_phone)
        if user_doc:
            user_id = user_doc["_id"]
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user_doc and not user.encrypted_document_blob:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if user.encrypted_document_blob:
        user_doc = await account_recovery(blob=user.encrypted_document_blob, user_id=user_id, password=user.password, db=db)

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
