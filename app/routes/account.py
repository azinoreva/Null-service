from fastapi import APIRouter, Depends, HTTPException, status
from app.models.user_model import ReturnUserCreate, ForgotPassword
from app.utils._redis import get_redis_client
from redis.asyncio import Redis
from app.utils.auth import create_passport, require_jwe_auth, create_encrypted_token, verify_refresh_token, rotate_refresh_token, verify_password, build_user_details, normalize_phone_number
from pydantic import BaseModel, Field
import json, random
from app.utils.limiter import exponential_backoff
from app.utils.mails_n_sms import send_otp_sms

router = APIRouter()



@router.post("/refresh")
async def refresh_session(
    payload: dict = Depends(verify_refresh_token),
):
    """Rotate the session.

    verify_refresh_token only decodes; rotate_refresh_token burns the old
    refresh row and issues a new pair, and raises 401 if the old one comes
    back a second time (reuse) or the session was revoked.
    """
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    session = await rotate_refresh_token(payload)

    return {"access_token": session["access_token"],
        "refresh_token":session["refresh_token"],
        "expires":24*60*60 
    }


class UserDetailsRequest(BaseModel):
    password: str = Field(..., min_length=8, max_length=20) 
    public_key: str = Field(..., min_length=20, max_length=100)

@router.post("/get-details", response_model=ReturnUserCreate)
async def get_details(
    payload: UserDetailsRequest,
    user: dict = Depends(require_jwe_auth),
    redis: Redis = Depends(get_redis_client),
):
    """Hand back everything signup gave, to a user who already has an account.
    Signing in from a second app returns only tokens, so that app never
    learns the user_id, recovery policy, schema version, invitation quota,
    passport signature or the encrypted recovery token. This route closes
    that gap: with a valid access token plus the account password it
    returns the exact same document /create-new-user-postprocess does.
    """
    user_id = user.get("sub")
    raw_doc = await redis.hget("users", user_id)
    if not raw_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")

    user_doc = json.loads(raw_doc)

    if not verify_password(payload.password, user_doc["salt"], user_doc["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    security_token_doc = await create_encrypted_token(
        password=payload.password, details=user_doc
    )

    return {
        **build_user_details(user_id, user_doc),
        **security_token_doc,
        "passport": create_passport(user_id, payload.public_key)
    }





@router.post("/forgot_password")
async def forgot_password(
    user: ForgotPassword,
    redis: Redis = Depends(get_redis_client)
    ):
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if user.user_id:
    # check for user_id in redis
    
        raw_doc = await redis.hget("users", user.user_id)
        if not raw_doc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
        user_doc = json.loads(raw_doc)
        # Now send the users encrypted blob so they figure out themselves
        document = user_doc.get("encrypted_blob")
        return {"message": document}
    elif user.phone_number and not user.pin: 
        # This means it is the first time so Check for phone in redis
        phone_number = normalize_phone_number(user.phone_number)
        if not await exponential_backoff(redis, phone_number):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Too many requests")
        
        if await redis.hexists("phone_numbers", phone_number):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="if this phone number is registered, an sms will be sent to you")
        # Make otp and send it
        otp = random.randint(100000, 999999)
        await redis.set(f"phone_recovery_otp_{user.phone_number}", otp, ex=600)  # 600 seconds = 10 minutes    
         
        # Send to appropriate service to send the pin to the user via SMS or other means
        await send_otp_sms(phone_number=phone_number, otp=str(otp))

        return {"message": "An otp has been sent to your phone number do it in 10 minutes or it will be deleted"} 

    elif user.phone_number and user.pin:
        # Check if the pin is correct
        phone_number = normalize_phone_number(user.phone_number)
        otp = await redis.get(f"phone_recovery_otp_{phone_number}")
        if not otp:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        if str(otp) != user.pin:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        # Find the user_id from phone
        user_id = await redis.hget("phone_numbers", phone_number)
        raw_doc = await redis.hget("users", user_id)
        user_doc = json.loads(raw_doc)
        # Now send the users encrypted blob so they figure out themselves
        document = user_doc.get("encrypted_blob")
        return {"message": document}

    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    


class PublicKey(BaseModel):
    public_key: str = Field(..., min_length= 20, max_length=100)

@router.post("/new-passport")
async def new_passport(
    PublicKey: PublicKey,
    user: dict = Depends(require_jwe_auth),
    redis: Redis = Depends(get_redis_client)
):
    user_id = user['sub']
    passport = create_passport(user_id, PublicKey.public_key)
    return {
        "passport": passport,
        "expires": 30*24*3600  
    }
