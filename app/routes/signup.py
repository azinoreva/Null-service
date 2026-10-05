from fastapi import APIRouter, Depends, HTTPException, status
from app.models.user_model import Recovery, UserAccount, RecoveryPolicy, SignInReturn, ReturnUserCreate
from app.utils._redis import get_redis_client
from redis.asyncio import Redis
from app.utils.backoff import backoff
import random, json
from uuid import uuid4
from app.utils.auth import create_passport, require_jwe_auth, create_encrypted_token, verify_refresh_token, rotate_refresh_token, verify_password, hash_password, build_user_details, normalize_phone_number
from pydantic import BaseModel, Field
from app.utils.mails_n_sms import send_otp_sms
from app.utils.limiter import exponential_backoff
import time

router = APIRouter()



class UserCreate(BaseModel):
    phone_number: str = Field(..., min_length=10, max_length=15)


@router.post("/create-new-user-preprocess")
async def create_new_user_preprocess(
    user: UserCreate,
    redis: Redis = Depends(get_redis_client)
):
    """
    This endpoint checks if the phone number already exists and if it does not, it generates a 6 digit pin that expires in 10 minutes
    """
    phone_number = normalize_phone_number(user.phone_number)

    # check if this phone number already exists in the redis members set
    if await redis.hexists("phone_numbers", phone_number):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Not allowed")
    # Lets do exponential backoff for this using redis so the user does not waste our sms.
    check_phone_block = await exponential_backoff(redis, phone_number)
    if check_phone_block:
        pin = random.randint(100000, 999999)  # Generate a 6-digit pin

        # Send to appropriate service to send the pin to the user via SMS or other means
        await send_otp_sms(phone_number=phone_number, otp=str(pin))

    # Set the pin in Redis for 10 minutes
    await redis.set(f"otp_{phone_number}", pin, ex=600)  # 600 seconds = 10 minutes

  
    return {    
        "phone_number": phone_number,
        "otp_sent": True,
        "message": f"A pin has been sent to your phone number. It will expire in 10 minutes. {pin}"
        }

class UserCreatePostProcess(UserCreate):
    pin: str = Field(..., min_length=6, max_length=6)
    password: str = Field(..., min_length=8, max_length=20)
    encrypted_blob: str = Field(..., max_length=10000)
    public_key: str = Field(..., min_length= 20, max_length=100)





@router.post("/create-new-user-postprocess", response_model=ReturnUserCreate)
async def create_new_user_postprocess(
    user: UserCreatePostProcess,
    redis: Redis = Depends(get_redis_client)
):
    phone_number = normalize_phone_number(user.phone_number)

    if await redis.hexists("phone_numbers", phone_number):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Not allowed")

    # check_phone_block = await backoff(redis, phone_number)
    # if check_phone_block:
    #     raise HTTPException(status_code=400, detail="Not allowed")
    
    # Get the pin from Redis
    stored_pin = await redis.get(f"otp_{phone_number}")

    # Check if the pin is correct
    if stored_pin != user.pin:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect pin")

    # Hash the password
    salt, password_hash = hash_password(user.password)
    user_id = str(uuid4())
    # create a json to store the user details
    account = UserAccount(
        _id=user_id,
        phone_number=phone_number,
        password=password_hash,
        salt=salt,
        push_notification_token=[],
        date_created=int(time.time()),
        recovery_type=Recovery.STANDARD,
        settings_blob=None, # This is the users settings but encrypted
        schema_version=1,
        encrypted_blob=user.encrypted_blob if user.encrypted_blob else None # This encrypted blob is the users encrypted password.
    )
    json_doc = json.dumps(account.model_dump())

    pipeline = redis.pipeline()
    pipeline.hset("users", user_id, json_doc)
    pipeline.hset("phone_numbers", phone_number, user_id)
    pipeline.delete(f"otp_:{phone_number}")
    await pipeline.execute()

  

    # Also encrypt this data for the user to store, this is for safety incase the server loses its db. It would know and be able to restore a user.
    # NOTE: the JWE is keyed with the PLAINTEXT password, because the client is the one
    # that has to decrypt it (see account_recovery) and it only ever knows the password.
    security_token_doc = await create_encrypted_token(password=user.password, details=account.model_dump())
    
    # Sign the user_passport (inside build_user_details)
    return_doc = {
        **build_user_details(user_id, json.loads(json_doc)),
        **security_token_doc,
        "passport": create_passport(user_id, user.public_key)
    }
    return return_doc

