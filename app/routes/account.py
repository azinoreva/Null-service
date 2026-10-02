from fastapi import APIRouter, Depends, HTTPException, status
from app.models.user_model import ReturnUserCreate, ForgotPassword
from app.utils._redis import get_redis_client
from redis.asyncio import Redis
from app.utils.auth import create_passport, require_jwe_auth, create_encrypted_token, verify_refresh_token, rotate_refresh_token, verify_password, build_user_details, normalize_phone_number, hash_password
from pydantic import BaseModel, Field
import json, random
from app.utils.limiter import exponential_backoff
from app.utils.mails_n_sms import send_otp_sms
import hashlib, secrets
from enum import Enum
from app.utils.firebase import send_push
from typing import Optional

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



class PasswordChangeRequest(BaseModel):
    encrypted_blob: str = Field(max_length=10000)
    current_password: str = Field(min_length=8, max_length=15)
    new_password: str = Field(min_length=8, max_length=15)  

class PasswordChangeResponse(BaseModel):
    status: str
    new_encrypted_token: dict
    message: str

# -------------------------------------------------------------------------
# HELPER FUNCTIONS
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# ROUTES
# -------------------------------------------------------------------------
@router.post("/change-password")
async def change_password(
    request: PasswordChangeRequest,
    user: dict = Depends(require_jwe_auth),
    redis: Redis = Depends(get_redis_client)
):
    if request.current_password == request.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from current password"
        )
    # Check the user_id in the redis hash to ensure the user exists and is authenticated
    user_id = user.get("sub")
    _user = await redis.hget("users", user_id)
    if not _user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    _user_ = json.loads(_user)
    if not _user_.get("salt") or not _user_.get("password_hash"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not authenticated !"
        )
    verified = await verify_password(request.current_password, _user_.get("salt"), _user_.get("password_hash"))
    if not verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid current password"
        )
    
    # Step 1: Update the password in Redis
    new_password_hash, new_salt = await hash_password(request.new_password)
    # edit user
    _user_["password_hash"] = new_password_hash
    _user_["salt"] = new_salt
    # save the encrypted blob
    _user_["encrypted_blob"] = request.encrypted_blob

    await redis.hset("users", user_id, json.dumps(_user_))
    
    # Step 2: Generate a new encrypted token
    new_token_data = await create_encrypted_token(request.new_password, _user_)
    return PasswordChangeResponse(
        status="password_changed",
        new_encrypted_token=new_token_data,
        message="Password successfully changed. New encrypted token generated."
    )
class PushToken(BaseModel):
    token: str = Field(..., max_length=255, description="Push notification token for the user")
@router.post("/push-notification-token")
async def set_push_notification_token(
    token: PushToken,
    user: dict = Depends(require_jwe_auth),
    redis: Redis = Depends(get_redis_client)
):
    
    user_id = user.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user"
        )
        
    # 1. Fetch user data from Redis
    user_data_str = await redis.hget("users", user_id)
    if not user_data_str:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
        
    # 2. Safely parse the existing user JSON document
    try:
        user_data = json.loads(user_data_str)
    except json.JSONDecodeError:
    # Fallback if the data in Redis happens to be malformed
        user_data = {}

    # 3. Ensure the tokens field exists and is a list
    current_tokens = user_data.get("push_notification_token")
    
    if isinstance(current_tokens, list):
        # Prevent adding duplicate tokens to the list
        if token not in current_tokens:
            current_tokens.append(token.token)
    elif isinstance(current_tokens, str) and current_tokens:
        # If it was previously saved as a single string, convert it to a list
        if current_tokens == token.token:
            user_data["push_notification_token"] = [token.token]
        else:
            user_data["push_notification_token"] = [current_tokens, token]
    else:
        # Initialize a new list if the field was missing or null
        user_data["push_notification_token"] = [token.token]

    # 4. Save the merged object back to the Redis hash
    await redis.hset("users", user_id, json.dumps(user_data))
    
    return {
        "status": "success",
        "message": "Push notification token updated successfully."
    }

class NotificationType( str, Enum):
    PING = "ping"
    MESSAGE = "message"
    SERVER_MESSAGE = "server_message"

class SentTo(BaseModel):
    user_id:str = Field(..., max_length=36)
    notification_type: NotificationType
    message: Optional[str] = Field(None, max_length=100, description="Message content for MESSAGE notification type. Max length 100 characters.")

# Put a hard rate limit so someone can't spam the push notification system. For example, limit to 1 notification per minute. We also need to log unusual uses like for instance if someone is not knowing the user_id and is trying to send a notification to a user_id that doesn't exist. We also need to log if someone is trying to send a notification to a user_id that exists but is not their own user_id. We also need to log if someone is trying to send a notification to a user_id that exists but is not their own user_id and the notification_type is not "ping". We also need to log if someone is trying to send a notification to a user_id that exists but is not their own user_id and the notification_type is "ping" but the message is empty. We also need to log if someone is trying to send a notification to a user_id that exists but is not their own user_id and the notification_type is "ping" but the message is too long (more than 100 characters).
@router.post("/send_push_notification")
async def send_push_notification(
    sent_to: SentTo,
    user: dict = Depends(require_jwe_auth),
    redis: Redis = Depends(get_redis_client)
):
    
    # check the user_id if it exists. 
    recipient = await redis.hget("users", sent_to.user_id)
    if not recipient:
        # log the unusual use case
        #logger.warning("Attempt to send notification to non-existent user_id: %s", sent_to
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="invalid query"
        )
    if sent_to.user_id == user.get("sub"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot send notification to yourself"
        )

    notification_tokens = json.loads(recipient).get("push_notification_token", [])
    if sent_to.notification_type == NotificationType.PING:
        message = "Ping from user {}".format(user.get("sub"))
        for token in notification_tokens:
            send_push(token, "Null Ping",  message)

    elif sent_to.notification_type == NotificationType.MESSAGE:
        if not sent_to.message:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Message cannot be empty for MESSAGE notification type"
            )
        message = "Message from user {}: {}".format(user.get("sub"), sent_to.message)
        for token in notification_tokens:
            send_push(token, "Message",  message)

    elif sent_to.notification_type == NotificationType.SERVER_MESSAGE:
        if not sent_to.message:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Message cannot be empty for SERVER_MESSAGE notification type"
            )
        message = "Server message: {}".format(sent_to.message)
        for token in notification_tokens:
            send_push(token, "NULL Message", message)
    return {
        "status": "success",
        "message": "Notification sent successfully."
    }



class PhoneAction(str, Enum):
    REMOVE = "remove"
    UPDATE = "update"


class PhoneStep(str, Enum):
    REQUEST = "request"
    VERIFY = "verify"


class PhoneNumber(BaseModel):
    step: PhoneStep
    phone_number: str = Field(
        ...,
        min_length=10,
        max_length=15
    )
    action: PhoneAction

    new_phone_number: Optional[str] = Field(
        None,
        min_length=10,
        max_length=15
    )

    otp: Optional[str] = Field(
        None,
        max_length=10
    )


def hash_otp(otp: str):
    return hashlib.sha256(
        otp.encode()
    ).hexdigest()


@router.post("/edit-phone")
async def edit_my_phone_number(
    payload: PhoneNumber,
    user: dict = Depends(require_jwe_auth),
    redis = Depends(get_redis_client)
):
    user_id = user.get("sub")

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Invalid user"
        )


    # Get user
    user_data_str = await redis.hget(
        "users",
        user_id
    )

    if not user_data_str:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )


    try:
        user_data = json.loads(user_data_str)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500,
            detail="Corrupt user data"
        )


    current_phone = user_data.get("phone_number")


    #
    # STEP 1: SEND OTP
    #
    if payload.step == PhoneStep.REQUEST:

        normalized_current = normalize_phone_number(
            payload.phone_number
        )


        # verify old phone belongs to user
        if current_phone != normalized_current:
            raise HTTPException(
                status_code=400,
                detail="Current phone number does not match"
            )


        if payload.action == PhoneAction.UPDATE:

            if not payload.new_phone_number:
                raise HTTPException(
                    status_code=400,
                    detail="New phone number required"
                )


            new_phone = normalize_phone_number(
                payload.new_phone_number
            )


            if new_phone == current_phone:
                raise HTTPException(
                    status_code=400,
                    detail="New number must differ"
                )


            # check duplicate
            existing_user = await redis.hget(
                "phone_numbers",
                new_phone
            )


            if existing_user and existing_user != user_id:
                raise HTTPException(
                    status_code=400,
                    detail="Phone number already registered"
                )


        else:
            new_phone = None


        otp = str(
            secrets.randbelow(900000) + 100000
        )


        pending = {
            "action": payload.action.value,
            "new_phone_number": new_phone,
            "otp_hash": hash_otp(otp)
        }


        await redis.setex(
            f"phone_change:{user_id}",
            300,
            json.dumps(pending)
        )


        #
        # Replace with your SMS provider
        #
        await send_otp_sms(
            payload.phone_number,
            otp
        )


        return {
            "status": "otp_sent",
            "message": "Verification code sent"
        }


    #
    # STEP 2: VERIFY OTP
    #
    if payload.step == PhoneStep.VERIFY:


        if not payload.otp:
            raise HTTPException(
                status_code=400,
                detail="OTP required"
            )


        pending_str = await redis.get(
            f"phone_change:{user_id}"
        )


        if not pending_str:
            raise HTTPException(
                status_code=400,
                detail="OTP expired or not requested"
            )


        pending = json.loads(pending_str)


        if hash_otp(payload.otp) != pending["otp_hash"]:
            raise HTTPException(
                status_code=400,
                detail="Invalid OTP"
            )


        action = pending["action"]


        #
        # REMOVE PHONE
        #
        if action == PhoneAction.REMOVE.value:

            if current_phone:
                await redis.hdel(
                    "phone_numbers",
                    current_phone
                )

            user_data.pop(
                "phone_number",
                None
            )


        #
        # UPDATE PHONE
        #
        elif action == PhoneAction.UPDATE.value:

            new_phone = pending["new_phone_number"]


            # remove old index
            if current_phone:
                await redis.hdel(
                    "phone_numbers",
                    current_phone
                )


            user_data["phone_number"] = new_phone


            # create new index
            await redis.hset(
                "phone_numbers",
                new_phone,
                user_id
            )


        await redis.hset(
            "users",
            user_id,
            json.dumps(user_data)
        )


        await redis.delete(
            f"phone_change:{user_id}"
        )


        return {
            "status": "success",
            "message": (
                "Phone removed successfully"
                if action == PhoneAction.REMOVE.value
                else "Phone updated successfully"
            )
        }

