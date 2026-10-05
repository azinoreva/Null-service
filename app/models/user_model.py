from pydantic import BaseModel, Field
from typing import Optional
import re
from enum import Enum

class Recovery(str, Enum):
    STANDARD="standard"
    SECURE= "Secure"

class UserStart(BaseModel):
    phone: str = Field(..., max_length=16, re=r'^\d{11}$')

class UserRegister(BaseModel):
    otp: str = Field(..., min_length=6, max_length=6, re=r'^\d{6}$')
    phone: str = Field(..., max_length=16, re=r'^\d{11}$')
    password: str = Field(..., max_length=40)
    encrypted_blob: Optional[str] = Field(..., max_length=10000)

class User(BaseModel):
    _id: str 
    phone: str
    password: str
    salt:str
    push_token: Optional[str] = None
    recovery_type: Recovery = Recovery.STANDARD
    settings_blob: None
    encrypted_blob: Optional[str]
    schema_version: int = 1

    


class UserCreate(BaseModel):
    password: str = Field(min_length=8, max_length=15)

class UserSignUp(BaseModel):
    expired: bool = False
    password: Optional[str] = Field(default=None, min_length=8, max_length=15)



class UserAccountCreate:  
    phone_number: str = Field(..., min_length=10, max_length=15)
    password: str = Field(min_length=8, max_length=20)


class RecoveryPolicy(str, Enum):
    STANDARD = "standard"
    LOCKDOWN = "lockdown"
# This information must sit in database.
class UserAccount(BaseModel):
    id: str = Field(..., max_length=50, alias="_id")
    phone_number: Optional[str] = Field(None)
    recovery_type: RecoveryPolicy
    salt: str  # Salt used to hash password
    password: str # Hashed password # Timestamp of the last invitation count reset
    push_notification_token: Optional[list]
    date_created: int
    settings_blob: Optional[str]
    encrypted_blob: Optional[str] = Field(max_length=10000) # Encrypted blob of password so that the user can sign in when they forget their password. This is a one-time encrypted blob that is created when the user signs up. It is used to create a new password for the user when they forget their password. The encrypted blob is created using the user's password and a salt. The salt version is stored in the database so that we can use the correct salt version when decrypting the blob. The encrypted blob is deleted after it is used to create a new password for the user. This is to ensure that the user cannot use the same encrypted blob to create multiple passwords. The encrypted blob is also deleted after 24 hours to ensure that it cannot be used after that time period.
    schema_version: int = Field(default=1, description="Version of the schema")
    class Config:
        schema_extra = {
            "example": {
                "_id": "user_1234567890abcdef",
                "phone_number": "+1234567890",
                "recovery_type": "standard",
                "salt": "salt_here",
                "password": "hashed_password_here",
                "push_notification_token": None,
                "settings_blob": None,
                "date_created": 1620000000,
                "encrypted_blob": None,
                "schema_version": 1
            }
        }


class SignIn(BaseModel):
    phone_number: Optional[str] = Field(None, min_length=10, max_length=15, description="The phone number of the user")
    password: str = Field(..., min_length=8, max_length=20)
    user_id: Optional[str] = Field(None, min_length=32, max_length=36, description="The user id of the user")
    encrypted_document_blob: Optional[str]  = Field(None, max_length=10000, description ="This is not the password. This is for when the user is not known by the server. But thier blob exist. Lets say the server gets wiped this is recovery")
    salt_version: Optional[int] = Field(None, description="The version of the salt. This is used to verify the password")


class RecreateData(BaseModel):
    password: str = Field(min_length=8, max_length=20)


class ForgotPassword(BaseModel):
    user_id:Optional[str] = Field(default=None, min_length=32, max_length=36)
    phone_number: Optional[str] = Field(default=None, min_length=10, max_length=15)
    pin: Optional[str] = Field (default=None, min_length=6, max_length=6)


class SignInReturn(BaseModel):
    access_token: str
    refresh_token: str
    expires: int
    user_id: str


class ReturnUserCreate(BaseModel):
    user_id: str
    salt_version: int
    security_token: str
    schema_version: int
    recovery_type: RecoveryPolicy
    passport: str