from pydantic import BaseModel, Field
from typing import Optional
import re
import time
from enum import Enum
from sqlalchemy import Column, Integer, String, JSON, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.utils.db import Base

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
class UserORM(Base):
    __tablename__ = "users"

    _id = Column(String, primary_key=True, index=True)
    phone_number = Column(String, unique=True, index=True, nullable=True)
    salt = Column(String, nullable=False)
    password = Column(String, nullable=False)  # hashed password
    recovery_type = Column(String, nullable=False, default=RecoveryPolicy.STANDARD.value)
    push_notification_token = Column(JSON, nullable=True)  # list of tokens
    date_created = Column(Integer, nullable=False, default=lambda: int(time.time()))
    settings_blob = Column(String, nullable=True)
    encrypted_blob = Column(String, nullable=True)  # one-time recovery blob
    schema_version = Column(Integer, nullable=False, default=1)

    def to_doc(self) -> dict:
        """Shape the row exactly like the JSON doc the routes already consume."""
        return {
            "_id": self._id,
            "phone_number": self.phone_number,
            "salt": self.salt,
            "password": self.password,
            "recovery_type": self.recovery_type,
            "push_notification_token": list(self.push_notification_token or []),
            "date_created": self.date_created,
            "settings_blob": self.settings_blob,
            "encrypted_blob": self.encrypted_blob,
            "schema_version": self.schema_version,
        }


def _doc_id(doc: dict) -> Optional[str]:
    return doc.get("_id") or doc.get("id") or doc.get("user_id")


def _enum_value(value) -> Optional[str]:
    if isinstance(value, Enum):
        return value.value
    return value


async def get_user(db: AsyncSession, user_id: str) -> Optional[dict]:
    row = await db.get(UserORM, user_id)
    return row.to_doc() if row else None


async def get_user_by_phone(db: AsyncSession, phone_number: str) -> Optional[dict]:
    row = await db.scalar(
        select(UserORM).where(UserORM.phone_number == phone_number)
    )
    return row.to_doc() if row else None


async def phone_exists(db: AsyncSession, phone_number: str) -> bool:
    row = await db.scalar(
        select(UserORM._id).where(UserORM.phone_number == phone_number)
    )
    return row is not None


async def save_user(db: AsyncSession, doc: dict) -> str:
    """Insert or update a user document. Fields absent from `doc` keep
    their current (or default) value so partial updates are safe."""
    user_id = _doc_id(doc)
    if not user_id:
        raise ValueError("user document has no id")

    row = await db.get(UserORM, user_id)
    if row is None:
        row = UserORM(_id=user_id, date_created=int(time.time()))
        db.add(row)

    if "phone_number" in doc:
        row.phone_number = doc["phone_number"]
    if "password" in doc or "password_hash" in doc:
        row.password = doc.get("password") or doc.get("password_hash")
    if "salt" in doc:
        row.salt = doc["salt"]
    if "recovery_type" in doc:
        row.recovery_type = _enum_value(doc["recovery_type"]) or RecoveryPolicy.STANDARD.value
    if "push_notification_token" in doc:
        tokens = doc["push_notification_token"]
        row.push_notification_token = list(tokens) if tokens else []
    if "date_created" in doc and doc["date_created"] is not None:
        row.date_created = int(doc["date_created"])
    if "settings_blob" in doc:
        row.settings_blob = doc["settings_blob"]
    if "encrypted_blob" in doc:
        row.encrypted_blob = doc["encrypted_blob"]
    if "schema_version" in doc and doc["schema_version"] is not None:
        row.schema_version = int(doc["schema_version"])

    await db.commit()
    return user_id

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