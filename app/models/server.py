import hmac
import time
from enum import Enum
from typing import List, Optional, Tuple

from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    ForeignKey,
    Integer,
    String,
    Text,
    select,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.updates import Categories
from app.utils.db import Base


class MediaType(Enum):
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"

class ServerType(Enum):
    PRIVATE = "private"
    PUBLIC = "public"


class Media(BaseModel):
    url: str = Field(..., max_length = 150)
    size: int = Field(ge=100, le=10000) # in kilobytes
    timer: int = Field(ge=10)# This is the time in minutes the media will be shown fo
    media_type: List[MediaType]

class Server(BaseModel):
    serverId: str
    serverUrl: str
    serverName: str
    media: Optional[Media] = None
    maxPayload: int  # This is the maximum text length allowed for a message going to posts
    colour: str
    about: str
    categories: Optional[List[Categories]] = None
    annotated: bool
    disabled: bool = False
    location: Optional[str]
    serverType: ServerType



    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "serverId": "1234567890",
                "serverName": "Test Server",
                "media": {
                    "url": "https://example.com/image.jpg",
                    "size": 1024,
                    "timer": 10,
                },
                "maxPayload": 1000,
                "colour": "#FFFFFF",
                "about": "This is a test server",
                "categories": ["general"],
                "annotated":False,
                "disabled": False,
                "serverType": ServerType.PRIVATE

            }
        }
    

class ServerIn(BaseModel):
    server_url: str = Field(..., max_length=150)
    serverName: str = Field(..., max_length=100)
    email: EmailStr
    media: Optional[Media] = None
    maxPayload: int = Field(10000, le=100000) # This is the maximum text length allowed for a message going to
    about: str = Field(..., max_length = 500)
    categories: Optional[List[Categories]] = None  # If none, everything goes
    annotated: bool
    disabled: bool = False
    location: Optional[str] =Field (None, max_length=150)
    otp: str = Field(..., max_length = 6, min_length = 6)
    phone: str = Field(..., max_length=16, min_length=12)
    ephemeral: bool
    serverType: ServerType


# ============================================================
# Persistence: public server data
# ============================================================

class ServerORM(Base):
    """The public server record. Carries no owner information on purpose, so
    a lookup by server id can never reveal who owns the server."""

    __tablename__ = "servers"

    serverId = Column(String, primary_key=True, index=True)
    serverUrl = Column(String, index=True, nullable=False)
    serverName = Column(String, nullable=False)
    serverType = Column(String, nullable=False)
    maxPayload = Column(Integer, nullable=False)
    media = Column(JSON, nullable=True)
    colour = Column(String, nullable=True)
    about = Column(Text, nullable=True)
    categories = Column(JSON, nullable=True)
    annotated = Column(Boolean, nullable=False, default=False)
    disabled = Column(Boolean, nullable=False, default=False)
    location = Column(String, nullable=True)

    def to_doc(self) -> dict:
        return {
            "serverId": self.serverId,
            "serverUrl": self.serverUrl,
            "serverName": self.serverName,
            "serverType": self.serverType,
            "maxPayload": self.maxPayload,
            "media": self.media,
            "colour": self.colour,
            "about": self.about,
            "categories": list(self.categories) if self.categories else self.categories,
            "annotated": bool(self.annotated),
            "disabled": bool(self.disabled),
            "location": self.location,
        }


# ============================================================
# Persistence: ownership (separate table, connected via server_id)
# ============================================================

class ServerOwnerORM(Base):
    """Owner identity for a server.

    Kept in its own table so the public `servers` table stays owner-free.
    The only way to read a row out of here is with the owner's email hash
    (see `get_owned_server`), or by phone hash during registration dedup.
    """

    __tablename__ = "server_owners"

    server_id = Column(
        String,
        ForeignKey("servers.serverId", ondelete="CASCADE"),
        primary_key=True,
    )
    phone_hash = Column(String, unique=True, index=True, nullable=False)
    email_hash = Column(String, index=True, nullable=False)
    phone = Column(String, nullable=True)   # retained only when not ephemeral
    email = Column(String, nullable=True)   # retained only when not ephemeral
    ephemeral = Column(Boolean, nullable=False, default=False)

    def to_doc(self) -> dict:
        return {
            "server_id": self.server_id,
            "phone_hash": self.phone_hash,
            "email_hash": self.email_hash,
            "phone": self.phone,
            "email": self.email,
            "ephemeral": bool(self.ephemeral),
        }


class UserServerORM(Base):
    """Per-account server membership list.

    Replaces the old Redis set `servers:{user_id}`. Not foreign-keyed to
    `servers` on purpose: a client may list servers it is attached to that
    are not registered on this instance.
    """

    __tablename__ = "user_servers"

    user_id = Column(String, primary_key=True, index=True)
    server_id = Column(String, primary_key=True)


def _enum_value(value):
    return value.value if isinstance(value, Enum) else value


def _server_kwargs(record: dict) -> dict:
    return {
        "serverId": record["serverId"],
        "serverUrl": record.get("serverUrl"),
        "serverName": record.get("serverName"),
        "serverType": _enum_value(record.get("serverType")),
        "maxPayload": record.get("maxPayload"),
        "media": record.get("media"),
        "colour": record.get("colour"),
        "about": record.get("about"),
        "categories": record.get("categories"),
        "annotated": bool(record.get("annotated", False)),
        "disabled": bool(record.get("disabled", False)),
        "location": record.get("location"),
    }


def _owner_kwargs(owner: dict) -> dict:
    return {
        "server_id": owner["server_id"],
        "phone_hash": owner["phone_hash"],
        "email_hash": owner["email_hash"],
        "phone": owner.get("phone"),
        "email": owner.get("email"),
        "ephemeral": bool(owner.get("ephemeral", False)),
    }


async def list_servers(db: AsyncSession) -> list[dict]:
    rows = (await db.scalars(select(ServerORM))).all()
    return [row.to_doc() for row in rows]


async def get_server(db: AsyncSession, server_id: str) -> Optional[dict]:
    row = await db.get(ServerORM, server_id)
    return row.to_doc() if row else None


async def create_server(
    db: AsyncSession, server_record: dict, owner_record: dict
) -> None:
    """Insert the public server row and its owner row in one transaction."""
    db.add(ServerORM(**_server_kwargs(server_record)))
    db.add(ServerOwnerORM(**_owner_kwargs(owner_record)))
    await db.commit()


async def save_server(db: AsyncSession, record: dict) -> None:
    server_id = record["serverId"]
    row = await db.get(ServerORM, server_id)
    if row is None:
        db.add(ServerORM(**_server_kwargs(record)))
    else:
        for key, value in _server_kwargs(record).items():
            setattr(row, key, value)
    await db.commit()


async def save_owner(db: AsyncSession, owner: dict) -> None:
    server_id = owner["server_id"]
    row = await db.get(ServerOwnerORM, server_id)
    if row is None:
        db.add(ServerOwnerORM(**_owner_kwargs(owner)))
    else:
        for key, value in _owner_kwargs(owner).items():
            setattr(row, key, value)
    await db.commit()


async def phone_registered(db: AsyncSession, phone_hash: str) -> bool:
    """Duplicate-registration guard: keyed by phone hash, never by server id."""
    return (
        await db.scalar(
            select(ServerOwnerORM.server_id).where(
                ServerOwnerORM.phone_hash == phone_hash
            )
        )
    ) is not None


async def get_owned_server(
    db: AsyncSession, server_id: str, email_hash: str
) -> Optional[Tuple[dict, dict]]:
    """Load a server *and* its owner, but only if the caller proves ownership
    by supplying the owner's email hash. Returns None otherwise so the route
    can answer 404 (same response for "no such server" and "wrong email").
    """
    server_row = await db.get(ServerORM, server_id)
    owner_row = await db.get(ServerOwnerORM, server_id)
    if server_row is None or owner_row is None:
        return None
    if not hmac.compare_digest(owner_row.email_hash or "", email_hash):
        return None
    return server_row.to_doc(), owner_row.to_doc()


async def add_user_servers(
    db: AsyncSession, user_id: str, server_ids: List[str]
) -> None:
    existing = set(
        (
            await db.scalars(
                select(UserServerORM.server_id).where(
                    UserServerORM.user_id == user_id
                )
            )
        ).all()
    )
    for server_id in server_ids:
        if server_id not in existing:
            db.add(UserServerORM(user_id=user_id, server_id=server_id))
            existing.add(server_id)
    await db.commit()


async def list_user_servers(db: AsyncSession, user_id: str) -> List[str]:
    rows = (
        await db.scalars(
            select(UserServerORM.server_id).where(UserServerORM.user_id == user_id)
        )
    ).all()
    return list(rows)