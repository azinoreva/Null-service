import time
from typing import Optional

from sqlalchemy import JSON, Column, Integer, String, UniqueConstraint, delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.utils.db import Base


class ContactDropORM(Base):
    """A contact dropped straight into a recipient's inbox.

    Mirrors the old Redis hash `contact:inbox:{recipient_id}` where the
    field was the sender id and the value the serialized contact. The
    unique pair (recipient_id, sender_id) preserves the hash semantics:
    a sender re-dropping overwrites their previous drop.
    """

    __tablename__ = "contact_drops"

    id = Column(Integer, primary_key=True, autoincrement=True)
    recipient_id = Column(String, index=True, nullable=False)
    sender_id = Column(String, nullable=False)
    nickname = Column(String, nullable=False)
    title = Column(String, nullable=False)
    bio = Column(String, nullable=False)
    public_key = Column(String, nullable=False)
    dh_public_key = Column(String, nullable=True)
    avatar = Column(String, nullable=True)
    servers = Column(JSON, nullable=True)
    contact_id = Column(String, nullable=False)
    date_created = Column(Integer, nullable=False, default=lambda: int(time.time()))
    expires_at = Column(Integer, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "recipient_id", "sender_id", name="uq_contact_drop_recipient_sender"
        ),
    )

    def to_doc(self) -> dict:
        return {
            "nickname": self.nickname,
            "title": self.title,
            "bio": self.bio,
            "public_key": self.public_key,
            "dh_public_key": self.dh_public_key,
            "avatar": self.avatar,
            "servers": list(self.servers) if self.servers else self.servers,
            "contact_id": self.contact_id,
        }


class DhDropORM(Base):
    """A dh key dropped into a recipient's inbox.

    Mirrors the old Redis hash `dh_inbox:{user_id}`. Unique pair
    (recipient_id, sender_id) preserves the overwrite-on-redrop behavior.
    """

    __tablename__ = "dh_drops"

    id = Column(Integer, primary_key=True, autoincrement=True)
    recipient_id = Column(String, index=True, nullable=False)
    sender_id = Column(String, nullable=False)
    dh_enc_key = Column(String, nullable=False)
    dh_enc_nonce = Column(String, nullable=False)
    servers = Column(JSON, nullable=True)
    date_created = Column(Integer, nullable=False, default=lambda: int(time.time()))
    expires_at = Column(Integer, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "recipient_id", "sender_id", name="uq_dh_drop_recipient_sender"
        ),
    )

    def to_doc(self) -> dict:
        return {
            "sender_id": self.sender_id,
            "dh_enc_key": self.dh_enc_key,
            "dh_enc_nonce": self.dh_enc_nonce,
            "servers": list(self.servers) if self.servers else self.servers,
        }


def _expiry(expires_in: int) -> int:
    return int(time.time()) + int(expires_in)


async def save_contact_drop(
    db: AsyncSession, recipient_id: str, contact_doc: dict, expires_in: int
) -> None:
    """Insert or overwrite the sender's dropped contact for a recipient."""
    sender_id = contact_doc["contact_id"]

    # Clear the sender's previous drop and any of this recipient's expired
    # drops in one shot, so an active inbox never accumulates stale rows.
    await db.execute(
        delete(ContactDropORM).where(
            ContactDropORM.recipient_id == recipient_id,
            or_(
                ContactDropORM.sender_id == sender_id,
                ContactDropORM.expires_at <= int(time.time()),
            ),
        )
    )
    db.add(
        ContactDropORM(
            recipient_id=recipient_id,
            sender_id=sender_id,
            nickname=contact_doc["nickname"],
            title=contact_doc["title"],
            bio=contact_doc["bio"],
            public_key=contact_doc["public_key"],
            dh_public_key=contact_doc.get("dh_public_key"),
            avatar=contact_doc.get("avatar"),
            servers=contact_doc.get("servers"),
            contact_id=sender_id,
            expires_at=_expiry(expires_in),
        )
    )
    await db.commit()


async def pop_contact_drops(db: AsyncSession, recipient_id: str) -> list[dict]:
    """Return the recipient's live contacts and clear the whole inbox."""
    rows = (
        await db.scalars(
            select(ContactDropORM)
            .where(
                ContactDropORM.recipient_id == recipient_id,
                ContactDropORM.expires_at > int(time.time()),
            )
            .order_by(ContactDropORM.id)
        )
    ).all()
    docs = [row.to_doc() for row in rows]

    await db.execute(
        delete(ContactDropORM).where(ContactDropORM.recipient_id == recipient_id)
    )
    await db.commit()
    return docs


async def save_dh_drop(
    db: AsyncSession, recipient_id: str, sender_id: str, dh_doc: dict, expires_in: int
) -> None:
    """Insert or overwrite the sender's dropped dh key for a recipient."""
    await db.execute(
        delete(DhDropORM).where(
            DhDropORM.recipient_id == recipient_id,
            or_(
                DhDropORM.sender_id == sender_id,
                DhDropORM.expires_at <= int(time.time()),
            ),
        )
    )
    db.add(
        DhDropORM(
            recipient_id=recipient_id,
            sender_id=sender_id,
            dh_enc_key=dh_doc["dh_enc_key"],
            dh_enc_nonce=dh_doc["dh_enc_nonce"],
            servers=dh_doc.get("servers"),
            expires_at=_expiry(expires_in),
        )
    )
    await db.commit()


async def pop_dh_drops(db: AsyncSession, recipient_id: str) -> list[dict]:
    """Return the recipient's live dh drops and clear the whole inbox."""
    rows = (
        await db.scalars(
            select(DhDropORM)
            .where(
                DhDropORM.recipient_id == recipient_id,
                DhDropORM.expires_at > int(time.time()),
            )
            .order_by(DhDropORM.id)
        )
    ).all()
    docs = [row.to_doc() for row in rows]

    await db.execute(
        delete(DhDropORM).where(DhDropORM.recipient_id == recipient_id)
    )
    await db.commit()
    return docs


async def clear_dh_drops(db: AsyncSession, recipient_id: str) -> bool:
    """Wipe a recipient's dh inbox without reading it. True if anything was cleared."""
    result = await db.execute(
        delete(DhDropORM).where(DhDropORM.recipient_id == recipient_id)
    )
    await db.commit()
    return bool(result.rowcount)


async def purge_expired_drops(db: AsyncSession) -> int:
    """Delete every contact/dh drop past its expiry. Returns rows removed.

    Called periodically so inboxes that are never fetched don't grow without
    bound (reads also filter on expiry, so expired rows are never delivered).
    """
    now = int(time.time())
    contact_result = await db.execute(
        delete(ContactDropORM).where(ContactDropORM.expires_at <= now)
    )
    dh_result = await db.execute(
        delete(DhDropORM).where(DhDropORM.expires_at <= now)
    )
    await db.commit()
    return (contact_result.rowcount or 0) + (dh_result.rowcount or 0)
