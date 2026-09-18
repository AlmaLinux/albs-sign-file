import datetime

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


def utcnow() -> datetime.datetime:
    """
    Naive UTC 'now'.

    ``datetime.utcnow()`` is deprecated from Python 3.12 on, and the columns
    below are timezone-naive, so the offset is dropped explicitly rather
    than left to the database driver.
    """
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)


class UserKey(Base):
    """
    Keys a user is allowed to sign with.

    A user with no rows here falls back to ``settings.default_key_access``
    ('all' keeps the historical behaviour of letting any authenticated user
    sign with any key the service holds; 'none' denies until keys are
    granted explicitly). A user with at least one row is always restricted
    to the keys listed for them, whatever the default is.
    """

    __tablename__ = "user_keys"
    __table_args__ = (
        UniqueConstraint('user_id', 'keyid', name='uq_user_keys_user_keyid'),
    )

    id = Column(Integer, primary_key=True)
    user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='CASCADE'),
        index=True,
        nullable=False,
    )
    keyid = Column(String, index=True, nullable=False)


class SignAuditRecord(Base):
    """
    One row per signing request that reaches a private key.

    The row is written before signing starts and updated with the outcome,
    so an interrupted or failed request still leaves a trace of who asked
    for what.
    """

    __tablename__ = "sign_audit_records"

    id = Column(Integer, primary_key=True)
    created_at = Column(
        DateTime,
        default=utcnow,
        index=True,
        nullable=False,
    )
    finished_at = Column(DateTime, nullable=True)
    operation = Column(String, nullable=False)
    user_id = Column(Integer, index=True, nullable=True)
    user_email = Column(String, index=True, nullable=False)
    keyid = Column(String, index=True, nullable=False)
    filename = Column(String, nullable=True)
    package_nevra = Column(String, index=True, nullable=True)
    sha256_before = Column(String, nullable=True)
    sha256_after = Column(String, nullable=True)
    signature = Column(String, nullable=True)
    status = Column(String, nullable=False)
    detail = Column(String, nullable=True)
