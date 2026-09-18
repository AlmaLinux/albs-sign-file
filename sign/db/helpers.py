import logging
import re
from contextlib import contextmanager
from typing import List, Optional

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from sign.auth.hash import get_hash
from sign.config import settings
from sign.db.models import Base, SignAuditRecord, User, UserKey, utcnow
from sign.errors import AuditWriteError, UserNotFoundError


def create_database_engine():
    """
    Create a SQLAlchemy engine with optimized settings based on database type.

    For SQLite:
    - Adds check_same_thread=False for FastAPI compatibility

    For PostgreSQL:
    - Connection pooling with configurable pool size
    - Pool pre-ping for connection health checks
    - Automatic connection recycling to prevent stale connections
    - Configurable overflow for handling traffic spikes
    """
    match = re.search(r'^(sqlite|postgresql)', settings.db_url)
    if not match:
        raise NotImplementedError(
            'albs-sign-file supports only psql and sqlite databases'
        )
    if settings.db_url.startswith("sqlite"):
        return create_engine(
            settings.db_url,
            connect_args={"check_same_thread": False},
            echo=settings.db_echo,
        )
    return create_engine(
        settings.db_url,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_recycle=settings.db_pool_recycle,
        pool_pre_ping=settings.db_pool_pre_ping,
        echo=settings.db_echo,
        pool_timeout=30,
        connect_args={
            "connect_timeout": 10,
            "application_name": settings.service,
        },
    )


# Initialize the engine
engine = create_database_engine()


@contextmanager
def get_session():
    """
    Get a new database session as a context manager.

    Usage:
        with get_session() as session:
            user = session.query(User).first()

    The session will be automatically closed when exiting the context.
    """
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield session
    finally:
        session.close()


@contextmanager
def session_scope():
    """
    Provide a transactional scope around a series of operations.
    Automatically commits on success and rolls back on error.

    Usage:
        with session_scope() as session:
            session.query(User).all()
    """
    with get_session() as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise


def get_pool_stats() -> dict:
    """
    Get current connection pool statistics.
    Useful for monitoring and debugging connection pool issues.
    """
    pool = engine.pool
    return {
        "pool_size": pool.size(),
        "checked_in": pool.checkedin(),
        "checked_out": pool.checkedout(),
        "overflow": pool.overflow(),
        "total_connections": pool.size() + pool.overflow(),
    }


def db_is_connected() -> bool:
    """
    Check database connectivity
    Returns:
        bool: Connection status
    Raises:
        Exception: If connection fails
    """
    try:
        with engine.connect() as conn:
            # Execute a simple query to verify connection
            result = conn.execute(text("SELECT 1 as health_check"))
            result.fetchone()
            return True
    except Exception:
        return False


def db_create():
    Base.metadata.create_all(engine)


def db_drop():
    Base.metadata.drop_all(engine)


def create_user(email: str, password: str):
    hashed = get_hash(password)
    u = User(email=email, password=hashed)
    with get_session() as s:
        s.add(u)
        s.commit()
        u_id = u.id
        return u_id


def user_exists(email: str) -> bool:
    with get_session() as session:
        if session.query(User).filter(User.email == email).first():
            return True
        return False


def get_user(email: str) -> User:
    with get_session() as session:
        user = session.query(User).filter(User.email == email).first()
        if not user:
            raise UserNotFoundError
        # Expunge the user from the session so it can be used after session closes
        session.expunge(user)
        return user


def update_password(email: str, password: str):
    hashed = get_hash(password)
    with get_session() as session:
        row_count = (
            session.query(User)
            .filter(User.email == email)
            .update({'password': hashed})
        )
        if row_count == 0:
            raise UserNotFoundError
        session.commit()


def delete_user(email: str):
    with get_session() as session:
        user = session.query(User).filter(User.email == email).first()
        if not user:
            raise UserNotFoundError
        # SQLite does not enforce foreign keys unless asked to, so the
        # ON DELETE CASCADE on user_keys cannot be relied on here.
        session.query(UserKey).filter(UserKey.user_id == user.id).delete()
        session.delete(user)
        session.commit()


def list_user_keys(email: str) -> List[str]:
    """Key ids explicitly granted to a user (empty list means no grants)."""
    with get_session() as session:
        user = session.query(User).filter(User.email == email).first()
        if not user:
            raise UserNotFoundError
        rows = (
            session.query(UserKey.keyid)
            .filter(UserKey.user_id == user.id)
            .order_by(UserKey.keyid)
            .all()
        )
        return [row[0] for row in rows]


def grant_key(email: str, keyid: str) -> bool:
    """
    Allow a user to sign with ``keyid``.

    Returns False when the grant already existed.
    """
    with get_session() as session:
        user = session.query(User).filter(User.email == email).first()
        if not user:
            raise UserNotFoundError
        existing = (
            session.query(UserKey)
            .filter(UserKey.user_id == user.id, UserKey.keyid == keyid)
            .first()
        )
        if existing:
            return False
        session.add(UserKey(user_id=user.id, keyid=keyid))
        session.commit()
        return True


def revoke_key(email: str, keyid: str) -> bool:
    """
    Withdraw a user's permission to sign with ``keyid``.

    Returns False when there was no such grant. Revoking the last grant
    puts the user back on ``settings.default_key_access``.
    """
    with get_session() as session:
        user = session.query(User).filter(User.email == email).first()
        if not user:
            raise UserNotFoundError
        row_count = (
            session.query(UserKey)
            .filter(UserKey.user_id == user.id, UserKey.keyid == keyid)
            .delete()
        )
        session.commit()
        return row_count > 0


def user_can_sign_with(user: User, keyid: str) -> bool:
    """
    Whether ``user`` may sign with ``keyid``.

    Explicit grants win: once a user has any, they are limited to those
    keys. With no grants the answer comes from
    ``settings.default_key_access``.
    """
    with get_session() as session:
        granted = {
            row[0]
            for row in session.query(UserKey.keyid)
            .filter(UserKey.user_id == user.id)
            .all()
        }
    if granted:
        return keyid in granted
    return settings.default_key_access == 'all'


def start_sign_audit(
    operation: str,
    user_id: Optional[int],
    user_email: str,
    keyid: str,
    filename: Optional[str] = None,
) -> int:
    """
    Open an audit record for a signing request and return its id.

    Raises ``AuditWriteError`` if the record cannot be written: a request
    that cannot be accounted for must not reach a private key.
    """
    record = SignAuditRecord(
        operation=operation,
        user_id=user_id,
        user_email=user_email,
        keyid=keyid,
        filename=filename,
        status='started',
    )
    try:
        with get_session() as session:
            session.add(record)
            session.commit()
            return record.id
    except Exception as exc:
        raise AuditWriteError(str(exc)) from exc


def finish_sign_audit(
    record_id: int,
    status: str,
    package_nevra: Optional[str] = None,
    sha256_before: Optional[str] = None,
    sha256_after: Optional[str] = None,
    signature: Optional[str] = None,
    detail: Optional[str] = None,
):
    """
    Close the audit record opened by :func:`start_sign_audit`.

    Never raises: the package is already signed by this point, so a failure
    to update the row is logged (the 'started' row and the syslog entry
    remain) instead of turning a successful signature into an error.
    """
    values = {
        'status': status,
        'finished_at': utcnow(),
        'package_nevra': package_nevra,
        'sha256_before': sha256_before,
        'sha256_after': sha256_after,
        'signature': signature,
        'detail': detail,
    }
    try:
        with get_session() as session:
            session.query(SignAuditRecord).filter(
                SignAuditRecord.id == record_id
            ).update(values)
            session.commit()
    except Exception:
        logging.exception(
            'Failed to close audit record %s (status %s)', record_id, status
        )
