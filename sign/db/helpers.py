import re
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sign.auth.hash import get_hash
from sign.config import settings
from sign.db.models import Base, User
from sign.errors import UserNotFoundError


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
            result = conn.execute("SELECT 1 as health_check")
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
        row_count = session.query(User).filter(User.email == email).delete()
        if row_count == 0:
            raise UserNotFoundError
        session.commit()
