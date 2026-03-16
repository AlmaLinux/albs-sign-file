from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer

from sign.auth.jwt import JWT
from sign.config import settings
from sign.db.helpers import get_user
from sign.db.models import User
from sign.errors import UserNotFoundError
from sign.signing.backend import SigningBackend, get_signing_backend

from jwt.exceptions import PyJWTError

jwt = JWT(
    secret=settings.jwt_secret_key,
    expire_minutes=settings.jwt_expire_minutes,
    hash_algoritm=settings.jwt_algoritm,
)
bearer_scheme = HTTPBearer()

_signing_backend: SigningBackend = None


def get_backend() -> SigningBackend:
    """Get the signing backend (lazy singleton)."""
    global _signing_backend
    if _signing_backend is None:
        _signing_backend = get_signing_backend()
    return _signing_backend


async def get_current_user(credentials=Depends(bearer_scheme)) -> User:
    try:
        # If credentials have a whitespace then the token is the part after
        # the whitespace
        if ' ' in credentials.credentials:
            token = credentials.credentials.split(' ')[-1]
        else:
            token = credentials.credentials
        decoded_token = jwt.decode(token)
    except PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )

    try:
        user: User = get_user(decoded_token.email)
    except UserNotFoundError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Could not find user",
        )
    return user
