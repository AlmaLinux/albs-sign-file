from fastapi import HTTPException, status, Header
from typing import Union
from sign_file.db.models import User
from sign_file.db.helpers import get_user
from sign_file.config import settings
from sign_file.auth.jwt import JWT
from sign_file.errors import UserNotFoudError
from jwt.exceptions import PyJWTError

jwt = JWT(secret=settings.jwt_secret_key,
          expire_minutes=settings.jwt_expire_minutes,
          hash_algoritm=settings.jwt_algoritm)


async def get_current_user(token: Union[str, None] = Header(default=None)) -> User:
    try:
        decoded_token = jwt.decode(str.encode(token))
    except PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )

    try:
        user: User = get_user(decoded_token.email)
    except UserNotFoudError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Could not find user",
        )
    return user
