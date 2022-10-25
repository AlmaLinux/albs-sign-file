from ast import Import
from pydantic import BaseModel
from typing import Optional


class TokenRequest(BaseModel):
    email: str
    password: str


class JWT_Token(BaseModel):
    user_id: int
    email: str
    token: str
    exp: Optional[int] = None


class ErrMessage(BaseModel):
    details: str
