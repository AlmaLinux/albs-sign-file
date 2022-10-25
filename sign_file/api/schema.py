from ast import Import
from pydantic import BaseModel
from typing import Optional


class TokenRequest(BaseModel):
    email: str
    password: str


class Token(BaseModel):
    token: str
    user_id: int
    exp: int


class UserSchema(BaseModel):
    user_id: str
    email: str


class ErrMessage(BaseModel):
    detail: str
