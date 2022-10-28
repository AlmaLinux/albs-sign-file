from pydantic import BaseModel


class TokenRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    token: str
    user_id: int
    exp: int


class UserSchema(BaseModel):
    user_id: str
    email: str


class ErrMessage(BaseModel):
    detail: str
