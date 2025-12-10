from typing import List, Optional

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


class BatchSignRequest(BaseModel):
    keyid: str
    sign_type: str = 'detach-sign'
    sign_algo: str = 'SHA256'


class FileSignResult(BaseModel):
    filename: str
    success: bool
    signature: Optional[str] = None


class BatchSignResponse(BaseModel):
    results: List[FileSignResult]
    total: int
    successful: int
