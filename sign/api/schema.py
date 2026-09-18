from typing import List, Optional, Union

from pydantic import BaseModel


class TokenRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    token: str
    user_id: int
    exp: int


class UserSchema(BaseModel):
    user_id: Union[str, int]
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


class KeysResponse(BaseModel):
    """Keys the authenticated caller may sign with, and what it can do."""

    keys: List[str]
    restricted: bool
    rpm_signing_available: bool
