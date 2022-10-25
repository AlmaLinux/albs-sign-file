from fastapi import APIRouter, Depends, UploadFile, HTTPException, status
from fastapi.responses import PlainTextResponse
from fastapi.security import OAuth2PasswordRequestForm
from sign_file.config import settings
from sign_file.pgp.pgp import PGP
from sign_file.api.schema import Token, TokenRequest, ErrMessage
from sign_file.db.helpers import get_user
from sign_file.db.models import User
from sign_file.auth.jwt import JWT
from sign_file.auth.hash import hash_valid
from sign_file.errors import UserNotFoudError
from sign_file.api.dependencies import get_current_user
import logging

router = APIRouter()

pgp = PGP(keyring=settings.keyring,
          gpg_binary=settings.gpg_binary,
          pgp_keys=settings.pgp_keys,
          pass_db_dev_mode=settings.pass_db_dev_mode,
          pass_db_dev_pass=settings.pass_db_dev_pass)


jwt = JWT(secret=settings.jwt_secret_key,
          expire_minutes=settings.jwt_expire_minutes,
          hash_algoritm=settings.jwt_algoritm)


@router.get('/ping')
async def ping():
    return "pong"


@router.post('/sign', response_class=PlainTextResponse,
             responses={status.HTTP_400_BAD_REQUEST: {"model": ErrMessage}})
async def sign(keyid: str,
               file: UploadFile,
               user: User = Depends(get_current_user)) -> str:
    if not pgp.key_exists(keyid):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'key {keyid} does not exists')
    answer = await pgp.sign(keyid, file)
    logging.info("user %s has signed file %s with key %s",
                 user.email, file.filename, keyid)
    return answer


@router.post('/token', response_model=Token,
             responses={status.HTTP_401_UNAUTHORIZED: {"model": ErrMessage}})
async def token(token_request: TokenRequest):
    try:
        user: User = get_user(token_request.email)
    except UserNotFoudError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    if not hash_valid(token_request.password,
                      user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    token = jwt.encode(user.id, token_request.email)
    return token
