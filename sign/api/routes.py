import logging
from typing import List

from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status
from fastapi.responses import PlainTextResponse

from sign.config import settings
from sign.pgp.pgp import PGP
from sign.api.schema import (
    TokenRequest,
    TokenResponse,
    ErrMessage,
    BatchSignResponse,
    FileSignResult,
)
from sign.db.helpers import get_user
from sign.db.models import User
from sign.auth.jwt import JWT
from sign.auth.hash import hash_valid
from sign.errors import UserNotFoundError, FileTooBigError
from sign.api.dependencies import get_current_user

router = APIRouter()

pgp = PGP(keyring=settings.keyring,
          gpg_binary=settings.gpg_binary,
          pgp_keys=settings.pgp_keys,
          pass_db_dev_mode=settings.pass_db_dev_mode,
          pass_db_dev_pass=settings.pass_db_dev_pass,
          max_upload_bytes=settings.max_upload_bytes)


jwt = JWT(secret=settings.jwt_secret_key,
          expire_minutes=settings.jwt_expire_minutes,
          hash_algoritm=settings.jwt_algoritm)


@router.get('/ping')
async def ping():
    return "pong"


@router.post('/sign', response_class=PlainTextResponse,
             responses={status.HTTP_400_BAD_REQUEST: {"model": ErrMessage}})
async def sign(
    keyid: str,
    file: UploadFile,
    sign_type: str = 'detach-sign',
    sign_algo: str = 'SHA256',
    user: User = Depends(get_current_user),
) -> str:
    if not pgp.key_exists(keyid):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'key {keyid} does not exists')
    try:
        answer = await pgp.sign(
            keyid,
            file,
            detach_sign=sign_type == 'detach-sign',
            digest_algo=sign_algo,
        )
    except FileTooBigError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'file size exceeds {settings.max_upload_bytes} bytes'
        )
    logging.info("user %s has signed file %s with key %s",
                 user.email, file.filename, keyid)
    return answer


@router.post('/sign-batch', response_model=BatchSignResponse,
             responses={status.HTTP_400_BAD_REQUEST: {"model": ErrMessage}})
async def sign_batch(
    keyid: str,
    files: List[UploadFile] = File(...),
    sign_type: str = 'detach-sign',
    sign_algo: str = 'SHA256',
    user: User = Depends(get_current_user),
) -> BatchSignResponse:
    """
    Sign multiple files asynchronously.

    Due to GPG limitations with detach-sign option, each file is processed
    individually from download to signature generation. This endpoint processes
    all files concurrently using async operations for better performance.

    Fails immediately if any file fails (fail-fast behavior).

    Args:
        keyid: The PGP key ID to use for signing
        files: List of files to sign
        sign_type: Signature type ('detach-sign' or 'clear-sign')
        sign_algo: Digest algorithm (default: 'SHA256')
        user: Authenticated user (from JWT token)

    Returns:
        BatchSignResponse with results for each file (all successful)

    Raises:
        HTTPException: If any file fails to sign
    """
    if not files:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='No files provided for signing'
        )

    if not pgp.key_exists(keyid):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'key {keyid} does not exist'
        )

    logging.info(
        "user %s initiated batch signing of %d files with key %s",
        user.email, len(files), keyid
    )

    # Process all files asynchronously (fail-fast on first error)
    try:
        results_data = await pgp.sign_batch(
            keyid=keyid,
            files=files,
            detach_sign=sign_type == 'detach-sign',
            digest_algo=sign_algo,
        )
    except FileTooBigError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'file size exceeds {settings.max_upload_bytes} bytes',
        )

    # All files signed successfully
    file_results = []
    for filename, signature in results_data:
        file_results.append(FileSignResult(
            filename=filename,
            success=True,
            signature=signature,
        ))
        logging.info(
            "user %s successfully signed file %s with key %s",
            user.email, filename, keyid
        )

    return BatchSignResponse(
        results=file_results,
        total=len(files),
        successful=len(files),
    )


@router.post('/token', response_model=TokenResponse,
             responses={status.HTTP_401_UNAUTHORIZED: {"model": ErrMessage}})
async def token(token_request: TokenRequest):
    try:
        user: User = get_user(token_request.email)
    except UserNotFoundError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    if not hash_valid(token_request.password,
                      user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    token = jwt.encode(user.id, token_request.email)
    return token
