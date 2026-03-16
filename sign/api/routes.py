import logging
from typing import List

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import PlainTextResponse

from sign.api.dependencies import get_backend, get_current_user
from sign.api.schema import (
    BatchSignResponse,
    ErrMessage,
    FileSignResult,
    TokenRequest,
    TokenResponse,
)
from sign.auth.hash import hash_valid
from sign.auth.jwt import JWT
from sign.config import settings
from sign.db.helpers import get_user
from sign.db.models import User
from sign.errors import FileTooBigError, UserNotFoundError
from sign.signing.backend import SigningBackend

router = APIRouter()

jwt = JWT(
    secret=settings.jwt_secret_key,
    expire_minutes=settings.jwt_expire_minutes,
    hash_algoritm=settings.jwt_algoritm,
)


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
    backend: SigningBackend = Depends(get_backend),
) -> str:
    if not backend.key_exists(keyid):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'key {keyid} does not exist',
        )
    try:
        answer = await backend.sign(
            keyid,
            file,
            detach_sign=sign_type == 'detach-sign',
            digest_algo=sign_algo,
        )
    except FileTooBigError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'file size exceeds {settings.max_upload_bytes} bytes',
        )
    logging.info(
        "user %s has signed file %s with key %s",
        user.email, file.filename, keyid,
    )
    return answer


@router.post('/sign-batch', response_model=BatchSignResponse,
             responses={status.HTTP_400_BAD_REQUEST: {"model": ErrMessage}})
async def sign_batch(
    keyid: str,
    files: List[UploadFile] = File(...),
    sign_type: str = 'detach-sign',
    sign_algo: str = 'SHA256',
    user: User = Depends(get_current_user),
    backend: SigningBackend = Depends(get_backend),
) -> BatchSignResponse:
    """
    Sign multiple files asynchronously.

    Processes all files concurrently using async operations for better
    performance. Fails immediately if any file fails (fail-fast behavior).

    Args:
        keyid: The key ID to use for signing
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
            detail='No files provided for signing',
        )

    if not backend.key_exists(keyid):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'key {keyid} does not exist',
        )

    logging.info(
        "user %s initiated batch signing of %d files with key %s",
        user.email, len(files), keyid,
    )

    try:
        results_data = await backend.sign_batch(
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

    file_results = []
    for filename, signature in results_data:
        file_results.append(FileSignResult(
            filename=filename,
            success=True,
            signature=signature,
        ))
        logging.info(
            "user %s successfully signed file %s with key %s",
            user.email, filename, keyid,
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
