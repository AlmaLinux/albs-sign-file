import logging
import os
import re
from typing import List

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import FileResponse, PlainTextResponse
from starlette.background import BackgroundTask

from sign.api.dependencies import get_backend, get_current_user
from sign.api.schema import (
    BatchSignResponse,
    ErrMessage,
    FileSignResult,
    KeysResponse,
    TokenRequest,
    TokenResponse,
)
from sign.auth.hash import hash_valid
from sign.auth.jwt import JWT
from sign.config import settings
from sign.db.helpers import (
    finish_sign_audit,
    get_user,
    list_user_keys,
    start_sign_audit,
    user_can_sign_with,
)
from sign.db.models import User
from sign.errors import (
    AuditWriteError,
    FileTooBigError,
    NotAnRpmError,
    RpmSignError,
    UserNotFoundError,
)
from sign.signing.backend import SigningBackend

router = APIRouter()

RPM_SIGN_OPERATION = 'rpm-header'
# Starlette renamed HTTP_413_REQUEST_ENTITY_TOO_LARGE to
# HTTP_413_CONTENT_TOO_LARGE; spell the code out so either version works.
HTTP_413_PAYLOAD_TOO_LARGE = 413
UNSAFE_FILENAME_CHARS = re.compile(r'[^A-Za-z0-9._+~-]')


def ensure_key_allowed(user: User, keyid: str):
    """
    Reject the request unless ``user`` is entitled to sign with ``keyid``.

    See ``sign.db.models.UserKey`` for how entitlement is resolved.
    """
    if user_can_sign_with(user, keyid):
        return
    logging.warning(
        "user %s attempted to sign with key %s without permission",
        user.email,
        keyid,
    )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f'not authorized to sign with key {keyid}',
    )


def safe_filename(name: str, fallback: str = 'package.rpm') -> str:
    """
    Reduce a caller-supplied filename to a basename safe to echo back in a
    Content-Disposition header.
    """
    name = os.path.basename(name or '')
    name = UNSAFE_FILENAME_CHARS.sub('_', name).lstrip('.')
    return name or fallback


jwt = JWT(
    secret=settings.jwt_secret_key,
    expire_minutes=settings.jwt_expire_minutes,
    hash_algoritm=settings.jwt_algoritm,
)


@router.get('/ping')
async def ping():
    return "pong"


@router.post('/sign', response_class=PlainTextResponse,
             responses={status.HTTP_400_BAD_REQUEST: {"model": ErrMessage},
                        status.HTTP_403_FORBIDDEN: {"model": ErrMessage}})
async def sign(
    keyid: str,
    file: UploadFile,
    sign_type: str = 'detach-sign',
    sign_algo: str = 'SHA256',
    raw_signature: bool = False,
    user: User = Depends(get_current_user),
    backend: SigningBackend = Depends(get_backend),
) -> str:
    if not backend.key_exists(keyid):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'key {keyid} does not exist',
        )
    ensure_key_allowed(user, keyid)
    try:
        answer = await backend.sign(
            keyid,
            file,
            detach_sign=sign_type == 'detach-sign',
            digest_algo=sign_algo,
            raw_signature=raw_signature,
        )
    except FileTooBigError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'file size exceeds {settings.max_upload_bytes} bytes',
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    logging.info(
        "user %s has signed file %s with key %s (raw=%s)",
        user.email, file.filename, keyid, raw_signature,
    )
    return answer


@router.post('/sign-batch', response_model=BatchSignResponse,
             responses={status.HTTP_400_BAD_REQUEST: {"model": ErrMessage},
                        status.HTTP_403_FORBIDDEN: {"model": ErrMessage}})
async def sign_batch(
    keyid: str,
    files: List[UploadFile] = File(...),
    sign_type: str = 'detach-sign',
    sign_algo: str = 'SHA256',
    raw_signature: bool = False,
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
        raw_signature: If True, return raw KMS signatures (KMS backend only)
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
    ensure_key_allowed(user, keyid)

    logging.info(
        "user %s initiated batch signing of %d files with key %s (raw=%s)",
        user.email, len(files), keyid, raw_signature,
    )

    try:
        results_data = await backend.sign_batch(
            keyid=keyid,
            files=files,
            detach_sign=sign_type == 'detach-sign',
            digest_algo=sign_algo,
            raw_signature=raw_signature,
        )
    except FileTooBigError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'file size exceeds {settings.max_upload_bytes} bytes',
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
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


@router.post(
    '/sign-rpm',
    response_class=FileResponse,
    responses={
        status.HTTP_200_OK: {
            'content': {'application/x-rpm': {}},
            'description': 'the submitted package with a signed header',
        },
        status.HTTP_400_BAD_REQUEST: {'model': ErrMessage},
        status.HTTP_403_FORBIDDEN: {'model': ErrMessage},
        HTTP_413_PAYLOAD_TOO_LARGE: {'model': ErrMessage},
        status.HTTP_501_NOT_IMPLEMENTED: {'model': ErrMessage},
        status.HTTP_503_SERVICE_UNAVAILABLE: {'model': ErrMessage},
    },
)
async def sign_rpm(
    keyid: str,
    file: UploadFile,
    user: User = Depends(get_current_user),
    backend: SigningBackend = Depends(get_backend),
):
    """
    Sign the header of an RPM or SRPM and return the signed package.

    The package is signed with ``rpmsign --resign``, exactly as the build
    system signs its own artifacts, so a package that was built elsewhere
    can carry a header signature from a key that never leaves the farm.
    Only the signature header changes; the payload is untouched.

    Args:
        keyid: id of the key to sign with; the caller must be entitled to it
        file: the RPM/SRPM to sign

    Returns:
        The signed package as ``application/x-rpm``.
    """
    if not settings.rpm_sign_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='RPM header signing is disabled on this service',
        )
    if not backend.supports_rpm_signing():
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=(
                'RPM header signing is not supported by the '
                f'{settings.signing_backend} signing backend'
            ),
        )
    if not backend.key_exists(keyid):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'key {keyid} does not exist',
        )
    ensure_key_allowed(user, keyid)

    filename = safe_filename(file.filename)
    # The audit record is opened before the key is touched: a request that
    # cannot be accounted for must not be signed.
    try:
        record_id = start_sign_audit(
            operation=RPM_SIGN_OPERATION,
            user_id=user.id,
            user_email=user.email,
            keyid=keyid,
            filename=filename,
        )
    except AuditWriteError as exc:
        logging.error('Cannot open audit record for %s: %s', user.email, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='signing is unavailable: audit trail is not writable',
            headers={'Retry-After': '30'},
        )

    try:
        outcome = await backend.sign_rpm(
            keyid=keyid,
            file=file,
            user_email=user.email,
        )
    except FileTooBigError:
        finish_sign_audit(record_id, 'rejected', detail='file too big')
        raise HTTPException(
            status_code=HTTP_413_PAYLOAD_TOO_LARGE,
            detail=f'file size exceeds {settings.rpm_upload_limit} bytes',
        )
    except NotAnRpmError as exc:
        finish_sign_audit(record_id, 'rejected', detail=str(exc))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'not a valid RPM package: {exc}',
        )
    except ValueError as exc:
        finish_sign_audit(record_id, 'rejected', detail=str(exc))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    except RpmSignError as exc:
        logging.error(
            'rpmsign failed for user %s with key %s: %s',
            user.email, keyid, exc,
        )
        finish_sign_audit(record_id, 'failed', detail=str(exc))
        # The package was rejected by the signing side, not by its content:
        # the gpg agent or the key may be momentarily unavailable, so the
        # caller is told to retry rather than to change the request.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='signing failed, please retry',
            headers={'Retry-After': '30'},
        )
    except Exception as exc:
        finish_sign_audit(record_id, 'failed', detail=str(exc))
        raise

    finish_sign_audit(
        record_id,
        'signed',
        package_nevra=outcome.identity['nevra'],
        sha256_before=outcome.hash_before,
        sha256_after=outcome.hash_after,
        signature=outcome.signature,
    )
    logging.info(
        "user %s has signed RPM %s (%s) with key %s",
        user.email, filename, outcome.identity['nevra'], keyid,
    )
    return FileResponse(
        outcome.path,
        media_type='application/x-rpm',
        filename=filename,
        # The signed package is a temp file; drop it once it is on the wire.
        background=BackgroundTask(os.unlink, outcome.path),
    )


@router.get('/keys', response_model=KeysResponse)
async def keys(
    user: User = Depends(get_current_user),
    backend: SigningBackend = Depends(get_backend),
) -> KeysResponse:
    """
    List the keys this caller may sign with.

    ``restricted`` says whether the list comes from explicit grants for
    this user or from every key the service holds.
    """
    granted = list_user_keys(user.email)
    available = backend.list_keys()
    if granted:
        return KeysResponse(
            keys=sorted(set(granted) & set(available)),
            restricted=True,
            rpm_signing_available=(
                settings.rpm_sign_enabled and backend.supports_rpm_signing()
            ),
        )
    return KeysResponse(
        keys=sorted(available) if settings.default_key_access == 'all' else [],
        restricted=settings.default_key_access != 'all',
        rpm_signing_available=(
            settings.rpm_sign_enabled and backend.supports_rpm_signing()
        ),
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
