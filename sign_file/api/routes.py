from fastapi import APIRouter, UploadFile, HTTPException
from fastapi.responses import PlainTextResponse
import aiofiles
from sign_file.config import settings
from sign_file.pgp.pgp import PGP
from sign_file.api.schema import JWT_Token, TokenRequest, ErrMessage
from sign_file.db.helpers import get_user
from sign_file.db.models import User
from sign_file.auth.jwt import JWT
from sign_file.auth.hash import hash_valid
from sign_file.errors import UserNotFoudError

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


@router.post('/sign', response_class=PlainTextResponse)
async def sign(keyid: str, file: UploadFile) -> str:
    upload_size = 0
    async with aiofiles.tempfile.NamedTemporaryFile(
            'wb', delete=False, dir=settings.tmp_dir) as tmp_f:
        # reading file
        try:
            while contents := await file.read(1024 * 1024):
                upload_size += len(contents)
                if upload_size > settings.max_upload_bytes:
                    return {'message': f"upload size exeeds {settings.max_upload_bytes} B"}
                await tmp_f.write(contents)
        except Exception as e:
            return {"message": f"There was an error uploading the file:{e}"}
        finally:
            file.file.close()
        # signing file
        res = await pgp.sign(
            keyid, tmp_f.name)
        return str(res)


@router.post('/get-token', response_model=JWT_Token,
             responses={401: {"model": ErrMessage}})
def get_token(token_request: TokenRequest):
    try:
        user: User = get_user(token_request.email)
    except UserNotFoudError:
        raise HTTPException(status_code=401)

    if not hash_valid(token_request.password,
                      user.password):
        raise HTTPException(status_code=401)

    token = jwt.encode(user.id, token_request.email)
    return token
