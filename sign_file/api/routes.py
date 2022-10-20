from fastapi import APIRouter, UploadFile
from fastapi.responses import PlainTextResponse
import aiofiles
from .signer import pgp
from ..config import settings

router = APIRouter()


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
        return res
