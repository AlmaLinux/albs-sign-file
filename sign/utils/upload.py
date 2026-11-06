import aiofiles
from fastapi import UploadFile

from sign.errors import FileTooBigError


async def store_upload(file: UploadFile, dest_path: str, max_bytes: int) -> int:
    """Stream an upload to ``dest_path``, enforcing ``max_bytes``."""
    upload_size = 0
    try:
        async with aiofiles.open(dest_path, 'wb') as fd:
            while content := await file.read(1024 * 1024):
                upload_size += len(content)
                if upload_size > max_bytes:
                    raise FileTooBigError
                await fd.write(content)
    finally:
        # Always release the UploadFile's spooled temp file/fd, even if
        # the upload-size check aborts mid-read. See PF-673.
        file.file.close()
    return upload_size
