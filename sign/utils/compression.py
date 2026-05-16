from typing import Optional

import zstandard
from fastapi import UploadFile


SUPPORTED_COMPRESSIONS = ('zstd',)


class DecompressingUploadFile:
    """Wraps an UploadFile and streams zstd decompression on read().

    Proxies the subset of the UploadFile interface used by signing
    backends: async ``read(size)``, ``filename``, and ``file.close()``.
    """

    def __init__(self, upload_file: UploadFile):
        self._upload = upload_file
        self._dctx = zstandard.ZstdDecompressor()
        self._dobj = self._dctx.decompressobj()
        self._buffer = bytearray()
        self._upstream_done = False

    @property
    def filename(self) -> Optional[str]:
        return self._upload.filename

    @property
    def file(self):
        return self._upload.file

    async def read(self, size: int = -1) -> bytes:
        # Pull from upstream and feed decompressor until we have enough
        # decompressed bytes (or upstream is exhausted).
        while not self._upstream_done and (
            size < 0 or len(self._buffer) < size
        ):
            chunk = await self._upload.read(size if size > 0 else 1024 * 1024)
            if not chunk:
                self._upstream_done = True
                # Flush any remaining bytes from the decompressor
                tail = self._dobj.flush()
                if tail:
                    self._buffer.extend(tail)
                break
            try:
                decompressed = self._dobj.decompress(chunk)
            except zstandard.ZstdError as exc:
                raise ValueError(
                    f'invalid zstd stream: {exc}'
                ) from exc
            if decompressed:
                self._buffer.extend(decompressed)

        if size < 0 or size >= len(self._buffer):
            out = bytes(self._buffer)
            self._buffer.clear()
            return out

        out = bytes(self._buffer[:size])
        del self._buffer[:size]
        return out


def maybe_wrap(
    upload_file: UploadFile,
    compression: Optional[str],
) -> UploadFile:
    if not compression:
        return upload_file
    if compression not in SUPPORTED_COMPRESSIONS:
        raise ValueError(
            f'unsupported compression: {compression}'
        )
    return DecompressingUploadFile(upload_file)  # type: ignore[return-value]
