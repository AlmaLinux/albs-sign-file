import logging
from abc import ABC, abstractmethod
from typing import List, Optional, Tuple

from fastapi import UploadFile

from sign.config import settings


class SigningBackend(ABC):
    @abstractmethod
    def key_exists(self, keyid: str) -> bool:
        pass

    @abstractmethod
    def list_keys(self) -> List[str]:
        pass

    @abstractmethod
    async def sign(
        self,
        keyid: str,
        file: UploadFile,
        detach_sign: bool = True,
        digest_algo: str = 'SHA256',
    ) -> str:
        pass

    @abstractmethod
    async def sign_batch(
        self,
        keyid: str,
        files: List[UploadFile],
        detach_sign: bool = True,
        digest_algo: str = 'SHA256',
    ) -> List[Tuple[str, str]]:
        pass


_backend_instance: Optional[SigningBackend] = None


def get_signing_backend() -> SigningBackend:
    global _backend_instance

    if _backend_instance is not None:
        return _backend_instance

    backend_type = settings.signing_backend

    if backend_type == 'gpg':
        from sign.pgp import PGP

        _backend_instance = GPGAdapter(
            PGP(
                keyring=settings.keyring,
                gpg_binary=settings.gpg_binary,
                pgp_keys=settings.pgp_keys,
                pass_db_dev_mode=settings.pass_db_dev_mode,
                pass_db_dev_pass=settings.pass_db_dev_pass,
                max_upload_bytes=settings.max_upload_bytes,
                tmp_dir=settings.tmp_dir,
            )
        )
        logging.info("Using GPG signing backend")

    elif backend_type == 'kms':
        kms_key_ids = settings.get_kms_key_ids()
        kms_gpg_fingerprints = settings.get_kms_gpg_fingerprints()

        if not kms_key_ids:
            raise ValueError(
                "KMS backend requires SF_KMS_CONFIG_FILE with keys"
            )
        if not kms_gpg_fingerprints:
            raise ValueError(
                "KMS config missing gpg_fingerprint for keys"
            )

        from sign.kms import KMS

        _backend_instance = KMSAdapter(
            KMS(
                key_ids=kms_key_ids,
                gpg_fingerprints=kms_gpg_fingerprints,
                region=settings.kms_region,
                signing_algorithm=settings.kms_signing_algorithm,
                max_upload_bytes=settings.max_upload_bytes,
                tmp_dir=settings.tmp_dir,
                max_workers=settings.kms_max_workers,
            )
        )
        logging.info("Using AWS KMS signing backend")

    else:
        raise ValueError(f"Unknown signing backend: {backend_type}")

    return _backend_instance


class GPGAdapter(SigningBackend):
    def __init__(self, pgp):
        self._pgp = pgp

    def key_exists(self, keyid: str) -> bool:
        return self._pgp.key_exists(keyid)

    def list_keys(self) -> List[str]:
        return [key['keyid'] for key in self._pgp.list_keys()]

    async def sign(
        self,
        keyid: str,
        file: UploadFile,
        detach_sign: bool = True,
        digest_algo: str = 'SHA256',
    ) -> str:
        return await self._pgp.sign(
            keyid=keyid,
            file=file,
            detach_sign=detach_sign,
            digest_algo=digest_algo,
        )

    async def sign_batch(
        self,
        keyid: str,
        files: List[UploadFile],
        detach_sign: bool = True,
        digest_algo: str = 'SHA256',
    ) -> List[Tuple[str, str]]:
        return await self._pgp.sign_batch(
            keyid=keyid,
            files=files,
            detach_sign=detach_sign,
            digest_algo=digest_algo,
        )


class KMSAdapter(SigningBackend):
    """
    Adapter for AWS KMS signing backend.

    Produces PGP-compatible signatures using AWS KMS for the
    cryptographic operations.
    """

    def __init__(self, kms):
        self._kms = kms

    def key_exists(self, keyid: str) -> bool:
        return self._kms.key_exists(keyid)

    def list_keys(self) -> List[str]:
        return self._kms.list_keys()

    async def sign(
        self,
        keyid: str,
        file: UploadFile,
        detach_sign: bool = True,
        digest_algo: str = 'SHA256',
    ) -> str:
        return await self._kms.sign(
            keyid=keyid,
            file=file,
            detach_sign=detach_sign,
            digest_algo=digest_algo,
        )

    async def sign_batch(
        self,
        keyid: str,
        files: List[UploadFile],
        detach_sign: bool = True,
        digest_algo: str = 'SHA256',
    ) -> List[Tuple[str, str]]:
        return await self._kms.sign_batch(
            keyid=keyid,
            files=files,
            detach_sign=detach_sign,
            digest_algo=digest_algo,
        )
