"""
AWS KMS signing backend.

This module provides PGP-compatible signing using AWS KMS keys.
"""

import asyncio
import logging
import syslog
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from fastapi import UploadFile

from sign.errors import FileTooBigError
from sign.kms.pgp_wrapper import (
    compute_pgp_hash,
    wrap_signature_as_pgp,
)
from sign.utils.hashing import hash_content

logger = logging.getLogger(__name__)


class KMS:
    """
    AWS KMS signing backend with PGP-compatible output.

    This class uses AWS KMS for cryptographic signing operations
    and wraps the raw signatures in OpenPGP format for GPG compatibility.
    """

    def __init__(
        self,
        key_ids: List[str],
        gpg_fingerprints: dict,
        region: Optional[str] = None,
        signing_algorithm: str = 'RSASSA_PKCS1_V1_5_SHA_256',
        max_upload_bytes: int = 100000000,
        tmp_dir: str = '/tmp',
        max_workers: int = 10,
    ):
        """
        Initialize the KMS signing backend.

        Args:
            key_ids: List of KMS key IDs or aliases
            gpg_fingerprints: Mapping of KMS key ID -> GPG fingerprint
            region: AWS region (uses default if not specified)
            signing_algorithm: KMS signing algorithm
            max_upload_bytes: Maximum file size for signing
            tmp_dir: Directory for temporary files
            max_workers: Maximum concurrent signing operations
        """
        self._key_ids = key_ids
        self._gpg_fingerprints = gpg_fingerprints
        self._region = region
        self._signing_algorithm = signing_algorithm
        self._max_upload_bytes = max_upload_bytes
        self._tmp_dir = tmp_dir
        self._max_workers = max_workers

        # Configure boto3 client with retries
        config = Config(
            retries={'max_attempts': 3, 'mode': 'adaptive'},
            max_pool_connections=max_workers + 5,
        )

        if region:
            self._client = boto3.client(
                'kms', region_name=region, config=config
            )
        else:
            self._client = boto3.client('kms', config=config)

        self._executor = ThreadPoolExecutor(max_workers=max_workers)

        # Validate keys on init
        self._validate_keys()

    def _validate_keys(self):
        """Validate that configured keys exist and are usable."""
        for key_id in self._key_ids:
            try:
                response = self._client.describe_key(KeyId=key_id)
                key_state = response['KeyMetadata']['KeyState']
                if key_state != 'Enabled':
                    logger.warning(
                        "KMS key %s is not enabled (state: %s)",
                        key_id,
                        key_state,
                    )
            except ClientError as e:
                logger.error("Failed to validate KMS key %s: %s", key_id, e)
                raise ValueError(f"Invalid KMS key: {key_id}") from e

    def key_exists(self, keyid: str) -> bool:
        """Check if a key exists in the configured key list."""
        return keyid in self._key_ids

    def list_keys(self) -> List[str]:
        """Return list of configured key IDs."""
        return self._key_ids.copy()

    def get_gpg_fingerprint(self, keyid: str) -> str:
        """Get the GPG fingerprint for a given KMS key ID."""
        if keyid in self._gpg_fingerprints:
            return self._gpg_fingerprints[keyid]
        raise ValueError(
            f"No GPG fingerprint configured for KMS key: {keyid}"
        )

    def _sign_digest(self, key_id: str, digest: bytes) -> bytes:
        """
        Sign a digest using KMS.

        Args:
            key_id: KMS key ID
            digest: Hash digest to sign

        Returns:
            Raw signature bytes
        """
        response = self._client.sign(
            KeyId=key_id,
            Message=digest,
            MessageType='DIGEST',
            SigningAlgorithm=self._signing_algorithm,
        )
        return response['Signature']

    def _log_signing_event(
        self, filename: str, keyid: str, hash_before: str, success: bool
    ):
        """Log signing event to syslog for audit."""
        status = "SUCCESS" if success else "FAILED"
        message = (
            f"KMS Sign {status}: file={filename} "
            f"key={keyid} hash={hash_before}"
        )
        try:
            syslog.syslog(syslog.LOG_INFO, message)
        except Exception:
            logger.info(message)

    async def sign(
        self,
        keyid: str,
        file: UploadFile,
        detach_sign: bool = True,
        digest_algo: str = 'SHA256',
    ) -> str:
        """
        Sign a file using AWS KMS.

        Args:
            keyid: KMS key ID to use for signing
            file: File to sign (FastAPI UploadFile)
            detach_sign: True for detached signature, False for cleartext
            digest_algo: Hash algorithm (SHA256, SHA384, SHA512)

        Returns:
            ASCII-armored PGP signature
        """
        if keyid not in self._key_ids:
            raise ValueError(f"Key not found: {keyid}")

        # Read file content
        content = await file.read()
        await file.seek(0)

        if len(content) > self._max_upload_bytes:
            raise FileTooBigError(
                f"File size {len(content)} exceeds limit {self._max_upload_bytes}"
            )

        filename = file.filename or 'unknown'
        hash_before = hash_content(content)

        logger.info(
            "Signing file %s (%d bytes) with KMS key %s",
            filename,
            len(content),
            keyid,
        )

        try:
            gpg_fingerprint = self.get_gpg_fingerprint(keyid)

            # Compute the PGP signature hash
            digest, sig_type, hash_algo, creation_time, issuer_key_id = (
                compute_pgp_hash(
                    content, digest_algo, detach_sign, gpg_fingerprint
                )
            )

            # Sign with KMS in thread pool (boto3 is synchronous)
            loop = asyncio.get_event_loop()
            raw_signature = await loop.run_in_executor(
                self._executor, self._sign_digest, keyid, digest
            )

            # Wrap in PGP format
            pgp_signature = wrap_signature_as_pgp(
                raw_signature,
                content,
                digest_algo,
                detach_sign,
                gpg_fingerprint,
                creation_time,
            )

            self._log_signing_event(filename, keyid, hash_before, True)
            return pgp_signature

        except ClientError as e:
            self._log_signing_event(filename, keyid, hash_before, False)
            logger.error("KMS signing failed: %s", e)
            raise RuntimeError(f"KMS signing failed: {e}") from e

    async def sign_batch(
        self,
        keyid: str,
        files: List[UploadFile],
        detach_sign: bool = True,
        digest_algo: str = 'SHA256',
    ) -> List[Tuple[str, str]]:
        """
        Sign multiple files using AWS KMS.

        Args:
            keyid: KMS key ID to use for signing
            files: List of files to sign
            detach_sign: True for detached signatures
            digest_algo: Hash algorithm

        Returns:
            List of (filename, signature) tuples
        """
        tasks = [
            self.sign(keyid, file, detach_sign, digest_algo) for file in files
        ]

        results = []
        signatures = await asyncio.gather(*tasks, return_exceptions=True)

        for file, sig_or_error in zip(files, signatures):
            filename = file.filename or 'unknown'
            if isinstance(sig_or_error, Exception):
                logger.error("Failed to sign %s: %s", filename, sig_or_error)
                raise sig_or_error
            results.append((filename, sig_or_error))

        return results
