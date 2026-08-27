"""
AWS KMS signing backend.

This module provides PGP-compatible signing using AWS KMS keys.
"""

import asyncio
import base64
import hashlib
import logging
import syslog
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

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

# Digest algorithms this backend accepts, mapped to their hashlib name and
# the AWS KMS SigningAlgorithm suffix. KMS requires the digest length to match
# the hash named by SigningAlgorithm when MessageType is DIGEST, so the two
# can never be chosen independently.
SUPPORTED_DIGESTS = {
    'SHA256': ('sha256', 'SHA_256'),
    'SHA384': ('sha384', 'SHA_384'),
    'SHA512': ('sha512', 'SHA_512'),
}


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
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
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
            access_key_id: AWS access key ID (optional, uses env/IAM if not set)
            secret_access_key: AWS secret access key (optional)
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

        client_kwargs = {'config': config}
        if region:
            client_kwargs['region_name'] = region
        if access_key_id and secret_access_key:
            client_kwargs['aws_access_key_id'] = access_key_id
            client_kwargs['aws_secret_access_key'] = secret_access_key

        self._client = boto3.client('kms', **client_kwargs)

        self._executor = ThreadPoolExecutor(max_workers=max_workers)

        # Populated by _validate_keys(): key ID -> SigningAlgorithms reported
        # by KMS for that key.
        self._key_signing_algorithms: Dict[str, List[str]] = {}

        # Validate keys on init
        self._validate_keys()

    def _validate_keys(self):
        """Validate that configured keys exist and are usable."""
        for key_id in self._key_ids:
            try:
                response = self._client.describe_key(KeyId=key_id)
                metadata = response['KeyMetadata']
                key_state = metadata['KeyState']
                algorithms = metadata.get('SigningAlgorithms') or []
                self._key_signing_algorithms[key_id] = list(algorithms)
                if algorithms and self._signing_algorithm not in algorithms:
                    raise ValueError(
                        f"KMS key '{key_id}' does not support the configured "
                        f"signing algorithm "
                        f"'{self._signing_algorithm}'; "
                        f"supported: {', '.join(algorithms)}"
                    )
                if key_state != 'Enabled':
                    logger.warning(
                        "KMS key %s is not enabled (state: %s)",
                        key_id,
                        key_state,
                    )
                else:
                    logger.info("KMS key %s validated successfully", key_id)
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                error_msg = e.response.get('Error', {}).get('Message', str(e))
                logger.error(
                    "Failed to validate KMS key %s: [%s] %s",
                    key_id, error_code, error_msg
                )
                raise ValueError(
                    f"Invalid KMS key '{key_id}': [{error_code}] {error_msg}"
                ) from e

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

    def resolve_signing_algorithm(
        self, keyid: str, digest_algo: str
    ) -> Tuple[str, str]:
        """
        Resolve a requested digest algorithm to a usable KMS pair.

        The configured signing algorithm fixes the scheme (RSASSA-PSS,
        RSASSA-PKCS1-v1_5, ECDSA); the caller's digest_algo selects the hash.
        Both must agree, because KMS validates the digest length against the
        hash named by SigningAlgorithm.

        Args:
            keyid: KMS key ID the signature will be made with
            digest_algo: Requested digest algorithm (SHA256/SHA384/SHA512)

        Returns:
            Tuple of (hashlib algorithm name, KMS SigningAlgorithm)

        Raises:
            ValueError: If the digest is unknown, or the resulting algorithm
                is not supported by this key.
        """
        try:
            hash_name, suffix = SUPPORTED_DIGESTS[digest_algo.upper()]
        except KeyError:
            raise ValueError(
                f"Unsupported digest algorithm: {digest_algo}. "
                f"Supported: {', '.join(sorted(SUPPORTED_DIGESTS))}"
            ) from None

        scheme = self._signing_algorithm.rsplit('_SHA_', 1)[0]
        signing_algorithm = f'{scheme}_{suffix}'

        supported = self._key_signing_algorithms.get(keyid)
        if supported and signing_algorithm not in supported:
            raise ValueError(
                f"KMS key '{keyid}' cannot sign a {digest_algo.upper()} "
                f"digest ({signing_algorithm} is not supported); "
                f"supported: {', '.join(supported)}"
            )

        return hash_name, signing_algorithm

    def _sign_digest(
        self,
        key_id: str,
        digest: bytes,
        signing_algorithm: Optional[str] = None,
    ) -> bytes:
        """
        Sign a digest using KMS.

        Args:
            key_id: KMS key ID
            digest: Hash digest to sign
            signing_algorithm: KMS SigningAlgorithm to use; defaults to the
                configured one

        Returns:
            Raw signature bytes
        """
        response = self._client.sign(
            KeyId=key_id,
            Message=digest,
            MessageType='DIGEST',
            SigningAlgorithm=signing_algorithm or self._signing_algorithm,
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
        raw_signature: bool = False,
    ) -> str:
        """
        Sign a file using AWS KMS.

        Args:
            keyid: KMS key ID to use for signing
            file: File to sign (FastAPI UploadFile)
            detach_sign: True for detached signature, False for cleartext
            digest_algo: Hash algorithm (SHA256, SHA384, SHA512)
            raw_signature: If True, return base64-encoded raw KMS signature

        Returns:
            ASCII-armored PGP signature or base64-encoded raw signature

        Raises:
            ValueError: If the key is unknown, or digest_algo is unsupported
                by this backend or by the key
            FileTooBigError: If the file exceeds max_upload_bytes
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
        file_hash = hash_content(content)

        logger.info(
            "Signing file %s (%d bytes) with KMS key %s (raw=%s)",
            filename,
            len(content),
            keyid,
            raw_signature,
        )

        # Resolve before doing any work: an unusable digest/algorithm pair is
        # a bad request, not a signing failure.
        hash_name, signing_algorithm = self.resolve_signing_algorithm(
            keyid, digest_algo
        )

        try:
            if raw_signature:
                digest = hashlib.new(hash_name, content).digest()

                # Sign with KMS in thread pool (boto3 is synchronous)
                loop = asyncio.get_event_loop()
                sig_bytes = await loop.run_in_executor(
                    self._executor,
                    self._sign_digest,
                    keyid,
                    digest,
                    signing_algorithm,
                )

                self._log_signing_event(filename, keyid, file_hash, True)
                return base64.b64encode(sig_bytes).decode('ascii')

            gpg_fingerprint = self.get_gpg_fingerprint(keyid)

            # Compute the PGP signature hash
            digest, _, _, creation_time, _ = compute_pgp_hash(
                content, digest_algo, detach_sign, gpg_fingerprint
            )

            # Sign with KMS in thread pool (boto3 is synchronous)
            loop = asyncio.get_event_loop()
            sig_bytes = await loop.run_in_executor(
                self._executor,
                self._sign_digest,
                keyid,
                digest,
                signing_algorithm,
            )

            # Wrap in PGP format
            pgp_signature = wrap_signature_as_pgp(
                sig_bytes,
                content,
                digest_algo,
                detach_sign,
                gpg_fingerprint,
                creation_time,
            )

            self._log_signing_event(filename, keyid, file_hash, True)
            return pgp_signature

        except ClientError as e:
            self._log_signing_event(filename, keyid, file_hash, False)
            logger.error("KMS signing failed: %s", e)
            raise RuntimeError(f"KMS signing failed: {e}") from e

    async def sign_batch(
        self,
        keyid: str,
        files: List[UploadFile],
        detach_sign: bool = True,
        digest_algo: str = 'SHA256',
        raw_signature: bool = False,
    ) -> List[Tuple[str, str]]:
        """
        Sign multiple files using AWS KMS.

        Args:
            keyid: KMS key ID to use for signing
            files: List of files to sign
            detach_sign: True for detached signatures
            digest_algo: Hash algorithm
            raw_signature: If True, return base64-encoded raw signatures

        Returns:
            List of (filename, signature) tuples
        """
        tasks = [
            self.sign(keyid, file, detach_sign, digest_algo, raw_signature)
            for file in files
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
