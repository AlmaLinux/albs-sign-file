import asyncio
import base64
import hashlib
from unittest.mock import patch

import boto3
import pytest

from tests.kms.conftest import (
    FINGERPRINT,
    KEY_ID,
    P256_ALGORITHMS,
    SIGNATURE,
    FakeKMSClient,
)

CONTENT = b'albs sign file\n'


def test_raw_signature_is_base64_of_kms_output(make_kms, upload_file):
    backend, _ = make_kms()

    result = asyncio.run(
        backend.sign(KEY_ID, upload_file(CONTENT), raw_signature=True)
    )

    assert base64.b64decode(result) == SIGNATURE


def test_raw_signature_sends_matching_digest(make_kms, upload_file):
    backend, client = make_kms()

    asyncio.run(backend.sign(KEY_ID, upload_file(CONTENT), raw_signature=True))

    call = client.last_sign_call
    assert call['MessageType'] == 'DIGEST'
    assert call['Message'] == hashlib.sha256(CONTENT).digest()
    assert call['SigningAlgorithm'] == 'RSASSA_PKCS1_V1_5_SHA_256'


@pytest.mark.parametrize(
    'digest_algo,hash_func,expected_algorithm',
    [
        ('SHA256', hashlib.sha256, 'RSASSA_PKCS1_V1_5_SHA_256'),
        ('SHA384', hashlib.sha384, 'RSASSA_PKCS1_V1_5_SHA_384'),
        ('SHA512', hashlib.sha512, 'RSASSA_PKCS1_V1_5_SHA_512'),
        ('sha512', hashlib.sha512, 'RSASSA_PKCS1_V1_5_SHA_512'),
    ],
)
def test_signing_algorithm_follows_digest_algo(
    make_kms, upload_file, digest_algo, hash_func, expected_algorithm
):
    """KMS rejects a digest whose length disagrees with SigningAlgorithm."""
    backend, client = make_kms()

    asyncio.run(
        backend.sign(
            KEY_ID,
            upload_file(CONTENT),
            digest_algo=digest_algo,
            raw_signature=True,
        )
    )

    call = client.last_sign_call
    assert call['SigningAlgorithm'] == expected_algorithm
    assert call['Message'] == hash_func(CONTENT).digest()
    assert len(call['Message']) == hash_func().digest_size


def test_pgp_path_also_follows_digest_algo(make_kms, upload_file):
    backend, client = make_kms()

    asyncio.run(
        backend.sign(KEY_ID, upload_file(CONTENT), digest_algo='SHA512')
    )

    call = client.last_sign_call
    assert call['SigningAlgorithm'] == 'RSASSA_PKCS1_V1_5_SHA_512'
    assert len(call['Message']) == hashlib.sha512().digest_size


@pytest.mark.parametrize('digest_algo', ['SHA1', 'MD5', 'SHA-256', ''])
def test_unknown_digest_algo_is_rejected(make_kms, upload_file, digest_algo):
    """An unknown digest must fail loudly, not fall back to SHA-256."""
    backend, client = make_kms()

    with pytest.raises(ValueError, match='Unsupported digest algorithm'):
        asyncio.run(
            backend.sign(
                KEY_ID,
                upload_file(CONTENT),
                digest_algo=digest_algo,
                raw_signature=True,
            )
        )

    assert client.sign_calls == []


def test_digest_unsupported_by_key_is_rejected(make_kms, upload_file):
    """A P-256 key can only sign SHA-256; asking for SHA-512 is a 400."""
    backend, client = make_kms(
        signing_algorithms=P256_ALGORITHMS,
        signing_algorithm='ECDSA_SHA_256',
    )

    with pytest.raises(ValueError, match='cannot sign a SHA512 digest'):
        asyncio.run(
            backend.sign(
                KEY_ID,
                upload_file(CONTENT),
                digest_algo='SHA512',
                raw_signature=True,
            )
        )

    assert client.sign_calls == []


def test_p256_key_signs_sha256(make_kms, upload_file):
    backend, client = make_kms(
        signing_algorithms=P256_ALGORITHMS,
        signing_algorithm='ECDSA_SHA_256',
    )

    asyncio.run(backend.sign(KEY_ID, upload_file(CONTENT), raw_signature=True))

    assert client.last_sign_call['SigningAlgorithm'] == 'ECDSA_SHA_256'


def test_configured_algorithm_unsupported_by_key_fails_at_init():
    """Misconfiguration is caught on startup, not on the first signature."""
    client = FakeKMSClient(P256_ALGORITHMS)

    with patch.object(boto3, 'client', return_value=client):
        from sign.kms.kms import KMS

        with pytest.raises(ValueError, match='does not support'):
            KMS(
                key_ids=[KEY_ID],
                gpg_fingerprints={KEY_ID: FINGERPRINT},
                signing_algorithm='RSASSA_PKCS1_V1_5_SHA_256',
            )


def test_sign_batch_returns_raw_signatures(make_kms, upload_file):
    backend, client = make_kms()

    results = asyncio.run(
        backend.sign_batch(
            KEY_ID,
            [upload_file(CONTENT, 'a.rpm'), upload_file(b'other', 'b.rpm')],
            raw_signature=True,
        )
    )

    assert [name for name, _ in results] == ['a.rpm', 'b.rpm']
    assert all(base64.b64decode(sig) == SIGNATURE for _, sig in results)
    assert len(client.sign_calls) == 2


def test_pgp_path_still_returns_armored_signature(make_kms, upload_file):
    backend, _ = make_kms()

    result = asyncio.run(backend.sign(KEY_ID, upload_file(CONTENT)))

    assert result.startswith('-----BEGIN PGP SIGNATURE-----')


def test_unknown_key_is_rejected(make_kms, upload_file):
    backend, _ = make_kms()

    with pytest.raises(ValueError, match='Key not found'):
        asyncio.run(
            backend.sign('nope', upload_file(CONTENT), raw_signature=True)
        )
