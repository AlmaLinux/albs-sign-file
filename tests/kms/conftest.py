import io
from unittest.mock import patch

import boto3
import pytest
from fastapi import UploadFile

KEY_ID = 'test-key-1'
FINGERPRINT = 'A' * 40
RSA_ALGORITHMS = [
    'RSASSA_PKCS1_V1_5_SHA_256',
    'RSASSA_PKCS1_V1_5_SHA_384',
    'RSASSA_PKCS1_V1_5_SHA_512',
]
P256_ALGORITHMS = ['ECDSA_SHA_256']
SIGNATURE = b'\xde\xad\xbe\xef' * 8


class FakeKMSClient:
    """Minimal stand-in for the boto3 KMS client.

    Records the arguments of the last sign() call so tests can assert on
    what would actually be sent to AWS.
    """

    def __init__(self, signing_algorithms, key_state='Enabled'):
        self.signing_algorithms = signing_algorithms
        self.key_state = key_state
        self.sign_calls = []

    def describe_key(self, KeyId):
        return {
            'KeyMetadata': {
                'KeyState': self.key_state,
                'SigningAlgorithms': self.signing_algorithms,
            }
        }

    def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
        self.sign_calls.append({
            'KeyId': KeyId,
            'Message': Message,
            'MessageType': MessageType,
            'SigningAlgorithm': SigningAlgorithm,
        })
        return {'Signature': SIGNATURE}

    @property
    def last_sign_call(self):
        return self.sign_calls[-1]


@pytest.fixture
def make_kms():
    """Build a KMS backend wired to a FakeKMSClient."""

    def _make(signing_algorithms=None, **kwargs):
        client = FakeKMSClient(
            signing_algorithms
            if signing_algorithms is not None
            else RSA_ALGORITHMS
        )
        with patch.object(boto3, 'client', return_value=client):
            from sign.kms.kms import KMS

            backend = KMS(
                key_ids=[KEY_ID],
                gpg_fingerprints={KEY_ID: FINGERPRINT},
                **kwargs,
            )
        return backend, client

    return _make


@pytest.fixture
def upload_file():
    """Factory for throwaway UploadFile objects."""

    def _make(content=b'albs sign file\n', filename='package.rpm'):
        return UploadFile(filename=filename, file=io.BytesIO(content))

    return _make
