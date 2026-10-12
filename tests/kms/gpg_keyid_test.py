"""
Tests for addressing KMS keys by their GPG key ID or fingerprint (PF-3638).

Callers know a key by its GPG key ID, as on the GPG backend; the KMS backend
resolves that to the KMS key it is configured for.
"""

import asyncio
from unittest.mock import patch

import boto3
import pytest

from tests.kms.conftest import RSA_ALGORITHMS, FakeKMSClient

KMS_ID = '0e92079c-c172-4acf-a90d-92242e58cb59'
FINGERPRINT = 'FAD7859081D0738B7A828496D07BF2A08D50EB66'
GPG_KEYID = 'D07BF2A08D50EB66'
OTHER_KMS_ID = 'c0eef9a8-e2aa-4003-a873-599df58d41e9'
OTHER_FINGERPRINT = 'AD13941189BF2258AA3072C97BF120293948A27B'
OTHER_GPG_KEYID = '7BF120293948A27B'


def _make_kms(fingerprints):
    client = FakeKMSClient(RSA_ALGORITHMS)
    with patch.object(boto3, 'client', return_value=client):
        from sign.kms.kms import KMS

        backend = KMS(
            key_ids=list(fingerprints),
            gpg_fingerprints=fingerprints,
        )
    return backend, client


@pytest.fixture
def kms():
    return _make_kms({KMS_ID: FINGERPRINT, OTHER_KMS_ID: OTHER_FINGERPRINT})


@pytest.mark.parametrize(
    'keyid,expected',
    [
        (KMS_ID, KMS_ID),
        (GPG_KEYID, KMS_ID),
        (GPG_KEYID.lower(), KMS_ID),
        (FINGERPRINT, KMS_ID),
        (FINGERPRINT.lower(), KMS_ID),
        (OTHER_GPG_KEYID, OTHER_KMS_ID),
    ],
)
def test_key_resolves_by_any_spelling(kms, keyid, expected):
    backend, _ = kms

    assert backend.resolve_keyid(keyid) == expected
    assert backend.key_exists(keyid)


@pytest.mark.parametrize(
    'keyid',
    [
        'DEADBEEFDEADBEEF',
        # the short (8 hex) key ID is too collision-prone to accept
        GPG_KEYID[-8:],
        '',
    ],
)
def test_unknown_key_does_not_resolve(kms, keyid):
    backend, _ = kms

    assert backend.resolve_keyid(keyid) is None
    assert not backend.key_exists(keyid)


def test_signing_by_gpg_keyid_uses_the_kms_key(kms, upload_file):
    backend, client = kms

    asyncio.run(backend.sign(GPG_KEYID, upload_file(), raw_signature=True))

    assert client.last_sign_call['KeyId'] == KMS_ID


def test_signature_by_gpg_keyid_names_the_gpg_issuer(kms, upload_file):
    import pgpy

    backend, _ = kms

    armored = asyncio.run(backend.sign(GPG_KEYID, upload_file()))

    assert pgpy.PGPSignature.from_blob(armored).signer == GPG_KEYID


def test_batch_by_gpg_keyid_uses_the_kms_key(kms, upload_file):
    backend, client = kms

    asyncio.run(
        backend.sign_batch(
            GPG_KEYID,
            [upload_file(filename='a.rpm'), upload_file(filename='b.rpm')],
            raw_signature=True,
        )
    )

    assert [call['KeyId'] for call in client.sign_calls] == [KMS_ID, KMS_ID]


def test_unknown_gpg_keyid_is_rejected_by_name(kms, upload_file):
    backend, client = kms

    with pytest.raises(ValueError, match='DEADBEEFDEADBEEF'):
        asyncio.run(
            backend.sign('DEADBEEFDEADBEEF', upload_file(), raw_signature=True)
        )

    assert client.sign_calls == []


def test_listed_keys_stay_kms_ids(kms):
    backend, _ = kms

    assert backend.list_keys() == [KMS_ID, OTHER_KMS_ID]


def test_key_names_lists_every_id_of_the_key(kms):
    backend, _ = kms

    assert backend.key_names(KMS_ID) == [KMS_ID, GPG_KEYID, FINGERPRINT]


def test_two_kms_keys_with_one_gpg_key_fail_at_init():
    """An ambiguous GPG key ID is a config error, not a coin toss."""
    with pytest.raises(ValueError, match=GPG_KEYID):
        _make_kms({KMS_ID: FINGERPRINT, OTHER_KMS_ID: FINGERPRINT})


@pytest.mark.parametrize(
    'fingerprint',
    [
        GPG_KEYID,  # a key ID where a fingerprint belongs
        FINGERPRINT[:-1],
        '0x' + FINGERPRINT,
        FINGERPRINT[:-1] + 'G',
    ],
)
def test_malformed_fingerprint_fails_at_init(fingerprint):
    with pytest.raises(ValueError, match='40 hex characters'):
        _make_kms({KMS_ID: fingerprint})


def test_fingerprint_in_config_is_normalized():
    """gpg prints fingerprints in spaced groups; that form is accepted."""
    spaced = ' '.join(
        FINGERPRINT[i : i + 4] for i in range(0, len(FINGERPRINT), 4)
    ).lower()
    backend, _ = _make_kms({KMS_ID: spaced})

    assert backend.resolve_keyid(GPG_KEYID) == KMS_ID
