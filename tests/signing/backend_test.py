import asyncio
from unittest.mock import MagicMock

import pytest

import sign.kms
from sign.config import settings
from sign.signing import backend as backend_module
from sign.signing.backend import GPGAdapter, KMSAdapter


def _awaitable(value):
    async def _coro(*args, **kwargs):
        return value

    return _coro


@pytest.fixture
def gpg_adapter():
    pgp = MagicMock()
    pgp.sign = _awaitable('-----BEGIN PGP SIGNATURE-----')
    pgp.sign_batch = _awaitable([('a.rpm', 'sig')])
    return GPGAdapter(pgp)


def test_gpg_backend_rejects_raw_signature(gpg_adapter):
    with pytest.raises(ValueError, match='not supported with GPG backend'):
        asyncio.run(gpg_adapter.sign('KEYID', MagicMock(), raw_signature=True))


def test_gpg_backend_batch_rejects_raw_signature(gpg_adapter):
    with pytest.raises(ValueError, match='not supported with GPG backend'):
        asyncio.run(
            gpg_adapter.sign_batch('KEYID', [MagicMock()], raw_signature=True)
        )


def test_gpg_backend_signs_normally(gpg_adapter):
    result = asyncio.run(gpg_adapter.sign('KEYID', MagicMock()))

    assert result.startswith('-----BEGIN PGP SIGNATURE-----')


def test_kms_backend_delegates_rpm_signing():
    kms = MagicMock()
    kms.supports_rpm_signing.return_value = True
    kms.sign_rpm = _awaitable('outcome')
    adapter = KMSAdapter(kms)

    assert adapter.supports_rpm_signing() is True
    assert (
        asyncio.run(adapter.sign_rpm('KEY', MagicMock(), 'dev@example.com'))
        == 'outcome'
    )


def test_kms_backend_reports_unsupported_algorithm():
    kms = MagicMock()
    kms.supports_rpm_signing.return_value = False

    assert KMSAdapter(kms).supports_rpm_signing() is False


def test_kms_backend_gets_the_rpm_settings(monkeypatch):
    """Every RPM setting reaches the KMS backend, or it silently defaults."""
    built = {}

    def _kms(**kwargs):
        built.update(kwargs)
        return MagicMock()

    monkeypatch.setattr(backend_module, '_backend_instance', None)
    monkeypatch.setattr(sign.kms, 'KMS', _kms)
    for name, value in {
        'signing_backend': 'kms',
        'kms_keys': [{'kms_id': 'alias/rpm', 'gpg_fingerprint': 'A' * 40}],
        'kms_rpm_signer_binary': '/opt/sign-file-rpm-signer',
        'max_rpm_upload_bytes': 1234,
        'rpm_sign_max_concurrency': 3,
        'rpm_sign_timeout': 45,
        'rpmsign_binary': '/usr/bin/rpmsign',
        'rpm_binary': '/usr/bin/rpm',
    }.items():
        monkeypatch.setattr(settings, name, value)

    backend_module.get_signing_backend()

    assert built['rpm_signer_binary'] == '/opt/sign-file-rpm-signer'
    assert built['rpm_upload_limit'] == 1234
    assert built['rpm_sign_max_concurrency'] == 3
    assert built['rpm_sign_timeout'] == 45
    assert built['rpmsign_binary'] == '/usr/bin/rpmsign'
    assert built['rpm_binary'] == '/usr/bin/rpm'
