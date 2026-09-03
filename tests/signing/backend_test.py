import asyncio
from unittest.mock import MagicMock

import pytest

from sign.signing.backend import GPGAdapter


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


def test_no_provider_returns_no_preloaded_passwords(monkeypatch):
    from sign.signing import backend

    monkeypatch.setattr(backend.settings, 'bitwarden_enabled', False)
    monkeypatch.setattr(backend.settings, 'gsm_enabled', False)

    assert backend._fetch_preloaded_passwords() is None


def test_gsm_provider_is_dispatched(monkeypatch):
    from sign.pgp import gsm
    from sign.signing import backend

    monkeypatch.setattr(backend.settings, 'bitwarden_enabled', False)
    monkeypatch.setattr(backend.settings, 'gsm_enabled', True)
    monkeypatch.setattr(backend.settings, 'pgp_keys', ['KEYID'])
    monkeypatch.setattr(backend.settings, 'gsm_project_id', 'proj')
    monkeypatch.setattr(backend.settings, 'gsm_secret_prefix', 'gpg-')
    monkeypatch.setattr(backend.settings, 'gsm_secret_version', 'latest')
    monkeypatch.setattr(backend.settings, 'gsm_credentials_file', None)

    fetcher = MagicMock(return_value={'KEYID': 'passphrase'})
    monkeypatch.setattr(gsm, 'fetch_passphrases', fetcher)

    assert backend._fetch_preloaded_passwords() == {'KEYID': 'passphrase'}
    fetcher.assert_called_once_with(
        keyids=['KEYID'],
        project_id='proj',
        secret_prefix='gpg-',
        secret_version='latest',
        credentials_file=None,
    )


def test_two_providers_fail_backend_initialization(monkeypatch):
    from sign.signing import backend

    monkeypatch.setattr(backend.settings, 'bitwarden_enabled', True)
    monkeypatch.setattr(backend.settings, 'gsm_enabled', True)

    with pytest.raises(ValueError, match="Only one GPG passphrase provider"):
        backend._fetch_preloaded_passwords()
