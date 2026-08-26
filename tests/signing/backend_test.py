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
