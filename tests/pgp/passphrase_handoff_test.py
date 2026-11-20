import os
from unittest import mock

import pytest

from sign.pgp.errors import ConfigurationError
from sign.pgp.passphrase_handoff import (
    PASSPHRASES_ENV_VAR,
    publish_passphrases,
    take_passphrases,
)
from sign.pgp.pgp_password_db import PGPPasswordDB

KEYID = 'AAAABBBBCCCCDDDD'


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv(PASSPHRASES_ENV_VAR, raising=False)


def _gpg():
    gpg = mock.Mock()
    gpg.list_keys.return_value = [
        {'keyid': KEYID, 'fingerprint': 'F' * 40, 'subkeys': []},
    ]
    return gpg


def test_take_returns_published_passphrases():
    publish_passphrases({KEYID: 's3cret'})
    assert take_passphrases() == {KEYID: 's3cret'}


def test_take_removes_the_variable():
    publish_passphrases({KEYID: 's3cret'})
    take_passphrases()
    assert PASSPHRASES_ENV_VAR not in os.environ
    assert take_passphrases() is None


def test_take_without_handoff_returns_none():
    assert take_passphrases() is None


def test_take_rejects_non_object(monkeypatch):
    monkeypatch.setenv(PASSPHRASES_ENV_VAR, '["nope"]')
    with pytest.raises(ValueError):
        take_passphrases()


def test_handed_off_passwords_skip_prompt_and_verification():
    db = PGPPasswordDB(
        _gpg(),
        [KEYID],
        preloaded_passwords={KEYID: 's3cret'},
        verify_preloaded=False,
    )
    with mock.patch(
        'sign.pgp.pgp_password_db.verify_pgp_key_password'
    ) as verify, mock.patch('getpass.getpass') as prompt:
        db.ask_for_passwords()
    verify.assert_not_called()
    prompt.assert_not_called()
    assert db.get_password(KEYID) == 's3cret'


def test_preloaded_passwords_are_verified_by_default():
    db = PGPPasswordDB(
        _gpg(),
        [KEYID],
        preloaded_passwords={KEYID: 'wrong'},
    )
    with mock.patch(
        'sign.pgp.pgp_password_db.verify_pgp_key_password',
        return_value=False,
    ):
        with pytest.raises(ConfigurationError):
            db.ask_for_passwords()


def test_interactive_prompt_still_used_without_handoff():
    db = PGPPasswordDB(_gpg(), [KEYID])
    with mock.patch(
        'sign.pgp.pgp_password_db.verify_pgp_key_password',
        return_value=True,
    ), mock.patch(
        'sign.pgp.pgp_password_db.getpass.getpass', return_value='typed'
    ) as prompt:
        db.ask_for_passwords()
    prompt.assert_called_once()
    assert db.get_passwords() == {KEYID: 'typed'}
