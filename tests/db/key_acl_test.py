"""
Tests for per-user key entitlements and the signing audit trail (PF-3304).

The /sign-rpm endpoint is reachable by callers outside the build system, so
a caller must only be able to sign with the keys it was granted, and every
request that reaches a private key has to leave a row behind.
"""

import pytest

from sign.config import settings
from sign.db import helpers
from sign.db.helpers import (
    create_user,
    db_create,
    db_drop,
    delete_user,
    finish_sign_audit,
    grant_key,
    list_user_keys,
    revoke_key,
    start_sign_audit,
    user_can_sign_with,
)
from sign.db.models import SignAuditRecord, UserKey
from sign.errors import AuditWriteError, UserNotFoundError

KEYID = 'AAAA1111BBBB2222'
OTHER_KEYID = 'CCCC3333DDDD4444'


@pytest.fixture
def db():
    db_create()
    yield
    db_drop()


@pytest.fixture
def user(db):
    email = 'release-ci@example.com'
    create_user(email, 'secret')
    return helpers.get_user(email)


# --- entitlements -----------------------------------------------------------


def test_user_without_grants_may_use_any_key_by_default(user, monkeypatch):
    monkeypatch.setattr(settings, 'default_key_access', 'all')

    assert user_can_sign_with(user, KEYID) is True
    assert list_user_keys(user.email) == []


def test_user_without_grants_is_denied_when_default_is_none(
    user, monkeypatch
):
    monkeypatch.setattr(settings, 'default_key_access', 'none')

    assert user_can_sign_with(user, KEYID) is False


def test_granted_user_is_restricted_to_granted_keys(user, monkeypatch):
    # even with the permissive default, an explicit grant is a whitelist
    monkeypatch.setattr(settings, 'default_key_access', 'all')
    assert grant_key(user.email, KEYID) is True

    assert user_can_sign_with(user, KEYID) is True
    assert user_can_sign_with(user, OTHER_KEYID) is False
    assert list_user_keys(user.email) == [KEYID]


def test_grant_is_idempotent(user):
    assert grant_key(user.email, KEYID) is True
    assert grant_key(user.email, KEYID) is False
    assert list_user_keys(user.email) == [KEYID]


def test_revoking_the_last_grant_restores_the_default(user, monkeypatch):
    monkeypatch.setattr(settings, 'default_key_access', 'none')
    grant_key(user.email, KEYID)
    assert user_can_sign_with(user, KEYID) is True

    assert revoke_key(user.email, KEYID) is True

    assert list_user_keys(user.email) == []
    assert user_can_sign_with(user, KEYID) is False


def test_revoking_a_grant_that_does_not_exist(user):
    assert revoke_key(user.email, KEYID) is False


def test_grants_for_unknown_user(db):
    with pytest.raises(UserNotFoundError):
        grant_key('nobody@example.com', KEYID)
    with pytest.raises(UserNotFoundError):
        list_user_keys('nobody@example.com')


def test_deleting_a_user_drops_their_grants(user):
    grant_key(user.email, KEYID)

    delete_user(user.email)

    with helpers.get_session() as session:
        assert session.query(UserKey).filter(
            UserKey.user_id == user.id
        ).count() == 0


# --- audit trail ------------------------------------------------------------


def test_audit_record_is_opened_then_closed(user):
    record_id = start_sign_audit(
        operation='rpm-header',
        user_id=user.id,
        user_email=user.email,
        keyid=KEYID,
        filename='bash-5.2.15-5.el9.x86_64.rpm',
    )

    with helpers.get_session() as session:
        record = session.get(SignAuditRecord, record_id)
        assert record.status == 'started'
        assert record.user_email == user.email
        assert record.keyid == KEYID
        assert record.finished_at is None

    finish_sign_audit(
        record_id,
        'signed',
        package_nevra='bash-5.2.15-5.el9.x86_64',
        sha256_before='a' * 64,
        sha256_after='b' * 64,
        signature='RSA/SHA256, Key ID aaaa1111bbbb2222',
    )

    with helpers.get_session() as session:
        record = session.get(SignAuditRecord, record_id)
        assert record.status == 'signed'
        assert record.package_nevra == 'bash-5.2.15-5.el9.x86_64'
        assert record.sha256_before != record.sha256_after
        assert record.finished_at is not None


def test_audit_record_records_failures(user):
    record_id = start_sign_audit(
        operation='rpm-header',
        user_id=user.id,
        user_email=user.email,
        keyid=KEYID,
    )

    finish_sign_audit(record_id, 'failed', detail='gpg-agent is not running')

    with helpers.get_session() as session:
        record = session.get(SignAuditRecord, record_id)
        assert record.status == 'failed'
        assert 'gpg-agent' in record.detail


def test_start_sign_audit_reports_a_write_failure(user, monkeypatch):
    """A request that cannot be accounted for must not reach a key."""
    def _boom():
        raise RuntimeError('database is gone')

    monkeypatch.setattr(helpers, 'get_session', _boom)

    with pytest.raises(AuditWriteError):
        start_sign_audit(
            operation='rpm-header',
            user_id=user.id,
            user_email=user.email,
            keyid=KEYID,
        )


def test_finish_sign_audit_never_raises(user, monkeypatch):
    """
    The package is already signed by then; losing the update must not turn a
    successful signature into an error.
    """
    record_id = start_sign_audit(
        operation='rpm-header',
        user_id=user.id,
        user_email=user.email,
        keyid=KEYID,
    )

    def _boom():
        raise RuntimeError('database is gone')

    monkeypatch.setattr(helpers, 'get_session', _boom)

    finish_sign_audit(record_id, 'signed')
