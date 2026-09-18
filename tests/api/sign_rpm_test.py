"""
Tests for POST /sign-rpm and GET /keys (PF-3304).

These cover what an external caller sees: which requests are refused and
with what status, that every request that reaches a key is accounted for
first, and that the signed package comes back as a file.
"""

import os
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sign.api import routes
from sign.config import settings
from sign.errors import (
    AuditWriteError,
    FileTooBigError,
    NotAnRpmError,
    RpmSignError,
)
from sign.rpm.rpm_sign import RPM_LEAD_MAGIC, RpmSignOutcome

KEYID = 'AAAA1111BBBB2222'
OTHER_KEYID = 'CCCC3333DDDD4444'
NEVRA = 'bash-5.2.15-5.el9.x86_64'
SIGNATURE = 'RSA/SHA256, Key ID aaaa1111bbbb2222'
SIGNED_CONTENT = RPM_LEAD_MAGIC + b'signed payload'
UPLOAD = RPM_LEAD_MAGIC + b'payload'


class FakeBackend:
    def __init__(self, tmp_path, keys=(KEYID, OTHER_KEYID), rpm=True):
        self._tmp_path = tmp_path
        self._keys = list(keys)
        self._rpm = rpm
        self.calls = []
        self.effect = None

    def key_exists(self, keyid):
        return keyid in self._keys

    def list_keys(self):
        return list(self._keys)

    def supports_rpm_signing(self):
        return self._rpm

    async def sign_rpm(self, keyid, file, user_email=''):
        self.calls.append((keyid, file.filename, user_email))
        if self.effect is not None:
            raise self.effect
        path = self._tmp_path / 'signed.rpm'
        path.write_bytes(SIGNED_CONTENT)
        return RpmSignOutcome(
            path=str(path),
            identity={'name': 'bash', 'nevra': NEVRA,
                      'arch': 'x86_64', 'is_source': False},
            hash_before='a' * 64,
            hash_after='b' * 64,
            signature=SIGNATURE,
        )


@pytest.fixture
def audit(monkeypatch):
    """Capture the audit calls the route makes."""
    records = {'started': [], 'finished': [], 'fail_start': False}

    def _start(**kwargs):
        if records['fail_start']:
            raise AuditWriteError('database is gone')
        records['started'].append(kwargs)
        return len(records['started'])

    def _finish(record_id, status, **kwargs):
        records['finished'].append(
            {'id': record_id, 'status': status, **kwargs}
        )

    monkeypatch.setattr(routes, 'start_sign_audit', _start)
    monkeypatch.setattr(routes, 'finish_sign_audit', _finish)
    return records


@pytest.fixture
def client(tmp_path, monkeypatch, audit):
    """A TestClient with auth and the signing backend stubbed out."""
    user = SimpleNamespace(id=7, email='release-ci@example.com')
    backend = FakeBackend(tmp_path)
    monkeypatch.setattr(routes, 'user_can_sign_with', lambda u, k: True)
    monkeypatch.setattr(routes, 'list_user_keys', lambda email: [])

    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[routes.get_current_user] = lambda: user
    app.dependency_overrides[routes.get_backend] = lambda: backend

    with TestClient(app) as test_client:
        test_client.backend = backend
        test_client.user = user
        yield test_client


def _post(client, keyid=KEYID, filename='bash-5.2.15-5.el9.x86_64.rpm',
          content=UPLOAD):
    return client.post(
        '/sign-rpm',
        params={'keyid': keyid},
        files={'file': (filename, content, 'application/x-rpm')},
    )


# --- happy path -------------------------------------------------------------


def test_sign_rpm_returns_the_signed_package(client, audit):
    response = _post(client)

    assert response.status_code == 200
    assert response.content == SIGNED_CONTENT
    assert response.headers['content-type'] == 'application/x-rpm'
    assert 'bash-5.2.15-5.el9.x86_64.rpm' in (
        response.headers['content-disposition']
    )
    assert client.backend.calls == [
        (KEYID, 'bash-5.2.15-5.el9.x86_64.rpm', 'release-ci@example.com')
    ]


def test_signed_package_is_not_left_on_disk(client, tmp_path):
    _post(client)

    # TestClient runs the response's background task
    assert not (tmp_path / 'signed.rpm').exists()


def test_request_is_audited_before_and_after_signing(client, audit):
    _post(client)

    assert audit['started'] == [{
        'operation': 'rpm-header',
        'user_id': 7,
        'user_email': 'release-ci@example.com',
        'keyid': KEYID,
        'filename': 'bash-5.2.15-5.el9.x86_64.rpm',
    }]
    finished = audit['finished'][0]
    assert finished['status'] == 'signed'
    assert finished['package_nevra'] == NEVRA
    assert finished['signature'] == SIGNATURE
    assert finished['sha256_before'] != finished['sha256_after']


def test_returned_filename_is_a_basename(client):
    response = _post(client, filename='../../../etc/cron.d/payload.rpm')

    assert 'filename="payload.rpm"' in (
        response.headers['content-disposition']
    )


# --- authorization ----------------------------------------------------------


def test_caller_cannot_sign_with_a_key_it_is_not_entitled_to(
    client, monkeypatch, audit
):
    monkeypatch.setattr(
        routes, 'user_can_sign_with', lambda user, keyid: keyid == KEYID
    )

    response = _post(client, keyid=OTHER_KEYID)

    assert response.status_code == 403
    assert OTHER_KEYID in response.json()['detail']
    # nothing reached the key, and nothing was recorded as signed
    assert client.backend.calls == []
    assert audit['started'] == []


def test_unknown_key_is_rejected(client):
    response = _post(client, keyid='DEADBEEFDEADBEEF')

    assert response.status_code == 400
    assert 'does not exist' in response.json()['detail']


def test_request_is_refused_when_it_cannot_be_audited(client, audit):
    audit['fail_start'] = True

    response = _post(client)

    assert response.status_code == 503
    assert response.headers['Retry-After'] == '30'
    assert client.backend.calls == []


# --- availability -----------------------------------------------------------


def test_disabled_endpoint_reports_unavailable(client, monkeypatch):
    monkeypatch.setattr(settings, 'rpm_sign_enabled', False)

    response = _post(client)

    assert response.status_code == 503
    assert client.backend.calls == []


def test_backend_without_rpm_support_reports_not_implemented(
    client, monkeypatch
):
    monkeypatch.setattr(client.backend, 'supports_rpm_signing', lambda: False)

    response = _post(client)

    assert response.status_code == 501
    assert client.backend.calls == []


# --- failures ---------------------------------------------------------------


def test_oversized_package_is_rejected(client, audit):
    client.backend.effect = FileTooBigError()

    response = _post(client)

    assert response.status_code == 413
    assert audit['finished'][0]['status'] == 'rejected'


def test_non_rpm_upload_is_rejected(client, audit):
    client.backend.effect = NotAnRpmError('file is not an RPM package')

    response = _post(client)

    assert response.status_code == 400
    assert 'not a valid RPM package' in response.json()['detail']
    assert audit['finished'][0]['status'] == 'rejected'


def test_signing_failure_asks_the_caller_to_retry(client, audit):
    client.backend.effect = RpmSignError('gpg-agent is not running')

    response = _post(client)

    assert response.status_code == 503
    assert response.headers['Retry-After'] == '30'
    assert audit['finished'][0]['status'] == 'failed'
    # the reason stays in the audit trail and the log, not in the response
    assert 'gpg-agent' not in response.json()['detail']
    assert 'gpg-agent' in audit['finished'][0]['detail']


# --- key discovery ----------------------------------------------------------


def test_keys_lists_every_key_when_access_is_unrestricted(
    client, monkeypatch
):
    monkeypatch.setattr(settings, 'default_key_access', 'all')

    body = client.get('/keys').json()

    assert body['keys'] == sorted([KEYID, OTHER_KEYID])
    assert body['restricted'] is False
    assert body['rpm_signing_available'] is True


def test_keys_lists_only_granted_keys(client, monkeypatch):
    monkeypatch.setattr(routes, 'list_user_keys', lambda email: [KEYID])

    body = client.get('/keys').json()

    assert body['keys'] == [KEYID]
    assert body['restricted'] is True


def test_keys_is_empty_when_the_default_denies_everything(
    client, monkeypatch
):
    monkeypatch.setattr(settings, 'default_key_access', 'none')

    body = client.get('/keys').json()

    assert body['keys'] == []
    assert body['restricted'] is True
