"""
Tests for POST /sign and POST /sign-batch key handling (PF-3638).

A backend may know a key under several spellings (a KMS key by its KMS ID
or its GPG key ID); the routes resolve the requested key once, check grants
against it, and tell the caller which backend signed.
"""

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sign.api import routes

KMS_ID = '0e92079c-c172-4acf-a90d-92242e58cb59'
FINGERPRINT = 'FAD7859081D0738B7A828496D07BF2A08D50EB66'
GPG_KEYID = 'D07BF2A08D50EB66'
SIGNATURE = '-----BEGIN PGP SIGNATURE-----'


class FakeKMSBackend:
    """
    Resolves GPG_KEYID and FINGERPRINT (any case) to KMS_ID, like the KMS
    backend does.
    """

    name = 'kms'

    def __init__(self):
        self.calls = []

    def key_exists(self, keyid):
        return self.resolve_keyid(keyid) is not None

    def resolve_keyid(self, keyid):
        if keyid == KMS_ID:
            return KMS_ID
        return {FINGERPRINT: KMS_ID, GPG_KEYID: KMS_ID}.get(keyid.upper())

    def key_names(self, keyid):
        return [keyid, FINGERPRINT, GPG_KEYID]

    async def sign(self, keyid, file, **kwargs):
        self.calls.append(keyid)
        return SIGNATURE

    async def sign_batch(self, keyid, files, **kwargs):
        self.calls.append(keyid)
        return [(f.filename, SIGNATURE) for f in files]


@pytest.fixture
def grants(monkeypatch):
    """Key IDs the user is granted; empty means every key is allowed."""
    granted = set()

    def _can_sign(user, keyid):
        return not granted or keyid in granted

    monkeypatch.setattr(routes, 'user_can_sign_with', _can_sign)
    return granted


@pytest.fixture
def client(grants):
    user = SimpleNamespace(id=7, email='release-ci@example.com')
    backend = FakeKMSBackend()

    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[routes.get_current_user] = lambda: user
    app.dependency_overrides[routes.get_backend] = lambda: backend

    with TestClient(app) as test_client:
        test_client.backend = backend
        yield test_client


def _sign(client, keyid):
    return client.post(
        '/sign',
        params={'keyid': keyid},
        files={'file': ('a.txt', b'content', 'text/plain')},
    )


def _sign_batch(client, keyid):
    return client.post(
        '/sign-batch',
        params={'keyid': keyid},
        files=[
            ('files', ('a.txt', b'a', 'text/plain')),
            ('files', ('b.txt', b'b', 'text/plain')),
        ],
    )


@pytest.mark.parametrize('post', [_sign, _sign_batch])
@pytest.mark.parametrize('keyid', [KMS_ID, GPG_KEYID])
def test_either_keyid_signs_with_the_resolved_key(client, post, keyid):
    response = post(client, keyid)

    assert response.status_code == 200
    assert client.backend.calls == [KMS_ID]


@pytest.mark.parametrize('post', [_sign, _sign_batch])
def test_response_names_the_backend(client, post):
    response = post(client, GPG_KEYID)

    assert response.headers['x-sign-backend'] == 'kms'


def test_sign_returns_the_signature(client):
    response = _sign(client, GPG_KEYID)

    assert response.text == SIGNATURE


@pytest.mark.parametrize('post', [_sign, _sign_batch])
def test_unknown_key_is_rejected_by_name(client, post):
    response = post(client, 'DEADBEEFDEADBEEF')

    assert response.status_code == 400
    assert 'DEADBEEFDEADBEEF' in response.json()['detail']
    assert 'x-sign-backend' not in response.headers
    assert client.backend.calls == []


@pytest.mark.parametrize('granted', [KMS_ID, GPG_KEYID, FINGERPRINT])
@pytest.mark.parametrize(
    'requested', [KMS_ID, GPG_KEYID, GPG_KEYID.lower(), FINGERPRINT]
)
def test_grant_on_any_name_of_the_key_entitles_the_caller(
    client, grants, granted, requested
):
    """A grant names a key, not a spelling of it."""
    grants.add(granted)

    response = _sign(client, requested)

    assert response.status_code == 200
    assert client.backend.calls == [KMS_ID]


@pytest.mark.parametrize('post', [_sign, _sign_batch])
def test_caller_without_a_grant_is_refused(client, grants, post):
    grants.add('CCCC3333DDDD4444')

    response = post(client, GPG_KEYID.lower())

    assert response.status_code == 403
    assert GPG_KEYID.lower() in response.json()['detail']
    assert 'x-sign-backend' not in response.headers
    assert client.backend.calls == []
