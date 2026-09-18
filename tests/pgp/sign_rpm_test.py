"""
Tests for PGP.sign_rpm, the glue between the /sign-rpm endpoint and the
rpmsign wrapper (PF-3304).

What matters here is the temp file lifecycle: the signed package is handed
back to the route as a path on disk, so a failure anywhere in the middle
must not leave it behind.
"""

import asyncio
import os
from types import SimpleNamespace

import pytest

from sign.config import settings
from sign.errors import FileTooBigError, NotAnRpmError, RpmSignError
from sign.pgp import pgp as pgp_module
from sign.pgp.pgp import PGP
from sign.rpm.rpm_sign import RPM_LEAD_MAGIC

KEYID = 'AAAA1111BBBB2222'
IDENTITY = {
    'name': 'bash',
    'nevra': 'bash-5.2.15-5.el9.x86_64',
    'arch': 'x86_64',
    'is_source': False,
}
SIGNATURE = 'RSA/SHA256, Key ID aaaa1111bbbb2222'


class FakeUploadFile:
    """Minimal stand-in for fastapi.UploadFile."""

    def __init__(self, filename, data=RPM_LEAD_MAGIC + b'payload'):
        self.filename = filename
        self._chunks = [data] if data else []
        self.file = SimpleNamespace(closed=False)
        self.file.close = lambda: setattr(self.file, 'closed', True)

    async def read(self, _size):
        if self._chunks:
            return self._chunks.pop(0)
        return b''


def _make_pgp(tmp_path):
    """Build a PGP instance without running its heavy __init__."""
    pgp = object.__new__(PGP)
    pgp.tmp_dir = str(tmp_path)
    pgp.max_upload_bytes = 1024
    pgp._PGP__gpg = SimpleNamespace(gpgbinary='/usr/bin/gpg2')
    pgp._PGP__pass_db = SimpleNamespace(get_password=lambda keyid: 'pw')
    pgp._PGP__syslog = SimpleNamespace(rpm_sign_log=lambda **kwargs: None)
    pgp._PGP__gpg_semaphore = None
    pgp._PGP__rpm_semaphore = None
    return pgp


@pytest.fixture
def stub_rpm(monkeypatch):
    """Stub out everything that shells out to rpm/rpmsign."""
    calls = {}

    def _install(sign_effect=None):
        def _sign(path, keyid, password, **kwargs):
            calls['sign'] = {
                'path': path, 'keyid': keyid,
                'password': password, 'kwargs': kwargs,
            }
            if sign_effect is not None:
                raise sign_effect
            return SIGNATURE

        monkeypatch.setattr(pgp_module, 'sign_rpm_package', _sign)
        monkeypatch.setattr(
            pgp_module, 'read_package_identity', lambda path, **kw: IDENTITY
        )
        return calls

    return _install


def _tmp_rpms(tmp_path):
    return sorted(p.name for p in tmp_path.iterdir())


def test_sign_rpm_returns_signed_package(tmp_path, stub_rpm):
    calls = stub_rpm()
    pgp = _make_pgp(tmp_path)
    upload = FakeUploadFile('bash-5.2.15-5.el9.x86_64.rpm')

    outcome = asyncio.run(
        pgp.sign_rpm(KEYID, upload, user_email='release-ci@example.com')
    )

    assert outcome.identity == IDENTITY
    assert outcome.signature == SIGNATURE
    assert os.path.exists(outcome.path)
    assert calls['sign']['keyid'] == KEYID
    assert calls['sign']['password'] == 'pw'
    assert upload.file.closed is True
    # the caller owns the file and removes it once it is on the wire
    assert _tmp_rpms(tmp_path) == [os.path.basename(outcome.path)]


def test_sign_rpm_hashes_before_and_after(tmp_path, monkeypatch, stub_rpm):
    """The audit trail needs to show the package actually changed."""
    def _sign(path, keyid, password, **kwargs):
        with open(path, 'ab') as fd:
            fd.write(b'signature')
        return SIGNATURE

    stub_rpm()
    monkeypatch.setattr(pgp_module, 'sign_rpm_package', _sign)
    pgp = _make_pgp(tmp_path)

    outcome = asyncio.run(pgp.sign_rpm(KEYID, FakeUploadFile('a.rpm')))

    assert outcome.hash_before != outcome.hash_after
    os.unlink(outcome.path)


def test_sign_rpm_passes_service_settings(tmp_path, stub_rpm, monkeypatch):
    calls = stub_rpm()
    monkeypatch.setattr(settings, 'rpm_sign_timeout', 42)
    monkeypatch.setattr(settings, 'rpmsign_binary', '/usr/bin/rpmsign')
    pgp = _make_pgp(tmp_path)

    outcome = asyncio.run(pgp.sign_rpm(KEYID, FakeUploadFile('a.rpm')))

    assert calls['sign']['kwargs']['timeout'] == 42
    assert calls['sign']['kwargs']['rpmsign_binary'] == '/usr/bin/rpmsign'
    assert calls['sign']['kwargs']['locks_dir_path'] == settings.gpg_locks_dir
    os.unlink(outcome.path)


def test_sign_rpm_removes_temp_file_when_signing_fails(tmp_path, stub_rpm):
    stub_rpm(sign_effect=RpmSignError('gpg-agent is not running'))
    pgp = _make_pgp(tmp_path)

    with pytest.raises(RpmSignError):
        asyncio.run(pgp.sign_rpm(KEYID, FakeUploadFile('a.rpm')))

    assert _tmp_rpms(tmp_path) == []


def test_sign_rpm_removes_temp_file_when_upload_is_too_big(
    tmp_path, stub_rpm, monkeypatch
):
    stub_rpm()
    monkeypatch.setattr(settings, 'max_rpm_upload_bytes', 4)
    pgp = _make_pgp(tmp_path)
    upload = FakeUploadFile('a.rpm', data=RPM_LEAD_MAGIC + b'x' * 100)

    with pytest.raises(FileTooBigError):
        asyncio.run(pgp.sign_rpm(KEYID, upload))

    assert _tmp_rpms(tmp_path) == []
    assert upload.file.closed is True


def test_sign_rpm_rejects_non_rpm_before_touching_the_key(
    tmp_path, stub_rpm
):
    calls = stub_rpm()
    pgp = _make_pgp(tmp_path)
    upload = FakeUploadFile('a.rpm', data=b'PK\x03\x04 a zip file')

    with pytest.raises(NotAnRpmError):
        asyncio.run(pgp.sign_rpm(KEYID, upload))

    assert 'sign' not in calls
    assert _tmp_rpms(tmp_path) == []
