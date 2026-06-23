"""
Regression tests for PF-673: /sign-batch failing with
'ValueError: filedescriptor out of range in select()'.

These cover the three fixes:
  1. every pexpect.run() call passes use_poll=True (poll() has no FD_SETSIZE
     limit, so signing never crashes on a high-numbered fd);
  2. the gpg '<name>.asc' file and the UploadFile spooled fd are cleaned up on
     every path, including signing failure / oversized upload (no fd leak);
  3. sign_batch signs files one at a time, so it does not open one temp file +
     PTY per file up front (fd usage stays flat regardless of batch size).
"""
import asyncio
import os
from types import SimpleNamespace
from unittest import mock

import pytest

from sign.errors import FileTooBigError
from sign.pgp.pgp import PGP


class _FakeUploadFile:
    """Minimal stand-in for fastapi.UploadFile."""

    def __init__(self, filename, data=b'data'):
        self.filename = filename
        self._chunks = [data] if data else []
        # .file mimics the SpooledTemporaryFile; we only assert it is closed.
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
    pgp._PGP__syslog = SimpleNamespace(sign_log=lambda *a, **k: None)
    pgp._PGP__gpg_semaphore = None
    return pgp


def _write_asc_then_ok(tmp_path):
    """
    Fake pexpect.run that emulates gpg --detach-sign --armor: it creates a
    '<name>.asc' next to the temp file and returns success.
    """
    def _run(command, **kwargs):
        # the temp file path is the last token of the command
        target = command.split()[-1]
        with open(f'{target}.asc', 'w') as fl:
            fl.write('-----BEGIN PGP SIGNATURE-----\n')
        return (b'', 0)
    return _run


def _write_asc_then_fail(tmp_path):
    """gpg that writes a partial .asc but exits non-zero (signing failure)."""
    def _run(command, **kwargs):
        target = command.split()[-1]
        with open(f'{target}.asc', 'w') as fl:
            fl.write('partial')
        return (b'boom', 2)
    return _run


# --- Fix 1: use_poll=True ---------------------------------------------------

def test_sign_passes_use_poll(tmp_path):
    pgp = _make_pgp(tmp_path)
    seen = {}

    def _run(command, **kwargs):
        seen.update(kwargs)
        target = command.split()[-1]
        with open(f'{target}.asc', 'w') as fl:
            fl.write('sig')
        return (b'', 0)

    with mock.patch('sign.pgp.pgp.pexpect.run', side_effect=_run):
        asyncio.run(pgp.sign('KEY', _FakeUploadFile('a.rpm')))

    assert seen.get('use_poll') is True


def test_sign_batch_passes_use_poll(tmp_path):
    pgp = _make_pgp(tmp_path)
    seen = {}

    def _run(command, **kwargs):
        seen.update(kwargs)
        target = command.split()[-1]
        with open(f'{target}.asc', 'w') as fl:
            fl.write('sig')
        return (b'', 0)

    with mock.patch('sign.pgp.pgp.pexpect.run', side_effect=_run):
        asyncio.run(pgp.sign_batch('KEY', [_FakeUploadFile('a.rpm')]))

    assert seen.get('use_poll') is True


# --- Fix 3: no leak of .asc / UploadFile on any path ------------------------

def test_sign_removes_asc_on_success(tmp_path):
    pgp = _make_pgp(tmp_path)
    upload = _FakeUploadFile('a.rpm')
    with mock.patch('sign.pgp.pgp.pexpect.run',
                    side_effect=_write_asc_then_ok(tmp_path)):
        asyncio.run(pgp.sign('KEY', upload))
    assert os.listdir(tmp_path) == []        # no .asc, no temp file left
    assert upload.file.closed is True


def test_sign_removes_asc_on_gpg_failure(tmp_path):
    pgp = _make_pgp(tmp_path)
    upload = _FakeUploadFile('a.rpm')
    with mock.patch('sign.pgp.pgp.pexpect.run',
                    side_effect=_write_asc_then_fail(tmp_path)):
        with pytest.raises(Exception):
            asyncio.run(pgp.sign('KEY', upload))
    # the partial .asc gpg left behind must be cleaned up despite the failure
    assert os.listdir(tmp_path) == []
    assert upload.file.closed is True


def test_sign_closes_upload_on_too_big(tmp_path):
    pgp = _make_pgp(tmp_path)
    pgp.max_upload_bytes = 2
    upload = _FakeUploadFile('a.rpm', data=b'way too large')
    with mock.patch('sign.pgp.pgp.pexpect.run') as run:
        with pytest.raises(FileTooBigError):
            asyncio.run(pgp.sign('KEY', upload))
    run.assert_not_called()                  # bailed before signing
    assert upload.file.closed is True        # but still released the fd
    assert os.listdir(tmp_path) == []


def test_sign_batch_removes_asc_on_failure(tmp_path):
    pgp = _make_pgp(tmp_path)
    with mock.patch('sign.pgp.pgp.pexpect.run',
                    side_effect=_write_asc_then_fail(tmp_path)):
        with pytest.raises(Exception):
            asyncio.run(pgp.sign_batch('KEY', [_FakeUploadFile('a.rpm')]))
    assert os.listdir(tmp_path) == []


# --- Fix 2: sequential signing, fd usage stays flat -------------------------

def test_sign_batch_signs_sequentially(tmp_path):
    """
    At no point should more than one temp file exist in tmp_dir at once,
    proving files are not all opened up front.
    """
    pgp = _make_pgp(tmp_path)
    max_concurrent = {'n': 0}

    def _run(command, **kwargs):
        # count *.asc-less temp files currently open in the dir
        live = [f for f in os.listdir(tmp_path) if not f.endswith('.asc')]
        max_concurrent['n'] = max(max_concurrent['n'], len(live))
        target = command.split()[-1]
        with open(f'{target}.asc', 'w') as fl:
            fl.write('sig')
        return (b'', 0)

    files = [_FakeUploadFile(f'f{i}.rpm') for i in range(20)]
    with mock.patch('sign.pgp.pgp.pexpect.run', side_effect=_run):
        results = asyncio.run(pgp.sign_batch('KEY', files))

    assert len(results) == 20
    assert max_concurrent['n'] == 1          # never more than one open at once


def test_sign_batch_returns_filenames_and_sigs(tmp_path):
    pgp = _make_pgp(tmp_path)
    files = [_FakeUploadFile('a.rpm'), _FakeUploadFile('b.rpm')]
    with mock.patch('sign.pgp.pgp.pexpect.run',
                    side_effect=_write_asc_then_ok(tmp_path)):
        results = asyncio.run(pgp.sign_batch('KEY', files))
    assert [name for name, _ in results] == ['a.rpm', 'b.rpm']
