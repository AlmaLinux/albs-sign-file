"""
Regression tests for PF-673: /sign-batch failing with
'ValueError: filedescriptor out of range in select()'.

These cover the three fixes:
  1. every pexpect.run() call passes use_poll=True (poll() has no FD_SETSIZE
     limit, so signing never crashes on a high-numbered fd). pexpect is only
     used for Yubikey-backed keys now; software keys get the passphrase on
     stdin via subprocess.run (no pty at all);
  2. the gpg '<name>.asc' file and the UploadFile spooled fd are cleaned up on
     every path, including signing failure / oversized upload (no fd leak);
  3. sign_batch signs files one at a time, so it does not open one temp file +
     PTY per file up front (fd usage stays flat regardless of batch size).
"""
import asyncio
import os
import subprocess
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


def _as_subprocess(fake_pexpect_run):
    """
    Adapt a fake pexpect.run(command, **kw) -> (out, status) into a fake
    subprocess.run(args, **kw) -> CompletedProcess, so one fake gpg serves
    both the software-key (subprocess) and Yubikey (pexpect) paths.
    """
    def _run(args, **kwargs):
        out, status = fake_pexpect_run(' '.join(args), **kwargs)
        return subprocess.CompletedProcess(args, status, stdout=out)
    return _run


def _patch_gpg(fake_pexpect_run):
    """Patch the software-key gpg invocation with a fake gpg."""
    return mock.patch('sign.pgp.pgp.subprocess.run',
                      side_effect=_as_subprocess(fake_pexpect_run))


def _yubikey():
    """Route signing through the Yubikey (pexpect) path."""
    return mock.patch.multiple(
        'sign.pgp.pgp',
        restart_gpg_agent=mock.DEFAULT,
    ), mock.patch.object(PGP, '_is_yubikey', return_value=True)


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

    agent, yubikey = _yubikey()
    with agent, yubikey, \
            mock.patch('sign.pgp.pgp.pexpect.run', side_effect=_run):
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

    agent, yubikey = _yubikey()
    with agent, yubikey, \
            mock.patch('sign.pgp.pgp.pexpect.run', side_effect=_run):
        asyncio.run(pgp.sign_batch('KEY', [_FakeUploadFile('a.rpm')]))

    assert seen.get('use_poll') is True


# --- Fix 3: no leak of .asc / UploadFile on any path ------------------------

def test_sign_removes_asc_on_success(tmp_path):
    pgp = _make_pgp(tmp_path)
    upload = _FakeUploadFile('a.rpm')
    with _patch_gpg(_write_asc_then_ok(tmp_path)):
        asyncio.run(pgp.sign('KEY', upload))
    assert os.listdir(tmp_path) == []        # no .asc, no temp file left
    assert upload.file.closed is True


def test_sign_removes_asc_on_gpg_failure(tmp_path):
    pgp = _make_pgp(tmp_path)
    upload = _FakeUploadFile('a.rpm')
    with _patch_gpg(_write_asc_then_fail(tmp_path)):
        with pytest.raises(Exception):
            asyncio.run(pgp.sign('KEY', upload))
    # the partial .asc gpg left behind must be cleaned up despite the failure
    assert os.listdir(tmp_path) == []
    assert upload.file.closed is True


def test_sign_closes_upload_on_too_big(tmp_path):
    pgp = _make_pgp(tmp_path)
    pgp.max_upload_bytes = 2
    upload = _FakeUploadFile('a.rpm', data=b'way too large')
    with mock.patch('sign.pgp.pgp.subprocess.run') as run:
        with pytest.raises(FileTooBigError):
            asyncio.run(pgp.sign('KEY', upload))
    run.assert_not_called()                  # bailed before signing
    assert upload.file.closed is True        # but still released the fd
    assert os.listdir(tmp_path) == []


def test_sign_batch_removes_asc_on_failure(tmp_path):
    pgp = _make_pgp(tmp_path)
    with _patch_gpg(_write_asc_then_fail(tmp_path)):
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
    with _patch_gpg(_run):
        results = asyncio.run(pgp.sign_batch('KEY', files))

    assert len(results) == 20
    assert max_concurrent['n'] == 1          # never more than one open at once


def test_sign_batch_returns_filenames_and_sigs(tmp_path):
    pgp = _make_pgp(tmp_path)
    files = [_FakeUploadFile('a.rpm'), _FakeUploadFile('b.rpm')]
    with _patch_gpg(_write_asc_then_ok(tmp_path)):
        results = asyncio.run(pgp.sign_batch('KEY', files))
    assert [name for name, _ in results] == ['a.rpm', 'b.rpm']


# --- passphrase on stdin, gpg off the event loop -----------------------------

def test_software_key_passes_passphrase_on_stdin(tmp_path):
    pgp = _make_pgp(tmp_path)
    seen = {}

    def _run(args, **kwargs):
        seen['args'], seen['kwargs'] = args, kwargs
        with open(f'{args[-1]}.asc', 'w') as fl:
            fl.write('sig')
        return subprocess.CompletedProcess(args, 0, stdout=b'')

    with mock.patch('sign.pgp.pgp.subprocess.run', side_effect=_run), \
            mock.patch('sign.pgp.pgp.pexpect.run') as pexpect_run:
        asyncio.run(pgp.sign('KEY', _FakeUploadFile('a.txt')))

    pexpect_run.assert_not_called()
    args = seen['args']
    assert args[0] == '/usr/bin/gpg2'
    assert '--batch' in args
    assert args[args.index('--passphrase-fd') + 1] == '0'
    assert args[args.index('--pinentry-mode') + 1] == 'loopback'
    assert seen['kwargs']['input'] == b'pw\n'
    # the passphrase is never on the command line
    assert 'pw' not in args


def test_concurrent_signs_overlap(tmp_path):
    """gpg runs off the event loop, so one worker signs files in parallel."""
    import threading
    import time

    pgp = _make_pgp(tmp_path)
    running = {'now': 0, 'max': 0}
    lock = threading.Lock()

    def _slow_gpg(command, **kwargs):
        with lock:
            running['now'] += 1
            running['max'] = max(running['max'], running['now'])
        time.sleep(0.2)
        with lock:
            running['now'] -= 1
        with open(f'{command.split()[-1]}.asc', 'w') as fl:
            fl.write('sig')
        return (b'', 0)

    async def _sign_many():
        await asyncio.gather(*(
            pgp.sign('KEY', _FakeUploadFile(f'f{i}.txt')) for i in range(4)
        ))

    with _patch_gpg(_slow_gpg):
        asyncio.run(_sign_many())

    assert running['max'] > 1


def test_yubikey_concurrent_batches_and_signs_do_not_deadlock(tmp_path):
    """
    Two batches and two single signs for the same Yubikey key, at once,
    in one process. Waiting for the per-key flock on the event loop used to
    deadlock the worker: a batch holding the key could never resume.
    """
    import threading
    import time

    pgp = _make_pgp(tmp_path / 'tmp')
    (tmp_path / 'tmp').mkdir()

    def _gpg(command, **kwargs):
        time.sleep(0.05)
        with open(f'{command.split()[-1]}.asc', 'w') as fl:
            fl.write('sig')
        return (b'', 0)

    async def _all():
        await asyncio.gather(
            pgp.sign_batch('KEY', [_FakeUploadFile(f'a{i}') for i in range(3)]),
            pgp.sign_batch('KEY', [_FakeUploadFile(f'b{i}') for i in range(3)]),
            pgp.sign('KEY', _FakeUploadFile('c')),
            pgp.sign('KEY', _FakeUploadFile('d')),
        )

    done = threading.Event()
    errors = []

    def _run():
        try:
            asyncio.run(_all())
        except Exception as exc:  # surfaced through `errors`
            errors.append(exc)
        done.set()

    agent, yubikey = _yubikey()
    with agent, yubikey, \
            mock.patch('sign.pgp.pgp.pexpect.run', side_effect=_gpg), \
            mock.patch('sign.pgp.pgp.settings.gpg_locks_dir',
                       str(tmp_path / 'locks')):
        worker = threading.Thread(target=_run, daemon=True)
        worker.start()
        finished = done.wait(timeout=15)

    assert finished, 'signing deadlocked'
    assert not errors


def test_gpg_sign_concurrency_is_capped(tmp_path):
    """No more than gpg_sign_max_concurrency gpg runs at once per process."""
    import threading
    import time

    from sign.pgp import pgp as pgp_module

    pgp = _make_pgp(tmp_path)
    running = {'now': 0, 'max': 0}
    lock = threading.Lock()

    def _slow_gpg(command, **kwargs):
        with lock:
            running['now'] += 1
            running['max'] = max(running['max'], running['now'])
        time.sleep(0.1)
        with lock:
            running['now'] -= 1
        with open(f'{command.split()[-1]}.asc', 'w') as fl:
            fl.write('sig')
        return (b'', 0)

    async def _sign_many():
        await asyncio.gather(*(
            pgp.sign('KEY', _FakeUploadFile(f'f{i}.txt')) for i in range(8)
        ))

    pgp_module._gpg_sign_slots.cache_clear()
    try:
        with mock.patch.object(pgp_module.settings,
                               'gpg_sign_max_concurrency', 2), \
                _patch_gpg(_slow_gpg):
            asyncio.run(_sign_many())
    finally:
        pgp_module._gpg_sign_slots.cache_clear()

    assert running['max'] == 2
