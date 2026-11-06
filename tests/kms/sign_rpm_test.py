"""
Tests for KMS.sign_rpm, the glue between the /sign-rpm endpoint and rpmsign
running the KMS signer.

As on the GPG backend, the signed package is handed back as a path on disk,
so a failure anywhere in the middle must not leave it behind. On top of
that, the signer runs as a separate process and only knows the key and the
credentials it is given through rpmsign's environment.
"""

import asyncio
import os
import secrets
import threading
import time
from unittest.mock import patch

import boto3
import pytest

from sign.errors import FileTooBigError, NotAnRpmError, RpmSignError
from sign.kms import kms as kms_module
from sign.kms import rpm_signer
from sign.kms.kms import KMS
from sign.log import sentry_event_scrubber
from sign.rpm.rpm_sign import RPM_LEAD_MAGIC
from tests.kms.conftest import (
    FINGERPRINT,
    KEY_ID,
    RSA_ALGORITHMS,
    FakeKMSClient,
)
from tests.sentry_capture import captured_event

SIGNER = '/usr/local/bin/sign-file-rpm-signer'
PACKAGE = RPM_LEAD_MAGIC + b'unsigned package'
IDENTITY = {
    'name': 'bash',
    'nevra': 'bash-5.2.15-5.el9.x86_64',
    'arch': 'x86_64',
    'is_source': False,
}
SIGNATURE = 'RSA/SHA256, Key ID aaaaaaaaaaaaaaaa'


@pytest.fixture
def stub_rpm(monkeypatch):
    """Stub out rpm, rpmsign and the signer lookup."""
    calls = {}
    active = []
    lock = threading.Lock()

    def _install(sign_effect=None, signer=SIGNER, delay=0, missing=()):
        def _sign(path, keyid, signer_binary, **kwargs):
            calls['sign'] = {
                'path': path,
                'keyid': keyid,
                'signer': signer_binary,
                'kwargs': kwargs,
            }
            with lock:
                active.append(path)
                calls['max_active'] = max(
                    calls.get('max_active', 0), len(active)
                )
            time.sleep(delay)
            with lock:
                active.remove(path)
            if sign_effect is not None:
                # what a killed rpmsign leaves behind
                with open(f'{path}.sig', 'wb') as fd:
                    fd.write(b'partial')
                raise sign_effect
            with open(path, 'ab') as fd:
                fd.write(b' signed')
            return SIGNATURE

        monkeypatch.setattr(kms_module, 'sign_rpm_package_with_signer', _sign)
        monkeypatch.setattr(
            kms_module, 'read_package_identity', lambda path, **kw: IDENTITY
        )
        monkeypatch.setattr(
            kms_module.shutil,
            'which',
            lambda name: None if name in missing else signer,
        )
        return calls

    return _install


@pytest.fixture
def kms(make_kms, tmp_path):
    def _make(**kwargs):
        kwargs.setdefault('tmp_dir', str(tmp_path))
        backend, _ = make_kms(**kwargs)
        return backend

    return _make


def _leftovers(tmp_path):
    return [
        name for name in os.listdir(tmp_path) if name.endswith(('.rpm', '.sig'))
    ]


@pytest.fixture
def syslog_lines(monkeypatch):
    lines = []
    monkeypatch.setattr(
        kms_module.syslog, 'syslog', lambda level, line: lines.append(line)
    )
    return lines


def test_signs_with_rpmsign_and_the_signer(
    kms, stub_rpm, upload_file, tmp_path
):
    calls = stub_rpm()
    backend = kms(
        rpm_sign_timeout=30,
        rpmsign_binary='/usr/bin/rpmsign',
        rpm_binary='/usr/bin/rpm',
    )

    outcome = asyncio.run(
        backend.sign_rpm(KEY_ID, upload_file(PACKAGE), 'dev@example.com')
    )

    with open(outcome.path, 'rb') as fd:
        assert fd.read() == PACKAGE + b' signed'
    assert outcome.identity == IDENTITY
    assert outcome.signature == SIGNATURE
    assert outcome.hash_before != outcome.hash_after

    sign = calls['sign']
    assert sign['path'] == outcome.path
    # rpm passes %_gpg_name to the signer, which checks it against its key
    assert sign['keyid'] == FINGERPRINT
    assert sign['signer'] == SIGNER
    assert sign['kwargs']['timeout'] == 30
    assert sign['kwargs']['rpmsign_binary'] == '/usr/bin/rpmsign'
    assert sign['kwargs']['rpm_binary'] == '/usr/bin/rpm'
    env = sign['kwargs']['env']
    assert env[rpm_signer.ENV_KMS_KEY_ID] == KEY_ID
    assert env[rpm_signer.ENV_GPG_FINGERPRINT] == FINGERPRINT
    assert env[rpm_signer.ENV_SIGNING_ALGORITHM] == 'RSASSA_PKCS1_V1_5_SHA_256'


def test_key_can_be_named_by_gpg_key_id(kms, stub_rpm, upload_file):
    calls = stub_rpm()

    asyncio.run(kms().sign_rpm(FINGERPRINT[-16:], upload_file(PACKAGE)))

    env = calls['sign']['kwargs']['env']
    assert env[rpm_signer.ENV_KMS_KEY_ID] == KEY_ID


def test_signs_sha256_whatever_digest_files_use(kms, stub_rpm, upload_file):
    """rpm is told sha256; the KMS algorithm has to agree with it."""
    calls = stub_rpm()

    asyncio.run(
        kms(signing_algorithm='RSASSA_PKCS1_V1_5_SHA_512').sign_rpm(
            KEY_ID, upload_file(PACKAGE)
        )
    )

    env = calls['sign']['kwargs']['env']
    assert env[rpm_signer.ENV_SIGNING_ALGORITHM] == 'RSASSA_PKCS1_V1_5_SHA_256'


def test_explicit_credentials_reach_the_signer(kms, stub_rpm, upload_file):
    calls = stub_rpm()
    backend = kms(
        access_key_id='AKIA',
        secret_access_key='secret',
        region='eu-west-1',
    )

    asyncio.run(backend.sign_rpm(KEY_ID, upload_file(PACKAGE)))

    env = calls['sign']['kwargs']['env']
    assert env['AWS_ACCESS_KEY_ID'] == 'AKIA'
    assert env['AWS_SECRET_ACCESS_KEY'] == 'secret'
    assert env['AWS_DEFAULT_REGION'] == 'eu-west-1'


def test_unknown_key_is_rejected(kms, stub_rpm, upload_file, tmp_path):
    calls = stub_rpm()

    with pytest.raises(ValueError, match='Key not found'):
        asyncio.run(kms().sign_rpm('nope', upload_file(PACKAGE)))

    assert 'sign' not in calls
    assert _leftovers(tmp_path) == []


@pytest.mark.parametrize(
    'content, kwargs, stub, error',
    [
        (PACKAGE, {}, {'sign_effect': RpmSignError('boom')}, RpmSignError),
        (b'PK\x03\x04 not an rpm', {}, {}, NotAnRpmError),
        (PACKAGE, {'rpm_upload_limit': 4}, {}, FileTooBigError),
        (PACKAGE, {}, {'signer': None}, RpmSignError),
    ],
    ids=['rpmsign-fails', 'not-an-rpm', 'too-big', 'no-signer'],
)
def test_failure_leaves_no_temp_file(
    kms, stub_rpm, upload_file, tmp_path, content, kwargs, stub, error
):
    stub_rpm(**stub)

    with pytest.raises(error):
        asyncio.run(kms(**kwargs).sign_rpm(KEY_ID, upload_file(content)))

    assert _leftovers(tmp_path) == []


def test_upload_limit_defaults_to_max_upload_bytes(kms, stub_rpm, upload_file):
    stub_rpm()

    with pytest.raises(FileTooBigError):
        asyncio.run(
            kms(max_upload_bytes=4).sign_rpm(KEY_ID, upload_file(PACKAGE))
        )


@pytest.mark.parametrize(
    'algorithm, supported',
    [
        ('RSASSA_PKCS1_V1_5_SHA_256', True),
        ('RSASSA_PKCS1_V1_5_SHA_512', True),
        ('RSASSA_PSS_SHA_256', False),
        ('ECDSA_SHA_256', False),
    ],
)
def test_rpm_signing_needs_pkcs1_signatures(
    make_kms, stub_rpm, algorithm, supported
):
    stub_rpm()
    backend, _ = make_kms(
        signing_algorithms=RSA_ALGORITHMS + [algorithm],
        signing_algorithm=algorithm,
    )

    assert backend.supports_rpm_signing() is supported


def test_rpm_signing_needs_the_signer_installed(make_kms, stub_rpm):
    """Unavailable, not a 503 worth retrying on every request."""
    stub_rpm(signer=None)
    backend, _ = make_kms()

    assert backend.supports_rpm_signing() is False


@pytest.mark.parametrize('tool', ['rpmsign', 'rpm'])
def test_rpm_signing_needs_rpm_tools_installed(make_kms, stub_rpm, tool):
    """A KMS host had no use for rpm-sign before; now it is a requirement."""
    stub_rpm(missing=(tool,))
    backend, _ = make_kms()

    assert backend.supports_rpm_signing() is False


def test_credentials_stay_out_of_sentry_when_the_worker_fails(
    kms, stub_rpm, upload_file
):
    """
    asyncio.to_thread holds the call in a functools.partial, which Sentry
    reports by its repr; an unexpected error must not carry the secret out.
    """
    # Made up here: a literal would show up in the source context Sentry
    # attaches to this test's own frame.
    access_key_id = 'AKIA' + secrets.token_hex(8).upper()
    secret = secrets.token_hex(16)
    stub_rpm(sign_effect=OSError('rpmsign could not be started'))
    backend = kms(access_key_id=access_key_id, secret_access_key=secret)

    event = captured_event(
        lambda: asyncio.run(backend.sign_rpm(KEY_ID, upload_file(PACKAGE))),
        event_scrubber=sentry_event_scrubber(),
    )

    assert 'OSError' in event
    assert secret not in event
    # not a secret, but it names the AWS account
    assert access_key_id not in event


def test_spaced_lowercase_fingerprint_reaches_rpm_normalized(
    stub_rpm, upload_file, tmp_path
):
    """%_gpg_name must pass the key id check rpm_sign applies."""
    calls = stub_rpm()
    spaced = ' '.join(FINGERPRINT.lower()[i : i + 4] for i in range(0, 40, 4))
    with patch.object(
        boto3, 'client', return_value=FakeKMSClient(RSA_ALGORITHMS)
    ):
        backend = KMS(
            key_ids=[KEY_ID],
            gpg_fingerprints={KEY_ID: spaced},
            tmp_dir=str(tmp_path),
        )

    asyncio.run(backend.sign_rpm(KEY_ID, upload_file(PACKAGE)))

    assert calls['sign']['keyid'] == FINGERPRINT
    env = calls['sign']['kwargs']['env']
    assert env[rpm_signer.ENV_GPG_FINGERPRINT] == FINGERPRINT


def test_rpmsign_runs_are_bounded(kms, stub_rpm, upload_file):
    calls = stub_rpm(delay=0.2)
    backend = kms(rpm_sign_max_concurrency=1)

    async def _sign_three():
        await asyncio.gather(
            *(backend.sign_rpm(KEY_ID, upload_file(PACKAGE)) for _ in range(3))
        )

    asyncio.run(_sign_three())

    assert calls['max_active'] == 1


def test_signing_is_audited(kms, stub_rpm, upload_file, syslog_lines):
    stub_rpm()

    asyncio.run(kms().sign_rpm(KEY_ID, upload_file(PACKAGE), 'dev@example.com'))

    [line] = syslog_lines
    assert line.startswith('RPM header sign. User: dev@example.com.')
    assert f"Package: {IDENTITY['nevra']}." in line
    assert line.endswith(f'Sign key ID: {KEY_ID}')


def test_failed_signing_is_audited(kms, stub_rpm, upload_file, syslog_lines):
    stub_rpm(sign_effect=RpmSignError('KMS said no'))

    with pytest.raises(RpmSignError):
        asyncio.run(
            kms().sign_rpm(KEY_ID, upload_file(PACKAGE), 'dev@example.com')
        )

    [line] = syslog_lines
    assert line.startswith('RPM header sign FAILED. User: dev@example.com.')
    assert line.endswith('Error: RpmSignError')
