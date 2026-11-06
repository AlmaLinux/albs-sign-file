"""
Tests for the gpg stand-in rpmsign runs to sign RPM headers with KMS.

rpmsign only ever sees what this program writes, so the tests check the
signature packet itself: that it verifies against the key KMS signed with,
and that it carries what rpm's own parser insists on.
"""

import hashlib
import io
import os

import pgpy
import pytest
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from pgpy.constants import PubKeyAlgorithm, SignatureType

import sign
from sign.kms import rpm_signer
from sign.kms.rpm_signer import SignerError, SignRequest

KMS_KEY_ID = 'alias/rpm-signing'
# pgpy warns on every verify that it skips checks a keyring would make.
pytestmark = pytest.mark.filterwarnings('ignore:TODO:UserWarning')

SIGNING_ALGORITHM = 'RSASSA_PKCS1_V1_5_SHA_256'
DATA = b'rpm header bytes' * 1000

# The argument vector rpmsign 4.14 (EL8) and 4.16 (EL9) pass to %__gpg.
RPMSIGN_ARGV = [
    '--no-verbose',
    '--no-armor',
    '--digest-algo',
    'sha256',
    '--no-secmem-warning',
    '-u',
    'FINGERPRINT',
    '-sbo',
    '/tmp/pkg.rpm.sig',
    '-',
]


@pytest.fixture(scope='module')
def pgp_key():
    return pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)


class FakeKMS:
    """Signs digests with a local RSA key, as KMS would with its own."""

    def __init__(self, private_key):
        self._private_key = private_key
        self.calls = []

    def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
        self.calls.append({
            'KeyId': KeyId,
            'Message': Message,
            'MessageType': MessageType,
            'SigningAlgorithm': SigningAlgorithm,
        })
        signature = self._private_key.sign(
            Message,
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA256()),
        )
        return {'Signature': signature}


@pytest.fixture
def kms(pgp_key):
    return FakeKMS(pgp_key._key.keymaterial.__privkey__())


@pytest.fixture
def environ(pgp_key):
    return rpm_signer.signer_env(
        kms_key_id=KMS_KEY_ID,
        gpg_fingerprint=str(pgp_key.fingerprint).replace(' ', ''),
        signing_algorithm=SIGNING_ALGORITHM,
    )


@pytest.fixture
def data_file(tmp_path):
    path = tmp_path / 'data'
    path.write_bytes(DATA)
    return str(path)


def _request(pgp_key, data_file, **kwargs):
    fields = {
        'local_user': str(pgp_key.fingerprint).replace(' ', ''),
        'output': '-',
        'digest_algo': 'sha256',
        'input': data_file,
    }
    fields.update(kwargs)
    return SignRequest(**fields)


# --- command line -----------------------------------------------------------


def test_parses_the_rpmsign_command_line():
    request = rpm_signer.parse_gpg_args(RPMSIGN_ARGV)

    assert request == SignRequest(
        local_user='FINGERPRINT',
        output='/tmp/pkg.rpm.sig',
        digest_algo='sha256',
        input='-',
    )


@pytest.mark.parametrize(
    'argv',
    [
        ['--detach-sign', '--local-user', 'K', '--output', 'out', 'in'],
        ['-s', '-b', '-u', 'K', '-o', 'out', '--', 'in'],
        ['-b', '--local-user=K', '--output=out', 'in'],
    ],
)
def test_parses_other_spellings(argv):
    request = rpm_signer.parse_gpg_args(argv)

    assert (request.local_user, request.output, request.input) == (
        'K',
        'out',
        'in',
    )


@pytest.mark.parametrize(
    'argv, message',
    [
        # an inline signature is not what rpm stores
        (['-s', '-u', 'K', '-o', 'out', '-'], 'detached'),
        (['--clearsign', '-u', 'K', '-o', 'out', '-'], '--clearsign'),
        # rpm 4.11 and older hand gpg a passphrase this program has no use for
        (['--passphrase-fd', '3', '-sbo', 'out', '-u', 'K'], '--passphrase-fd'),
        (['-sabo', 'out', '-u', 'K', '-'], '-a'),
        (['-sbo', 'out', '-'], 'local_user'),
        (['-sb', '-u', 'K', '-'], 'output'),
        (['-sb', '-u'], 'needs a value'),
        (['-sbo', 'out', '-u', 'K', 'one', 'two'], 'one input'),
    ],
)
def test_refuses_what_it_cannot_do(argv, message):
    with pytest.raises(SignerError, match=message):
        rpm_signer.parse_gpg_args(argv)


# --- signature --------------------------------------------------------------


def test_signature_verifies_against_the_kms_key(
    pgp_key, kms, environ, data_file
):
    packet = rpm_signer.sign(_request(pgp_key, data_file), environ, kms)

    signature = pgpy.PGPSignature.from_blob(packet)
    assert signature.type == SignatureType.BinaryDocument
    assert signature.signer == pgp_key.fingerprint.keyid
    assert pgp_key.pubkey.verify(DATA, signature)
    assert not pgp_key.pubkey.verify(DATA + b'x', signature)


def test_kms_signs_the_openpgp_digest(pgp_key, kms, environ, data_file):
    packet = rpm_signer.sign(_request(pgp_key, data_file), environ, kms)

    signature = pgpy.PGPSignature.from_blob(packet)
    call = kms.calls[-1]
    assert call['KeyId'] == KMS_KEY_ID
    assert call['MessageType'] == 'DIGEST'
    assert call['SigningAlgorithm'] == SIGNING_ALGORITHM
    assert call['Message'] == hashlib.sha256(signature.hashdata(DATA)).digest()


def test_packet_carries_the_hash_prefix(pgp_key, kms, environ, data_file):
    """rpm 4.14/4.16 reject a signature whose prefix does not match."""
    packet = rpm_signer.sign(_request(pgp_key, data_file), environ, kms)

    signature = pgpy.PGPSignature.from_blob(packet)
    assert bytes(signature.hash2) == kms.calls[-1]['Message'][:2]


def test_reads_all_of_a_large_input_from_stdin(
    pgp_key, kms, environ, monkeypatch
):
    """With --rpmv3 rpm streams the whole package, header and payload."""
    data = os.urandom(3 * 1024 * 1024 + 1)
    monkeypatch.setattr(
        rpm_signer.sys, 'stdin', type('S', (), {'buffer': io.BytesIO(data)})
    )

    packet = rpm_signer.sign(_request(pgp_key, '-'), environ, kms)

    signature = pgpy.PGPSignature.from_blob(packet)
    assert pgp_key.pubkey.verify(data, signature)
    assert not pgp_key.pubkey.verify(data[:-1], signature)


def test_refuses_another_key_than_configured(pgp_key, kms, environ, data_file):
    request = _request(pgp_key, data_file, local_user='A' * 40)

    with pytest.raises(SignerError, match='configured for'):
        rpm_signer.sign(request, environ, kms)

    assert kms.calls == []


def test_accepts_the_configured_key_in_any_case(
    pgp_key, kms, environ, data_file
):
    fingerprint = str(pgp_key.fingerprint).replace(' ', '').lower()

    rpm_signer.sign(
        _request(pgp_key, data_file, local_user='0x' + fingerprint),
        environ,
        kms,
    )

    assert len(kms.calls) == 1


@pytest.mark.parametrize('digest_algo', ['sha512', 'sha1', 'md5'])
def test_refuses_a_digest_kms_would_not_sign(
    pgp_key, kms, environ, data_file, digest_algo
):
    request = _request(pgp_key, data_file, digest_algo=digest_algo)

    with pytest.raises(SignerError, match='does not match'):
        rpm_signer.sign(request, environ, kms)


@pytest.mark.parametrize('algorithm', ['RSASSA_PSS_SHA_256', 'ECDSA_SHA_256'])
def test_refuses_algorithms_openpgp_rsa_cannot_carry(
    pgp_key, kms, environ, data_file, algorithm
):
    environ[rpm_signer.ENV_SIGNING_ALGORITHM] = algorithm

    with pytest.raises(SignerError, match='cannot make an OpenPGP RSA'):
        rpm_signer.sign(_request(pgp_key, data_file), environ, kms)


@pytest.mark.parametrize(
    'variable',
    [
        rpm_signer.ENV_KMS_KEY_ID,
        rpm_signer.ENV_GPG_FINGERPRINT,
        rpm_signer.ENV_SIGNING_ALGORITHM,
    ],
)
def test_requires_its_configuration(pgp_key, kms, environ, data_file, variable):
    del environ[variable]

    with pytest.raises(SignerError, match=variable):
        rpm_signer.sign(_request(pgp_key, data_file), environ, kms)


# --- environment ------------------------------------------------------------


def test_env_without_credentials_leaves_aws_alone():
    env = rpm_signer.signer_env('k', 'F' * 40, SIGNING_ALGORITHM)

    assert not any(name.startswith('AWS_') for name in env)


def test_env_puts_the_running_code_first_on_pythonpath(monkeypatch):
    monkeypatch.setenv('PYTHONPATH', '/opt/extra')
    root = os.path.dirname(os.path.dirname(os.path.abspath(sign.__file__)))

    env = rpm_signer.signer_env('k', 'F' * 40, SIGNING_ALGORITHM)

    assert env['PYTHONPATH'] == os.pathsep.join([root, '/opt/extra'])


def test_env_leaves_pythonpath_alone_for_an_installed_package(monkeypatch):
    monkeypatch.setattr(
        rpm_signer.site, 'getsitepackages', lambda: [rpm_signer.PACKAGE_ROOT]
    )

    env = rpm_signer.signer_env('k', 'F' * 40, SIGNING_ALGORITHM)

    # site-packages ahead of the standard library could shadow it
    assert 'PYTHONPATH' not in env


def test_env_with_credentials_blanks_inherited_session_tokens():
    env = rpm_signer.signer_env(
        'k',
        'F' * 40,
        SIGNING_ALGORITHM,
        region='eu-west-1',
        access_key_id='AKIA',
        secret_access_key='secret',
    )

    assert env['AWS_DEFAULT_REGION'] == 'eu-west-1'
    assert env['AWS_ACCESS_KEY_ID'] == 'AKIA'
    assert env['AWS_SECRET_ACCESS_KEY'] == 'secret'
    # botocore reads the legacy name before the current one
    assert env['AWS_SECURITY_TOKEN'] == ''
    assert env['AWS_SESSION_TOKEN'] == ''


# --- entry point ------------------------------------------------------------


@pytest.fixture
def run_main(pgp_key, kms, environ, monkeypatch):
    monkeypatch.setattr(rpm_signer.os, 'environ', environ)
    monkeypatch.setattr(rpm_signer.boto3, 'client', lambda *a, **kw: kms)
    return rpm_signer.main


def test_main_writes_the_signature_file(run_main, pgp_key, data_file, tmp_path):
    output = tmp_path / 'data.sig'
    fingerprint = str(pgp_key.fingerprint).replace(' ', '')

    code = run_main(['-u', fingerprint, '-sbo', str(output), data_file])

    assert code == 0
    signature = pgpy.PGPSignature.from_blob(output.read_bytes())
    assert pgp_key.pubkey.verify(DATA, signature)


def test_main_writes_to_stdout_for_dash(
    run_main, pgp_key, data_file, capsysbinary
):
    fingerprint = str(pgp_key.fingerprint).replace(' ', '')

    code = run_main(['-u', fingerprint, '-sbo', '-', data_file])

    assert code == 0
    signature = pgpy.PGPSignature.from_blob(capsysbinary.readouterr().out)
    assert pgp_key.pubkey.verify(DATA, signature)


def test_main_reports_bad_usage(run_main, capsys):
    assert run_main(['--clearsign']) == 2
    assert 'sign-file-rpm-signer: unsupported gpg option' in (
        capsys.readouterr().err
    )


def test_main_reports_kms_failure(
    run_main, kms, pgp_key, data_file, tmp_path, monkeypatch, capsys
):
    def _denied(**kwargs):
        raise ClientError(
            {'Error': {'Code': 'AccessDeniedException', 'Message': 'no'}},
            'Sign',
        )

    monkeypatch.setattr(kms, 'sign', _denied)
    output = tmp_path / 'data.sig'
    fingerprint = str(pgp_key.fingerprint).replace(' ', '')

    code = run_main(['-u', fingerprint, '-sbo', str(output), data_file])

    assert code == 1
    assert 'AccessDeniedException' in capsys.readouterr().err
    assert not output.exists()
