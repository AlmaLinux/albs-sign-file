"""
rpmsign running the KMS signer for real.

Everything rpmsign and the signer agree on is exercised here rather than
assumed: the gpg command line rpm builds, the data it streams on stdin, the
signature file it reads back, and the header and header+payload signatures
it stores. Only KMS is replaced, by a local RSA key inside the signer
process, and rpm itself checks the result.

fixtures/sign-file-fixture-1.0-1.noarch.rpm is an unsigned noarch package
with one small file, built with rpmbuild on AlmaLinux 9.

Skipped where rpmsign is not installed; the test image has it.
"""

import os
import shutil
import subprocess
import sys
import time

import pgpy
import pytest
from cryptography.hazmat.primitives import serialization
from pgpy.constants import HashAlgorithm, KeyFlags, PubKeyAlgorithm

from sign.errors import RpmSignError
from sign.kms import rpm_signer
from sign.rpm import rpm_sign

FIXTURE = os.path.join(
    os.path.dirname(__file__),
    'fixtures',
    'sign-file-fixture-1.0-1.noarch.rpm',
)

pytestmark = [
    pytest.mark.skipif(shutil.which('rpmsign') is None, reason='needs rpmsign'),
    pytest.mark.filterwarnings('ignore:TODO:UserWarning'),
]

FAKE_SIGNER = '''#!{python}
"""The KMS RPM signer with KMS replaced by a local RSA key."""
import os
import sys
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils

from sign.kms import rpm_signer


class FakeKMS:
    def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
        time.sleep(float(os.environ.get('FAKE_KMS_DELAY', '0')))
        with open(os.environ['FAKE_KMS_KEY'], 'rb') as fd:
            key = serialization.load_pem_private_key(fd.read(), None)
        with open(os.environ['FAKE_KMS_LOG'], 'a') as log:
            log.write(KeyId + '\\n')
        signature = key.sign(
            Message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
        )
        return {{'Signature': signature}}


rpm_signer.boto3.client = lambda *args, **kwargs: FakeKMS()
sys.exit(rpm_signer.main())
'''


@pytest.fixture(scope='module')
def pgp_key():
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    key.add_uid(
        pgpy.PGPUID.new('albs-sign-file tests'),
        usage={KeyFlags.Sign, KeyFlags.Certify},
        hashes=[HashAlgorithm.SHA256],
    )
    return key


@pytest.fixture
def lab(tmp_path, pgp_key):
    """The fake signer, its key, an rpm database trusting it, a package."""
    private_key = pgp_key._key.keymaterial.__privkey__()
    key_file = tmp_path / 'kms-key.pem'
    key_file.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    signer = tmp_path / 'signer'
    signer.write_text(FAKE_SIGNER.format(python=sys.executable))
    signer.chmod(0o755)

    pubkey = tmp_path / 'RPM-GPG-KEY-test'
    pubkey.write_text(str(pgp_key.pubkey))
    db = tmp_path / 'rpmdb'
    subprocess.run(['rpm', '--dbpath', str(db), '--initdb'], check=True)
    subprocess.run(
        ['rpm', '--dbpath', str(db), '--import', str(pubkey)], check=True
    )

    package = tmp_path / os.path.basename(FIXTURE)
    shutil.copy(FIXTURE, package)
    fingerprint = str(pgp_key.fingerprint).replace(' ', '')
    env = rpm_signer.signer_env(
        kms_key_id='alias/rpm-test',
        gpg_fingerprint=fingerprint,
        signing_algorithm='RSASSA_PKCS1_V1_5_SHA_256',
    )
    env.update(
        FAKE_KMS_KEY=str(key_file),
        FAKE_KMS_LOG=str(tmp_path / 'kms.log'),
    )
    return {
        'signer': str(signer),
        'db': str(db),
        'package': str(package),
        'fingerprint': fingerprint,
        'env': env,
        'kms_log': tmp_path / 'kms.log',
    }


def _rpm_check(lab):
    result = subprocess.run(
        ['rpm', '--dbpath', lab['db'], '-Kv', lab['package']],
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout + result.stderr


def test_rpm_verifies_what_rpmsign_and_the_signer_produce(lab):
    signature = rpm_sign.sign_rpm_package_with_signer(
        lab['package'], lab['fingerprint'], lab['signer'], env=lab['env']
    )

    code, output = _rpm_check(lab)
    assert code == 0, output
    assert 'NOT OK' not in output
    keyid = lab['fingerprint'][-8:].lower()
    # The header signature, and with --rpmv3 the header+payload one too.
    assert f'Header V4 RSA/SHA256 Signature, key ID {keyid}: OK' in output
    assert f'    V4 RSA/SHA256 Signature, key ID {keyid}: OK' in output
    assert signature.lower().endswith(lab['fingerprint'][-16:].lower())
    assert lab['kms_log'].read_text().split() == ['alias/rpm-test'] * 2


def test_a_package_signed_by_another_key_does_not_verify(lab, tmp_path):
    """The check above would notice a signature from the wrong key."""
    other = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    other_key = tmp_path / 'other.pem'
    other_key.write_bytes(
        other._key.keymaterial.__privkey__().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    lab['env']['FAKE_KMS_KEY'] = str(other_key)

    rpm_sign.sign_rpm_package_with_signer(
        lab['package'], lab['fingerprint'], lab['signer'], env=lab['env']
    )

    code, output = _rpm_check(lab)
    assert code != 0
    assert 'BAD' in output


def test_timeout_stops_the_signer_too(lab):
    """
    Killing rpmsign alone would leave the signer holding its pipes, and it
    would still have KMS sign whatever it had read by then.
    """
    lab['env']['FAKE_KMS_DELAY'] = '30'
    started = time.monotonic()

    with pytest.raises(RpmSignError, match='timed out after 2s'):
        rpm_sign.sign_rpm_package_with_signer(
            lab['package'],
            lab['fingerprint'],
            lab['signer'],
            env=lab['env'],
            timeout=2,
        )

    assert time.monotonic() - started < 10
    # Give an orphaned signer a moment to get to KMS, had it survived.
    time.sleep(1)
    assert not lab['kms_log'].exists()
