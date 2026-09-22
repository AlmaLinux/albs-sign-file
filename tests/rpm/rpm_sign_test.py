"""
Tests for the rpmsign wrapper behind POST /sign-rpm (PF-3304).

The invocation mirrors the one the ALBS sign nodes use, so most of what is
worth pinning down here is the shape of the command line, the order of
operations (delete old signatures, then re-sign, then read the signature
back) and the failure paths.
"""

import pytest

from sign.errors import NotAnRpmError, RpmSignError
from sign.rpm import rpm_sign

KEYID = 'AAAA1111BBBB2222'
SIG_DESCRIPTION = (
    'RSA/SHA256, Tue 01 Apr 2025 10:00:00 AM UTC, '
    'Key ID aaaa1111bbbb2222'
)
SIG_LINE = f'{SIG_DESCRIPTION}|(none)|{SIG_DESCRIPTION}|(none)'


# --- version gate -----------------------------------------------------------


@pytest.mark.parametrize(
    'version, expected',
    [
        ('4.16.1.3', True),
        ('4.14.4', True),
        ('4.14.3', False),
        ('4.14.2', False),
        # A plain string compare puts '4.9.0' above '4.14.3' and would pass
        # --rpmv3 to an rpmsign that rejects it.
        ('4.9.0', False),
        ('4.11.3', False),
        ('6.0.2', True),
    ],
)
def test_supports_rpmv3(version, expected):
    assert rpm_sign.supports_rpmv3(version) is expected


def test_rpmsign_version_reads_last_token(fake_plumbum):
    fake_plumbum({'rpmsign': lambda args: (0, 'RPM version 4.16.1.3\n', '')})

    assert rpm_sign.rpmsign_version() == '4.16.1.3'


def test_rpmsign_version_failure_raises(fake_plumbum):
    fake_plumbum({'rpmsign': lambda args: (1, '', 'boom')})

    with pytest.raises(RpmSignError, match='cannot get rpmsign version'):
        rpm_sign.rpmsign_version()


# --- key id handling --------------------------------------------------------


@pytest.mark.parametrize(
    'keyid',
    ['AAAA1111BBBB2222', '0xaaaa1111bbbb2222', 'BBBB2222', 'B' * 40],
)
def test_validate_keyid_accepts_hex(keyid):
    assert rpm_sign.validate_keyid(keyid) == keyid


@pytest.mark.parametrize(
    'keyid',
    [
        '',
        None,
        'not-a-key',
        'AAAA1111BBBB2222; rm -rf /',
        '$(id)',
        'AAAA111',  # too short
    ],
)
def test_validate_keyid_rejects_anything_else(keyid):
    with pytest.raises(ValueError):
        rpm_sign.validate_keyid(keyid)


@pytest.mark.parametrize(
    'keyid, expected',
    [
        ('AAAA1111BBBB2222', 'aaaa1111bbbb2222'),
        ('0xAAAA1111BBBB2222', 'aaaa1111bbbb2222'),
        ('C' * 24 + 'AAAA1111BBBB2222', 'aaaa1111bbbb2222'),
        ('BBBB2222', 'bbbb2222'),
    ],
)
def test_normalize_keyid(keyid, expected):
    assert rpm_sign.normalize_keyid(keyid) == expected


# --- package validation -----------------------------------------------------


def test_ensure_rpm_file_accepts_rpm(rpm_file):
    rpm_sign.ensure_rpm_file(rpm_file)


def test_ensure_rpm_file_rejects_other_files(tmp_path):
    path = tmp_path / 'not-an.rpm'
    path.write_bytes(b'PK\x03\x04 this is a zip')

    with pytest.raises(NotAnRpmError):
        rpm_sign.ensure_rpm_file(str(path))


def test_read_package_identity(fake_plumbum, rpm_file):
    fake_plumbum({
        'rpm': lambda args: (
            0, 'bash|0|5.2.15|5.el9|x86_64|(none)', ''
        ),
    })

    identity = rpm_sign.read_package_identity(rpm_file)

    assert identity['name'] == 'bash'
    assert identity['nevra'] == 'bash-5.2.15-5.el9.x86_64'
    assert identity['is_source'] is True


def test_read_package_identity_includes_epoch(fake_plumbum, rpm_file):
    fake_plumbum({
        'rpm': lambda args: (
            0, 'bash|2|5.2.15|5.el9|x86_64|bash-5.2.15-5.el9.src.rpm', ''
        ),
    })

    identity = rpm_sign.read_package_identity(rpm_file)

    assert identity['nevra'] == 'bash-2:5.2.15-5.el9.x86_64'
    assert identity['is_source'] is False


def test_read_package_identity_query_is_offline(fake_plumbum, rpm_file):
    calls = fake_plumbum({
        'rpm': lambda args: (0, 'bash|0|1|1|noarch|(none)', ''),
    })

    rpm_sign.read_package_identity(rpm_file)

    args = calls[0][1]
    assert '--nosignature' in args
    assert '--nodigest' in args


def test_read_package_identity_rejects_unreadable_package(
    fake_plumbum, rpm_file
):
    fake_plumbum({'rpm': lambda args: (1, '', 'error: not an rpm')})

    with pytest.raises(NotAnRpmError):
        rpm_sign.read_package_identity(rpm_file)


# --- signature verification -------------------------------------------------


def test_verify_header_signature_accepts_matching_key(fake_plumbum, rpm_file):
    fake_plumbum({'rpm': lambda args: (0, SIG_LINE, '')})

    signature = rpm_sign.verify_header_signature(rpm_file, KEYID)

    # the '(none)' padding from the four-tag query is dropped
    assert signature == SIG_DESCRIPTION


def test_verify_header_signature_rejects_other_key(fake_plumbum, rpm_file):
    fake_plumbum({'rpm': lambda args: (0, SIG_LINE, '')})

    with pytest.raises(RpmSignError, match='no header signature'):
        rpm_sign.verify_header_signature(rpm_file, 'CCCC3333DDDD4444')


def test_verify_header_signature_rejects_unsigned_package(
    fake_plumbum, rpm_file
):
    fake_plumbum({'rpm': lambda args: (0, '(none)|(none)|(none)|(none)', '')})

    with pytest.raises(RpmSignError, match='no header signature'):
        rpm_sign.verify_header_signature(rpm_file, KEYID)


# --- signing ----------------------------------------------------------------


@pytest.fixture
def fake_pexpect(monkeypatch):
    """Record the command pexpect.run was given and control its result."""
    seen = {}

    def _install(result=(b'', 0)):
        def _run(command, **kwargs):
            seen['command'] = command
            seen['kwargs'] = kwargs
            return result

        monkeypatch.setattr(rpm_sign.pexpect, 'run', _run)
        return seen

    return _install


@pytest.fixture
def signing_plumbum(fake_plumbum):
    """rpmsign reports a modern version and succeeds; rpm reports our key."""
    def _install(delsign_result=(0, '', '')):
        def _rpmsign(args):
            if args[0] == '--version':
                return (0, 'RPM version 4.16.1.3\n', '')
            return delsign_result

        return fake_plumbum({
            'rpmsign': _rpmsign,
            'rpm': lambda args: (0, SIG_LINE, ''),
        })

    return _install


def test_sign_rpm_package_builds_expected_command(
    signing_plumbum, fake_pexpect, rpm_file, tmp_path
):
    calls = signing_plumbum()
    seen = fake_pexpect()

    signature = rpm_sign.sign_rpm_package(
        rpm_file, KEYID, 'secret', locks_dir_path=str(tmp_path / 'locks')
    )

    assert signature == SIG_DESCRIPTION
    command = seen['command']
    assert command.startswith('/bin/bash -c "export GPG_TTY=$(tty); ')
    assert 'rpmsign --rpmv3 --resign ' in command
    assert f"-D '_gpg_name {KEYID}'" in command
    assert command.endswith(f'{rpm_file}"')
    # the passphrase is fed to the prompt, never put on the command line
    assert 'secret' not in command
    assert seen['kwargs']['events'] == {'Enter passphrase:.*': 'secret\r'}
    # poll() has no FD_SETSIZE limit, unlike select(). See PF-673.
    assert seen['kwargs']['use_poll'] is True
    # existing signatures are dropped before re-signing
    assert ('rpmsign', ['--delsign', rpm_file]) in calls


def test_sign_rpm_package_omits_rpmv3_on_old_rpmsign(
    fake_plumbum, fake_pexpect, rpm_file, tmp_path
):
    def _rpmsign(args):
        if args[0] == '--version':
            return (0, 'RPM version 4.11.3\n', '')
        return (0, '', '')

    fake_plumbum({
        'rpmsign': _rpmsign,
        'rpm': lambda args: (0, SIG_LINE, ''),
    })
    seen = fake_pexpect()

    rpm_sign.sign_rpm_package(
        rpm_file, KEYID, 'secret', locks_dir_path=str(tmp_path / 'locks')
    )

    assert '--rpmv3' not in seen['command']


def test_sign_rpm_package_rejects_bad_keyid(rpm_file, tmp_path):
    with pytest.raises(ValueError):
        rpm_sign.sign_rpm_package(
            rpm_file,
            '$(touch /tmp/pwned)',
            'secret',
            locks_dir_path=str(tmp_path / 'locks'),
        )


def test_sign_rpm_package_rejects_non_rpm(tmp_path):
    path = tmp_path / 'payload.rpm'
    path.write_bytes(b'not an rpm at all')

    with pytest.raises(NotAnRpmError):
        rpm_sign.sign_rpm_package(
            str(path), KEYID, 'secret', locks_dir_path=str(tmp_path / 'locks')
        )


def test_sign_rpm_package_fails_when_delsign_fails(
    signing_plumbum, fake_pexpect, rpm_file, tmp_path
):
    signing_plumbum(delsign_result=(1, '', 'cannot open'))
    seen = fake_pexpect()

    with pytest.raises(RpmSignError, match='cannot delete package signature'):
        rpm_sign.sign_rpm_package(
            rpm_file, KEYID, 'secret', locks_dir_path=str(tmp_path / 'locks')
        )

    assert 'command' not in seen


def test_sign_rpm_package_fails_on_nonzero_exit(
    signing_plumbum, fake_pexpect, rpm_file, tmp_path
):
    signing_plumbum()
    fake_pexpect(result=(b'gpg: signing failed', 1))

    with pytest.raises(RpmSignError, match='exit code'):
        rpm_sign.sign_rpm_package(
            rpm_file, KEYID, 'secret', locks_dir_path=str(tmp_path / 'locks')
        )


def test_sign_rpm_package_fails_on_timeout(
    signing_plumbum, fake_pexpect, rpm_file, tmp_path
):
    signing_plumbum()
    fake_pexpect(result=(b'', None))

    with pytest.raises(RpmSignError, match='timed out'):
        rpm_sign.sign_rpm_package(
            rpm_file, KEYID, 'secret', locks_dir_path=str(tmp_path / 'locks')
        )


def test_sign_rpm_package_fails_when_signature_is_missing(
    fake_plumbum, fake_pexpect, rpm_file, tmp_path
):
    """rpmsign can exit 0 without writing a usable signature."""
    def _rpmsign(args):
        if args[0] == '--version':
            return (0, 'RPM version 4.16.1.3\n', '')
        return (0, '', '')

    fake_plumbum({
        'rpmsign': _rpmsign,
        'rpm': lambda args: (0, '(none)|(none)|(none)|(none)', ''),
    })
    fake_pexpect()

    with pytest.raises(RpmSignError, match='no header signature'):
        rpm_sign.sign_rpm_package(
            rpm_file, KEYID, 'secret', locks_dir_path=str(tmp_path / 'locks')
        )


def test_sign_rpm_package_keeps_gnupg_environment(
    signing_plumbum, fake_pexpect, rpm_file, tmp_path, monkeypatch
):
    """
    rpmsign shells out to gpg, which needs HOME/GNUPGHOME to find the
    keyring and the agent socket.
    """
    monkeypatch.setenv('GNUPGHOME', '/srv/keys/.gnupg')
    signing_plumbum()
    seen = fake_pexpect()

    rpm_sign.sign_rpm_package(
        rpm_file, KEYID, 'secret', locks_dir_path=str(tmp_path / 'locks')
    )

    env = seen['kwargs']['env']
    assert env['GNUPGHOME'] == '/srv/keys/.gnupg'
    assert env['LC_ALL'] == 'en_US.UTF-8'


def test_sign_rpm_package_sets_gpg_tty(
    signing_plumbum, fake_pexpect, rpm_file, tmp_path
):
    """
    The service has no controlling tty, so pinentry gets the PTY pexpect
    allocates; without GPG_TTY gpg refuses to prompt for the passphrase.
    """
    signing_plumbum()
    seen = fake_pexpect()

    rpm_sign.sign_rpm_package(
        rpm_file, KEYID, 'secret', locks_dir_path=str(tmp_path / 'locks')
    )

    assert 'export GPG_TTY=$(tty);' in seen['command']
