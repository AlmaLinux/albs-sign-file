"""
RPM package header signing.

The ``rpmsign`` invocation mirrors the one the ALBS sign nodes use
(``sign_node/package_sign.py`` in albs-sign-node) so that a package signed
through this service is indistinguishable from one signed by the build
system's own sign slaves: previous signatures are dropped with
``--delsign`` first, then the package is re-signed in place with
``--rpmv3 --resign -D '_gpg_name <keyid>'`` and the passphrase is fed to
the prompt over a PTY.
"""

import contextlib
import dataclasses
import logging
import os
import re
import traceback
from typing import Dict, List, Optional

import pexpect
import plumbum

from sign.errors import NotAnRpmError, RpmSignError
from sign.utils.gpg import restart_gpg_agent
from sign.utils.locking import (
    GPG_AGENT_LOCK_FILENAME,
    exclusive_lock,
    shared_lock,
)

__all__ = [
    'RpmSignOutcome',
    'delete_signatures',
    'ensure_rpm_file',
    'gpg_sign_locks',
    'normalize_keyid',
    'read_package_identity',
    'read_signature_info',
    'rpmsign_version',
    'sign_rpm_package',
    'supports_rpmv3',
    'validate_keyid',
    'verify_header_signature',
]

@dataclasses.dataclass
class RpmSignOutcome:
    """Result of signing one uploaded package."""

    path: str
    identity: Dict[str, str]
    hash_before: str
    hash_after: str
    signature: str


# First four bytes of the RPM lead, present in both binary RPMs and SRPMs.
RPM_LEAD_MAGIC = b'\xed\xab\xee\xdb'

# rpmsign grew the --rpmv3 flag (write a V3 header signature alongside the
# V4 one) in 4.14.3; older builds reject the option.
RPMV3_MIN_VERSION = (4, 14, 3)

KEYID_RE = re.compile(r'^(0x)?[0-9A-Fa-f]{8,40}$')

# rpm renders a missing tag as this.
RPM_NONE = '(none)'


def validate_keyid(keyid: str) -> str:
    """
    Check that ``keyid`` is a plain hex key id / fingerprint.

    The key id is interpolated into the ``rpmsign`` command line, so it must
    not be able to carry shell metacharacters even though callers can only
    name keys the service already holds.
    """
    if not KEYID_RE.match(keyid or ''):
        raise ValueError(f'invalid PGP key id: {keyid!r}')
    return keyid


def normalize_keyid(keyid: str) -> str:
    """
    Reduce a key id or fingerprint to the lowercase long (16 hex) key id
    that rpm reports in the ``pgpsig`` tags. Shorter ids are returned as
    they are and matched as a suffix.
    """
    keyid = (keyid or '').lower()
    if keyid.startswith('0x'):
        keyid = keyid[2:]
    return keyid[-16:] if len(keyid) > 16 else keyid


def ensure_rpm_file(path: str):
    """
    Raise :class:`NotAnRpmError` unless ``path`` starts with the RPM lead
    magic. ``rpmsign`` happily rewrites whatever it is handed, so the check
    keeps non-packages out before anything touches the gpg agent.
    """
    with open(path, 'rb') as fd:
        if fd.read(len(RPM_LEAD_MAGIC)) != RPM_LEAD_MAGIC:
            raise NotAnRpmError('file is not an RPM package')


def _parse_version(text: str) -> tuple:
    parts = []
    for chunk in text.strip().split('.'):
        match = re.match(r'^(\d+)', chunk)
        if not match:
            break
        parts.append(int(match.group(1)))
    return tuple(parts)


def rpmsign_version(rpmsign_binary: str = 'rpmsign') -> str:
    """Return the version string reported by ``rpmsign --version``."""
    code, out, err = plumbum.local[rpmsign_binary].run(
        args=['--version'],
        retcode=None,
    )
    if code != 0:
        raise RpmSignError(
            f'cannot get rpmsign version: {out}\n{err}'
        )
    return out.split()[-1]


def supports_rpmv3(version: str) -> bool:
    """
    Whether this rpmsign accepts ``--rpmv3``.

    Compared component-wise: a plain string compare puts '4.9.0' above
    '4.14.3' and would pass the flag to an rpmsign that rejects it.
    """
    return _parse_version(version) > RPMV3_MIN_VERSION


def read_package_identity(path: str, rpm_binary: str = 'rpm') -> Dict[str, str]:
    """
    Read the package identity (NEVRA) used for the audit trail.

    Queried with signature and digest checks disabled: the package is not
    signed yet, and the point here is to name it, not to trust it.
    """
    query_format = (
        '%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}|%{SOURCERPM}'
    )
    code, out, err = plumbum.local[rpm_binary].run(
        args=[
            '-qp',
            '--nosignature',
            '--nodigest',
            '--qf',
            query_format,
            path,
        ],
        retcode=None,
    )
    if code != 0:
        raise NotAnRpmError(
            f'cannot read RPM metadata: {"".join((out, err)).strip()}'
        )
    fields = out.strip().split('|')
    if len(fields) != 6:
        raise NotAnRpmError(f'unexpected rpm query output: {out!r}')
    name, epoch, version, release, arch, sourcerpm = fields
    epoch_prefix = f'{epoch}:' if epoch and epoch != '0' else ''
    return {
        'name': name,
        'nevra': f'{name}-{epoch_prefix}{version}-{release}.{arch}',
        'arch': arch,
        'is_source': sourcerpm in ('', RPM_NONE),
    }


def read_signature_info(path: str, rpm_binary: str = 'rpm') -> str:
    """
    Return the header signature description rpm prints for ``path``, e.g.
    ``RSA/SHA256, Tue 01 Apr 2025 10:00:00 AM UTC, Key ID aaaa1111bbbb2222``.
    """
    query_format = (
        '%{RSAHEADER:pgpsig}|%{DSAHEADER:pgpsig}|'
        '%{SIGPGP:pgpsig}|%{SIGGPG:pgpsig}'
    )
    code, out, err = plumbum.local[rpm_binary].run(
        args=[
            '-qp',
            '--nosignature',
            '--nodigest',
            '--qf',
            query_format,
            path,
        ],
        retcode=None,
    )
    if code != 0:
        raise RpmSignError(
            f'cannot read RPM signature: {"".join((out, err)).strip()}'
        )
    return out.strip()


def verify_header_signature(
    path: str,
    keyid: str,
    rpm_binary: str = 'rpm',
) -> str:
    """
    Check that ``path`` now carries a header signature made by ``keyid``.

    ``rpmsign`` exits 0 in cases where it wrote nothing usable, so the
    result is read back rather than trusted. Returns the signature
    description for the audit record.
    """
    info = read_signature_info(path, rpm_binary=rpm_binary)
    if normalize_keyid(keyid) not in info.lower():
        raise RpmSignError(
            f'signed package carries no header signature from key {keyid} '
            f'(rpm reports: {info})'
        )
    # The query asks for four signature tags at once; report the one that
    # is actually set rather than the raw '(none)'-padded result.
    for field in info.split('|'):
        if field and field != RPM_NONE:
            return field
    return info


@contextlib.contextmanager
def gpg_sign_locks(
    keyid: str,
    gpg_locks_dir: str,
    yubikey_keyids: Optional[List[str]] = None,
):
    """
    Acquire the locks needed for a signing operation with ``keyid``.

    A shared lock on the gpg-agent file is always held during signing so
    that no other process can restart gpg-agent mid-sign. When ``keyid`` is
    a Yubikey-backed key, an additional per-key exclusive lock serializes
    hardware access, and gpg-agent is reloaded (under the exclusive
    gpg-agent lock) after the sign region exits.
    """
    yubikey_keyids = yubikey_keyids or []
    is_yubikey = keyid in yubikey_keyids
    with shared_lock(gpg_locks_dir, GPG_AGENT_LOCK_FILENAME):
        if is_yubikey:
            with exclusive_lock(gpg_locks_dir, keyid):
                yield
        else:
            yield
    if is_yubikey:
        with exclusive_lock(gpg_locks_dir, GPG_AGENT_LOCK_FILENAME):
            restart_gpg_agent()


def delete_signatures(path: str, rpmsign_binary: str = 'rpmsign'):
    """
    Drop any signatures the submitted package already carries.

    ``--resign`` replaces the signature anyway, but a package that arrives
    with a stale signature from another key would otherwise keep it in the
    signature header alongside ours.
    """
    logging.info('Deleting previous signatures from %s', path)
    code, out, err = plumbum.local[rpmsign_binary].run(
        args=['--delsign', path],
        retcode=None,
    )
    logging.debug('Command result: %d, %s\n%s', code, out, err)
    if code != 0:
        full_out = '\n'.join((out, err)).strip()
        raise RpmSignError(f'cannot delete package signature: {full_out}')


def sign_rpm_package(
    path: str,
    keyid: str,
    password: str,
    locks_dir_path: str = '/tmp/gpg_locks',
    yubikey_keyids: Optional[List[str]] = None,
    rpmsign_binary: str = 'rpmsign',
    rpm_binary: str = 'rpm',
    timeout: int = 1200,
) -> str:
    """
    Sign the header of the RPM package at ``path``, in place.

    Parameters
    ----------
    path : str
        RPM (or source RPM) package path.
    keyid : str
        PGP key keyid.
    password : str
        PGP key password.
    locks_dir_path : str
        Path to a dir with lock files.
    yubikey_keyids : list
        List of YubiKey-backed key ids.
    rpmsign_binary : str
        ``rpmsign`` executable.
    rpm_binary : str
        ``rpm`` executable, used to read the resulting signature back.
    timeout : int
        Seconds to wait for rpmsign.

    Returns
    -------
    str
        The header signature description rpm reports for the signed package.

    Raises
    ------
    RpmSignError
        If an error occurred.
    NotAnRpmError
        If ``path`` is not an RPM package.
    """
    validate_keyid(keyid)
    ensure_rpm_file(path)
    delete_signatures(path, rpmsign_binary=rpmsign_binary)

    sign_cmd_parts = [rpmsign_binary]
    if supports_rpmv3(rpmsign_version(rpmsign_binary)):
        sign_cmd_parts.append('--rpmv3')
    sign_cmd_parts.extend(['--resign', '-D', f"'_gpg_name {keyid}'", path])
    sign_cmd = ' '.join(sign_cmd_parts)
    # gpg-agent's pinentry needs a terminal to prompt on. The service runs
    # as a daemon with no controlling tty, so GPG_TTY is set from inside
    # the PTY pexpect gives us; without it gpg fails the signature with
    # 'Required environment variable not set'.
    final_cmd = f'/bin/bash -c "export GPG_TTY=$(tty); {sign_cmd}"'

    # The environment is inherited rather than replaced: rpmsign shells out
    # to gpg, which needs HOME/GNUPGHOME to find the keyring and the agent
    # socket. Only the locale is forced, so the passphrase prompt matches.
    env = dict(os.environ, LC_ALL='en_US.UTF-8')

    with gpg_sign_locks(
        keyid=keyid,
        gpg_locks_dir=locks_dir_path,
        yubikey_keyids=yubikey_keyids,
    ):
        out, status = pexpect.run(
            command=final_cmd,
            events={'Enter passphrase:.*': f'{password}\r'},
            env=env,
            timeout=timeout,
            withexitstatus=True,
            # poll() has no FD_SETSIZE (1024) limit, unlike select();
            # required when the process holds many open fds. See PF-673.
            use_poll=True,
        )
    if status is None:
        message = (
            f'The RPM signing command timed out after {timeout}s.'
            f'\nCommand: {final_cmd}\nOutput:\n{out}'
        )
        logging.error(message)
        raise RpmSignError(message)
    if status != 0:
        logging.error(
            'The RPM signing command failed with %s exit code.'
            '\nCommand: %s\nOutput:\n%s.\nTraceback: %s',
            status,
            final_cmd,
            out,
            traceback.format_exc(),
        )
        raise RpmSignError(
            f'RPM sign failed with {status} exit code.\nOutput: {out}'
        )

    return verify_header_signature(path, keyid, rpm_binary=rpm_binary)
