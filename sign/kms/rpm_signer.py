"""
gpg stand-in that rpmsign runs to sign RPM headers with an AWS KMS key.

rpmsign makes no signatures itself. It runs ``%{__gpg}`` with gpg's command
line, roughly ``gpg --no-verbose --no-armor --digest-algo sha256
--no-secmem-warning -u NAME -sbo SIGFILE -``, writes the data to sign to its
stdin, and stores the binary detached signature it finds in SIGFILE. With
``%__gpg`` pointing at this program, the data is hashed here, KMS signs the
digest, and rpmsign keeps doing everything else: which signature tags to
write, the header layout, ``--rpmv3``.

The service tells this program which key to use through the environment
(see ``signer_env``). AWS credentials and region come from the environment
the usual boto3 way.

Installed as the ``sign-file-rpm-signer`` console script: rpm executes
``%__gpg`` directly, without a shell or a PATH lookup, so it has to be a
single executable path.
"""

import os
import site
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from sign.kms.pgp_wrapper import (
    build_signature_packet,
    get_hash_name,
    get_hashlib_func,
    get_pgpy_hash_algorithm,
    signature_trailer,
)

PROG = 'sign-file-rpm-signer'

ENV_KMS_KEY_ID = 'SIGN_FILE_RPM_KMS_KEY_ID'
ENV_GPG_FINGERPRINT = 'SIGN_FILE_RPM_GPG_FINGERPRINT'
ENV_SIGNING_ALGORITHM = 'SIGN_FILE_RPM_SIGNING_ALGORITHM'

# Directory holding the ``sign`` package this module was imported from.
PACKAGE_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

# OpenPGP signature type of a detached signature over binary data.
BINARY_DOCUMENT = 0x00

# gpg options rpmsign passes that change nothing here.
IGNORED_FLAGS = {
    '--no-verbose',
    '--no-armor',
    '--no-secmem-warning',
    '--batch',
    '--no-tty',
    '--yes',
}
LONG_ACTIONS = {'--sign': 's', '--detach-sign': 'b'}
OPTIONS_WITH_VALUE = {
    '-u': 'local_user',
    '--local-user': 'local_user',
    '-o': 'output',
    '--output': 'output',
    '--digest-algo': 'digest_algo',
}


class SignerError(Exception):
    pass


@dataclass
class SignRequest:
    local_user: str
    output: str
    digest_algo: Optional[str] = None
    input: str = '-'


def parse_gpg_args(argv: List[str]) -> SignRequest:
    """
    Read the detached-signature request out of a gpg command line.

    Anything else gpg could be asked to do is refused rather than ignored,
    so a change in rpm's ``%__gpg_sign_cmd`` fails loudly.
    """
    values: Dict[str, str] = {}
    actions = set()
    positional = []
    args = iter(argv)
    for arg in args:
        if arg == '--':
            positional.extend(args)
            break
        if arg in IGNORED_FLAGS:
            continue
        if arg in LONG_ACTIONS:
            actions.add(LONG_ACTIONS[arg])
            continue
        if arg in OPTIONS_WITH_VALUE:
            try:
                values[OPTIONS_WITH_VALUE[arg]] = next(args)
            except StopIteration:
                raise SignerError(f'option {arg} needs a value') from None
            continue
        if arg.startswith('--') and '=' in arg:
            name, value = arg.split('=', 1)
            if name in OPTIONS_WITH_VALUE:
                values[OPTIONS_WITH_VALUE[name]] = value
                continue
        if arg.startswith('-') and not arg.startswith('--') and len(arg) > 1:
            # Bundled short options, e.g. -sbo FILE: s and b are flags,
            # u and o take the next argument.
            for letter in arg[1:]:
                if letter in 'sb':
                    actions.add(letter)
                elif letter in 'uo':
                    try:
                        values[OPTIONS_WITH_VALUE['-' + letter]] = next(args)
                    except StopIteration:
                        raise SignerError(
                            f'option -{letter} needs a value'
                        ) from None
                else:
                    raise SignerError(f'unsupported gpg option: -{letter}')
            continue
        if arg.startswith('-') and arg != '-':
            raise SignerError(f'unsupported gpg option: {arg}')
        positional.append(arg)

    if actions not in ({'s', 'b'}, {'b'}):
        raise SignerError('only detached signing (-sb) is supported')
    for required in ('local_user', 'output'):
        if required not in values:
            raise SignerError(f'missing gpg option for {required}')
    if len(positional) > 1:
        raise SignerError(f'expected one input, got {positional}')
    return SignRequest(
        local_user=values['local_user'],
        output=values['output'],
        digest_algo=values.get('digest_algo'),
        input=positional[0] if positional else '-',
    )


class SignerEnv(dict):
    """
    Environment for the signer. It may hold AWS credentials, so its repr
    names the variables only. A repr ends up where no scrubber looks inside
    it: asyncio.to_thread keeps the call, arguments and all, in a
    functools.partial that Sentry reports by its repr.
    """

    def __repr__(self):
        return f'{type(self).__name__}({sorted(self)})'


def signer_env(
    kms_key_id: str,
    gpg_fingerprint: str,
    signing_algorithm: str,
    region: Optional[str] = None,
    access_key_id: Optional[str] = None,
    secret_access_key: Optional[str] = None,
) -> SignerEnv:
    """
    Environment variables rpmsign has to pass on to this program.

    Without explicit credentials the program finds them the way the
    service's own boto3 client did: environment, config files, instance
    role. With explicit ones, any inherited session token is blanked: it
    belongs to other credentials, and boto3 would send it along with these.

    When the service runs from a source checkout (the development image),
    PYTHONPATH points the console script at that checkout, so it runs the
    same signer as the service. An installed package needs nothing: the
    script finds it in site-packages.
    """
    env = SignerEnv({
        ENV_KMS_KEY_ID: kms_key_id,
        ENV_GPG_FINGERPRINT: gpg_fingerprint,
        ENV_SIGNING_ALGORITHM: signing_algorithm,
    })
    if not _is_site_dir(PACKAGE_ROOT):
        env['PYTHONPATH'] = os.pathsep.join(
            filter(None, [PACKAGE_ROOT, os.environ.get('PYTHONPATH')])
        )
    if region:
        env['AWS_DEFAULT_REGION'] = region
    if access_key_id and secret_access_key:
        env['AWS_ACCESS_KEY_ID'] = access_key_id
        env['AWS_SECRET_ACCESS_KEY'] = secret_access_key
        # Blank inherited tokens (botocore reads the legacy name first); there
        # is no secret in an empty string.
        env['AWS_SECURITY_TOKEN'] = ''  # nosec B105
        env['AWS_SESSION_TOKEN'] = ''  # nosec B105
    return env


def _is_site_dir(path: str) -> bool:
    site_dirs = site.getsitepackages() + [site.getusersitepackages()]
    return os.path.realpath(path) in {os.path.realpath(d) for d in site_dirs}


def _normalize_fingerprint(value: str) -> str:
    value = value.replace(' ', '').upper()
    return value[2:] if value.startswith('0X') else value


def _hash_name(digest_algo: str) -> str:
    """gpg's --digest-algo value as named by get_hash_name, e.g. SHA256."""
    return digest_algo.upper().replace('-', '').replace('_', '')


def _hash_input(path: str, hasher):
    src = sys.stdin.buffer if path == '-' else open(path, 'rb')
    with src:
        for chunk in iter(lambda: src.read(1024 * 1024), b''):
            hasher.update(chunk)


def sign(request: SignRequest, environ, kms_client=None) -> bytes:
    """
    Hash the input, have KMS sign the digest, and return the signature
    packet.
    """
    try:
        kms_key_id = environ[ENV_KMS_KEY_ID]
        fingerprint = _normalize_fingerprint(environ[ENV_GPG_FINGERPRINT])
        signing_algorithm = environ[ENV_SIGNING_ALGORITHM]
    except KeyError as exc:
        raise SignerError(f'{exc.args[0]} is not set') from None

    # rpm passes %_gpg_name, which the service sets to the fingerprint of
    # the key it configured here; anything else means the two disagree.
    if _normalize_fingerprint(request.local_user) != fingerprint:
        raise SignerError(
            f'asked to sign as {request.local_user}, '
            f'but configured for {fingerprint}'
        )
    if not signing_algorithm.startswith('RSASSA_PKCS1_V1_5_'):
        raise SignerError(
            f'{signing_algorithm} cannot make an OpenPGP RSA signature'
        )
    # KMS checks the digest length against the hash its algorithm names.
    hash_name = get_hash_name(signing_algorithm)
    if request.digest_algo and _hash_name(request.digest_algo) != hash_name:
        raise SignerError(
            f'digest {request.digest_algo} does not match {signing_algorithm}'
        )

    hash_algo = get_pgpy_hash_algorithm(hash_name)
    creation_time = datetime.now(timezone.utc)
    hasher = get_hashlib_func(hash_name)()
    _hash_input(request.input, hasher)
    hasher.update(
        signature_trailer(
            BINARY_DOCUMENT, hash_algo, fingerprint, creation_time
        )
    )
    digest = hasher.digest()

    if kms_client is None:
        kms_client = boto3.client(
            'kms',
            config=Config(retries={'max_attempts': 3, 'mode': 'adaptive'}),
        )
    response = kms_client.sign(
        KeyId=kms_key_id,
        Message=digest,
        MessageType='DIGEST',
        SigningAlgorithm=signing_algorithm,
    )
    return build_signature_packet(
        response['Signature'],
        digest,
        BINARY_DOCUMENT,
        hash_algo,
        fingerprint,
        creation_time,
    )


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        request = parse_gpg_args(argv)
        packet = sign(request, os.environ)
    except SignerError as exc:
        print(f'{PROG}: {exc}', file=sys.stderr)
        return 2
    except (BotoCoreError, ClientError) as exc:
        print(f'{PROG}: KMS signing failed: {exc}', file=sys.stderr)
        return 1
    if request.output == '-':
        sys.stdout.buffer.write(packet)
    else:
        with open(request.output, 'wb') as fd:
            fd.write(packet)
    return 0


if __name__ == '__main__':
    sys.exit(main())
