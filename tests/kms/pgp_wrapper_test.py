import asyncio
from datetime import datetime, timezone

import pgpy
import pytest

from sign.kms import pgp_wrapper
from tests.kms.conftest import KEY_ID

CONTENT = b'albs sign file\n'


def _signature_block(result: str) -> str:
    start = result.index('-----BEGIN PGP SIGNATURE-----')
    return result[start:]


@pytest.mark.parametrize('detach_sign', [True, False])
@pytest.mark.parametrize('digest_algo', ['SHA256', 'SHA384', 'SHA512'])
def test_hash_prefix_matches_signed_digest(
    make_kms, upload_file, detach_sign, digest_algo
):
    """
    The packet carries the left 16 bits of the digest KMS signed. rpm's own
    OpenPGP parser (EL8, EL9) rejects a header signature where they differ.
    """
    backend, client = make_kms()

    result = asyncio.run(
        backend.sign(
            KEY_ID,
            upload_file(CONTENT),
            detach_sign=detach_sign,
            digest_algo=digest_algo,
        )
    )

    sig = pgpy.PGPSignature.from_blob(_signature_block(result))
    assert bytes(sig.hash2) == client.last_sign_call['Message'][:2]


@pytest.mark.parametrize('digest_algo', ['SHA256', 'SHA384', 'SHA512'])
def test_streamed_hash_matches_compute_pgp_hash(digest_algo):
    """The RPM signer hashes in chunks and finishes with the trailer."""
    created = datetime(2026, 11, 6, tzinfo=timezone.utc)
    fingerprint = 'D6FD32A40E7DB971B153C210FFAFE84D3118885F'
    digest, sig_type, hash_algo, _, _ = pgp_wrapper.compute_pgp_hash(
        CONTENT, digest_algo, True, fingerprint, created
    )

    hasher = pgp_wrapper.get_hashlib_func(digest_algo)()
    for byte in CONTENT:
        hasher.update(bytes([byte]))
    hasher.update(
        pgp_wrapper.signature_trailer(
            sig_type.value, hash_algo, fingerprint, created
        )
    )

    assert hasher.digest() == digest
