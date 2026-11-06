"""
OpenPGP signature packet construction for AWS KMS signatures using pgpy.

This module creates PGP-compatible signatures from raw KMS cryptographic
signatures, enabling verification with standard GPG tools.

Requires: pgpy (or PGPy13 for Python 3.13+)
"""

import hashlib
import struct
from datetime import datetime, timezone
from typing import Callable, Tuple

try:
    import pgpy
    from pgpy.constants import HashAlgorithm, SignatureType
except ImportError as e:
    raise ImportError(
        "pgpy is required for KMS signing. "
        "Install with: pip install PGPy13 (Python 3.13+) or pip install pgpy"
    ) from e


def get_pgpy_hash_algorithm(algorithm: str) -> HashAlgorithm:
    """Map algorithm name to pgpy HashAlgorithm."""
    algo_upper = algorithm.upper().replace('_', '')
    if 'SHA256' in algo_upper:
        return HashAlgorithm.SHA256
    if 'SHA384' in algo_upper:
        return HashAlgorithm.SHA384
    if 'SHA512' in algo_upper:
        return HashAlgorithm.SHA512
    return HashAlgorithm.SHA256


def get_hashlib_func(algorithm: str) -> Callable:
    """Get hashlib function for the algorithm."""
    algo_upper = algorithm.upper().replace('_', '')
    if 'SHA256' in algo_upper:
        return hashlib.sha256
    if 'SHA384' in algo_upper:
        return hashlib.sha384
    if 'SHA512' in algo_upper:
        return hashlib.sha512
    return hashlib.sha256


def get_hash_name(algorithm: str) -> str:
    """Get hash algorithm name for PGP headers."""
    algo_upper = algorithm.upper().replace('_', '')
    if 'SHA256' in algo_upper:
        return 'SHA256'
    if 'SHA384' in algo_upper:
        return 'SHA384'
    if 'SHA512' in algo_upper:
        return 'SHA512'
    return 'SHA256'


def _issuer_key_id(gpg_key_id: str) -> str:
    """Long (16 hex) key ID of a GPG fingerprint, as the issuer subpacket."""
    return gpg_key_id[-16:].upper() if gpg_key_id else '0' * 16


def _hashed_subpackets(creation_time: datetime, gpg_key_id: str) -> bytes:
    """Hashed subpackets: signature creation time and issuer key ID."""
    creation_ts = int(creation_time.timestamp())
    time_subpacket = bytes([5, 2]) + struct.pack('>I', creation_ts)
    issuer_subpacket = bytes([9, 16]) + bytes.fromhex(
        _issuer_key_id(gpg_key_id)
    )
    return time_subpacket + issuer_subpacket


def signature_trailer(
    sig_type: int,
    hash_algo: HashAlgorithm,
    gpg_key_id: str,
    creation_time: datetime,
) -> bytes:
    """
    The bytes hashed after the signed data (RFC 4880 Section 5.2.4).

    The digest to sign is the hash of the data followed by these bytes.
    Callers signing data too large to hold in memory hash it in chunks and
    finish with this.

    Args:
        sig_type: Signature type value (0x00 binary, 0x01 canonical text)
        hash_algo: Hash algorithm of the signature
        gpg_key_id: GPG key fingerprint
        creation_time: Signature creation time
    """
    hashed_subpackets = _hashed_subpackets(creation_time, gpg_key_id)
    trailer = bytes([
        4,  # Version 4
        sig_type,
        1,  # RSA
        hash_algo.value,
    ])
    trailer += struct.pack('>H', len(hashed_subpackets))
    trailer += hashed_subpackets
    final_trailer = bytes([4, 0xFF]) + struct.pack('>I', len(trailer))
    return trailer + final_trailer


def build_signature_packet(
    raw_signature: bytes,
    digest: bytes,
    sig_type: int,
    hash_algo: HashAlgorithm,
    gpg_key_id: str,
    creation_time: datetime,
) -> bytes:
    """
    Build a binary OpenPGP v4 signature packet around a raw RSA signature.

    Args:
        raw_signature: Raw signature bytes from KMS
        digest: The digest KMS signed
        sig_type: Signature type value the digest was computed with
        hash_algo: Hash algorithm the digest was computed with
        gpg_key_id: GPG key fingerprint
        creation_time: Creation time the digest was computed with

    Returns:
        The packet, header included
    """
    hashed_subpackets = _hashed_subpackets(creation_time, gpg_key_id)

    # Unhashed subpackets
    unhashed_subpackets = bytes([9, 16]) + bytes.fromhex(
        _issuer_key_id(gpg_key_id)
    )

    # MPI encoding of signature
    sig_stripped = raw_signature.lstrip(b'\x00') or b'\x00'
    bit_len = (len(sig_stripped) - 1) * 8
    if sig_stripped[0]:
        bit_len += sig_stripped[0].bit_length()
    sig_mpi = struct.pack('>H', bit_len) + sig_stripped

    # Signature packet body
    sig_body = bytes([4, sig_type, 1, hash_algo.value])
    sig_body += struct.pack('>H', len(hashed_subpackets))
    sig_body += hashed_subpackets
    sig_body += struct.pack('>H', len(unhashed_subpackets))
    sig_body += unhashed_subpackets
    # Left 16 bits of the signed hash (RFC 4880 Section 5.2.3). gpg and
    # Sequoia ignore a wrong value, but rpm's own OpenPGP parser (rpm 4.14
    # on EL8, 4.16 on EL9) rejects the signature.
    sig_body += digest[:2]
    sig_body += sig_mpi

    # Packet header (new format)
    header = bytes([0xC2])  # Tag 2 (signature)
    body_len = len(sig_body)
    if body_len < 192:
        header += bytes([body_len])
    elif body_len < 8384:
        header += bytes(
            [((body_len - 192) >> 8) + 192, (body_len - 192) & 0xFF]
        )
    else:
        header += bytes([0xFF]) + struct.pack('>I', body_len)

    return header + sig_body


def compute_pgp_hash(
    content: bytes,
    algorithm: str,
    detach_sign: bool,
    gpg_key_id: str,
    creation_time: datetime = None,
) -> Tuple[bytes, SignatureType, HashAlgorithm, datetime, str]:
    """
    Compute the hash for a PGP signature following RFC 4880.

    Args:
        content: File content to sign
        algorithm: Hash algorithm name
        detach_sign: True for detached signature, False for cleartext
        gpg_key_id: GPG key fingerprint
        creation_time: Optional timestamp (defaults to now)

    Returns:
        Tuple of (digest, sig_type, hash_algo, creation_time, issuer_key_id)
    """
    if creation_time is None:
        creation_time = datetime.now(timezone.utc)

    hash_func = get_hashlib_func(algorithm)
    hash_algo = get_pgpy_hash_algorithm(algorithm)
    issuer_key_id = _issuer_key_id(gpg_key_id)

    if detach_sign:
        sig_type = SignatureType.BinaryDocument
        hash_content = content
    else:
        sig_type = SignatureType.CanonicalDocument
        try:
            text = content.decode('utf-8')
        except UnicodeDecodeError:
            text = content.decode('latin-1')
        normalized = text.replace('\r\n', '\n').replace('\r', '\n')
        lines = [line.rstrip() for line in normalized.split('\n')]
        normalized = '\r\n'.join(lines)
        hash_content = normalized.encode('utf-8')

    # Compute hash
    h = hash_func()
    h.update(hash_content)
    h.update(
        signature_trailer(sig_type.value, hash_algo, gpg_key_id, creation_time)
    )
    digest = h.digest()

    return digest, sig_type, hash_algo, creation_time, issuer_key_id


def wrap_signature_as_pgp(
    raw_signature: bytes,
    digest: bytes,
    content: bytes,
    algorithm: str,
    detach_sign: bool,
    gpg_key_id: str,
    creation_time: datetime = None,
) -> str:
    """
    Wrap a raw KMS signature in PGP format using pgpy.

    Args:
        raw_signature: Raw signature bytes from KMS
        digest: The digest KMS signed, as returned by compute_pgp_hash
        content: Original file content (needed for cleartext)
        algorithm: Hash algorithm used
        detach_sign: True for detached signature, False for cleartext
        gpg_key_id: GPG key fingerprint
        creation_time: Optional timestamp

    Returns:
        ASCII-armored PGP signature or cleartext signed message
    """
    if creation_time is None:
        creation_time = datetime.now(timezone.utc)

    hash_algo = get_pgpy_hash_algorithm(algorithm)
    sig_type_val = 0x00 if detach_sign else 0x01
    packet = build_signature_packet(
        raw_signature,
        digest,
        sig_type_val,
        hash_algo,
        gpg_key_id,
        creation_time,
    )

    # Parse with pgpy for proper ASCII armoring
    sig = pgpy.PGPSignature()
    sig.parse(packet)

    if detach_sign:
        return str(sig)

    # Create cleartext signed message
    try:
        text = content.decode('utf-8')
    except UnicodeDecodeError:
        text = content.decode('latin-1')

    # Dash-escape lines starting with '-'
    escaped_lines = []
    for line in text.split('\n'):
        if line.startswith('-'):
            escaped_lines.append('- ' + line)
        else:
            escaped_lines.append(line)
    escaped_text = '\n'.join(escaped_lines)

    hash_name = get_hash_name(algorithm)

    return '\n'.join([
        '-----BEGIN PGP SIGNED MESSAGE-----',
        f'Hash: {hash_name}',
        '',
        escaped_text,
        str(sig),
    ])
