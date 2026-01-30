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
    issuer_key_id = gpg_key_id[-16:].upper() if gpg_key_id else '0' * 16

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

    # Build signature trailer for hash computation (RFC 4880 Section 5.2.4)
    creation_ts = int(creation_time.timestamp())

    # Hashed subpackets
    time_subpacket = bytes([5, 2]) + struct.pack('>I', creation_ts)
    key_id_bytes = bytes.fromhex(issuer_key_id)
    issuer_subpacket = bytes([9, 16]) + key_id_bytes
    hashed_subpackets = time_subpacket + issuer_subpacket

    # Signature trailer
    trailer = bytes([
        4,  # Version 4
        sig_type.value,
        1,  # RSA
        hash_algo.value,
    ])
    trailer += struct.pack('>H', len(hashed_subpackets))
    trailer += hashed_subpackets

    # Final trailer
    final_trailer = bytes([4, 0xFF]) + struct.pack('>I', len(trailer))

    # Compute hash
    h = hash_func()
    h.update(hash_content)
    h.update(trailer)
    h.update(final_trailer)
    digest = h.digest()

    return digest, sig_type, hash_algo, creation_time, issuer_key_id


def wrap_signature_as_pgp(
    raw_signature: bytes,
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
    issuer_key_id = gpg_key_id[-16:].upper() if gpg_key_id else '0' * 16
    creation_ts = int(creation_time.timestamp())
    sig_type_val = 0x00 if detach_sign else 0x01

    # Build hashed subpackets
    time_subpacket = bytes([5, 2]) + struct.pack('>I', creation_ts)
    key_id_bytes = bytes.fromhex(issuer_key_id)
    issuer_subpacket = bytes([9, 16]) + key_id_bytes
    hashed_subpackets = time_subpacket + issuer_subpacket

    # Unhashed subpackets
    unhashed_subpackets = issuer_subpacket

    # MPI encoding of signature
    sig_stripped = raw_signature.lstrip(b'\x00') or b'\x00'
    bit_len = (len(sig_stripped) - 1) * 8
    if sig_stripped[0]:
        bit_len += sig_stripped[0].bit_length()
    sig_mpi = struct.pack('>H', bit_len) + sig_stripped

    # Signature packet body
    sig_body = bytes([4, sig_type_val, 1, hash_algo.value])
    sig_body += struct.pack('>H', len(hashed_subpackets))
    sig_body += hashed_subpackets
    sig_body += struct.pack('>H', len(unhashed_subpackets))
    sig_body += unhashed_subpackets
    sig_body += bytes([0x00, 0x00])
    sig_body += sig_mpi

    # Packet header (new format)
    header = bytes([0xC2])  # Tag 2 (signature)
    body_len = len(sig_body)
    if body_len < 192:
        header += bytes([body_len])
    elif body_len < 8384:
        header += bytes([((body_len - 192) >> 8) + 192, (body_len - 192) & 0xFF])
    else:
        header += bytes([0xFF]) + struct.pack('>I', body_len)

    packet = header + sig_body

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
