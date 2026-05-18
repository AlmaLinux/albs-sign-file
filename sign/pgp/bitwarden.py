"""Fetch GPG key passphrases from a Bitwarden vault.

Each GPG keyid must correspond to a Bitwarden item whose *name* equals the
keyid and whose *password* field is the passphrase.
"""
import logging
from typing import Dict, List, Optional

from sign.pgp.errors import ConfigurationError

logger = logging.getLogger(__name__)


def fetch_passphrases(
    keyids: List[str],
    username: Optional[str] = None,
    password: Optional[str] = None,
    password_file: Optional[str] = None,
    collection_id: Optional[str] = None,
) -> Dict[str, str]:
    try:
        from bsbw import BWCLIWrapper
    except ImportError as e:
        raise ConfigurationError(
            "bitwarden-wrapper is not installed. "
            "Install with: pip install '.[bitwarden]'"
        ) from e

    if not password and not password_file:
        raise ConfigurationError(
            "Bitwarden master password or password file must be provided "
            "(set bitwarden.password / SF_BITWARDEN_PASSWORD or "
            "bitwarden.password_file / SF_BITWARDEN_PASSWORD_FILE)"
        )

    logger.info("Fetching GPG passphrases from Bitwarden for %d keys", len(keyids))
    wrapper = BWCLIWrapper(
        username=username,
        password=password,
        password_file=password_file,
        collection_id=collection_id,
    )
    container = wrapper.get_secrets()

    result: Dict[str, str] = {}
    missing: List[str] = []
    for keyid in keyids:
        if keyid not in container:
            missing.append(keyid)
            continue
        passphrase = container.get_credentials(keyid, password_only=True)
        if not passphrase:
            missing.append(keyid)
            continue
        result[keyid] = passphrase

    if missing:
        raise ConfigurationError(
            "Bitwarden vault is missing passphrases for keys: "
            + ", ".join(missing)
        )

    return result
