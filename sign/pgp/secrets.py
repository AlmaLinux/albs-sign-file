"""Resolve GPG key passphrases from an external secret provider.

Exactly one provider may be enabled at a time: signing keys should have a
single unambiguous source of truth, so enabling several is a configuration
error rather than a merge of their results.
"""

import logging
from typing import Dict, List, Optional

from sign.pgp.errors import ConfigurationError

logger = logging.getLogger(__name__)


def enabled_providers(settings) -> List[str]:
    """Names of the secret providers switched on in the configuration."""
    flags = (
        ("bitwarden", settings.bitwarden_enabled),
        ("vault", settings.vault_enabled),
    )
    return [name for name, enabled in flags if enabled]


def _from_bitwarden(settings) -> Dict[str, str]:
    from sign.pgp.bitwarden import fetch_passphrases

    return fetch_passphrases(
        keyids=settings.pgp_keys,
        username=settings.bitwarden_username,
        password=settings.bitwarden_password,
        password_file=settings.bitwarden_password_file,
        collection_id=settings.bitwarden_collection_id,
    )


def _from_vault(settings) -> Dict[str, str]:
    from sign.pgp.vault import fetch_passphrases

    return fetch_passphrases(
        keyids=settings.pgp_keys,
        addr=settings.vault_addr,
        token=settings.vault_token,
        token_file=settings.vault_token_file,
        role_id=settings.vault_role_id,
        secret_id=settings.vault_secret_id,
        secret_id_file=settings.vault_secret_id_file,
        namespace=settings.vault_namespace,
        mount=settings.vault_mount,
        path_prefix=settings.vault_path_prefix,
        field=settings.vault_passphrase_field,
        ca_cert=settings.vault_ca_cert,
    )


def resolve_passphrases(settings) -> Optional[Dict[str, str]]:
    """Fetch passphrases from the configured provider.

    Returns ``None`` when no provider is enabled, leaving the caller to fall
    back to development mode or interactive prompts.
    """
    providers = enabled_providers(settings)
    if len(providers) > 1:
        raise ConfigurationError(
            "Only one secret provider may be enabled at a time, but these "
            "are enabled: " + ", ".join(providers)
        )
    if not providers:
        return None
    provider = providers[0]
    logger.info("Using the %s secret provider for GPG passphrases", provider)
    fetchers = {"bitwarden": _from_bitwarden, "vault": _from_vault}
    return fetchers[provider](settings)
