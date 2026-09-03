"""Fetch GPG key passphrases from Google Secret Manager (GSM).

Each GPG keyid must correspond to a secret whose *id* is the keyid
(optionally prefixed via ``gsm.secret_prefix``) and whose payload is the
passphrase:

    gcloud secrets create <prefix><keyid> --replication-policy=automatic
    printf '%s' '<passphrase>' | \
        gcloud secrets versions add <prefix><keyid> --data-file=-

The client is deliberately built inside :func:`fetch_passphrases` rather than
at import time: a gRPC channel created before a ``fork()`` (e.g. under
``gunicorn --preload``) does not survive into the worker.
"""
import logging
from typing import Dict, List, Optional

from sign.pgp.errors import ConfigurationError

logger = logging.getLogger(__name__)

SECRET_VERSION_DEFAULT = "latest"  # nosec B105 - a version alias


def fetch_passphrases(
    keyids: List[str],
    project_id: Optional[str] = None,
    secret_prefix: str = "",  # nosec B107 - a secret-name prefix
    secret_version: str = SECRET_VERSION_DEFAULT,
    credentials_file: Optional[str] = None,
) -> Dict[str, str]:
    """Read one secret per keyid and return a keyid -> passphrase mapping.

    Parameters
    ----------
    keyids : list of str
        GPG keyids to look up.
    project_id : str
        Google Cloud project holding the secrets.
    secret_prefix : str
        Optional prefix prepended to the keyid to build the secret id.
    secret_version : str
        Secret version to access, ``latest`` by default.
    credentials_file : str, optional
        Path to a service account JSON key. When omitted, Application
        Default Credentials (workload identity, metadata server,
        ``GOOGLE_APPLICATION_CREDENTIALS``) are used.

    Raises
    ------
    sign.pgp.errors.ConfigurationError
        If the client library is missing, the configuration is incomplete,
        access is denied, or any keyid has no usable passphrase.
    """
    try:
        from google.api_core import exceptions as gcp_exceptions
        from google.cloud import secretmanager
    except ImportError as e:
        raise ConfigurationError(
            "google-cloud-secret-manager is not installed. "
            "Install with: pip install '.[gsm]'"
        ) from e

    if not project_id:
        raise ConfigurationError(
            "Google Secret Manager project ID must be provided "
            "(set gsm.project_id / SF_GSM_PROJECT_ID)"
        )

    logger.info(
        "Fetching GPG passphrases from Google Secret Manager "
        "(project %s) for %d keys",
        project_id,
        len(keyids),
    )

    if credentials_file:
        client = secretmanager.SecretManagerServiceClient\
            .from_service_account_file(credentials_file)
    else:
        client = secretmanager.SecretManagerServiceClient()

    result: Dict[str, str] = {}
    missing: List[str] = []
    for keyid in keyids:
        name = (
            f"projects/{project_id}/secrets/{secret_prefix}{keyid}"
            f"/versions/{secret_version}"
        )
        try:
            response = client.access_secret_version(name=name)
        except gcp_exceptions.NotFound:
            missing.append(keyid)
            continue
        except gcp_exceptions.PermissionDenied as e:
            # An IAM problem is a deployment error, not a missing key:
            # report it as-is instead of hiding it in the "missing" list.
            raise ConfigurationError(
                f"Access to Google Secret Manager secret {name!r} was "
                "denied. The service account needs the "
                "'roles/secretmanager.secretAccessor' role."
            ) from e
        except gcp_exceptions.GoogleAPICallError as e:
            raise ConfigurationError(
                f"Failed to read Google Secret Manager secret {name!r}: {e}"
            ) from e

        # Only strip the trailing newline a shell redirect may have added:
        # a passphrase is allowed to contain meaningful whitespace.
        passphrase = response.payload.data.decode("utf-8").rstrip("\n")
        if not passphrase:
            missing.append(keyid)
            continue
        result[keyid] = passphrase

    if missing:
        raise ConfigurationError(
            "Google Secret Manager is missing passphrases for keys: "
            + ", ".join(missing)
        )

    return result
