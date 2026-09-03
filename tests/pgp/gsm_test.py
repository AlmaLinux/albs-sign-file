import sys
import types
from unittest.mock import MagicMock

import pytest

from sign.pgp.errors import ConfigurationError

KEY_A = "AAAA1111BBBB2222"
KEY_B = "CCCC3333DDDD4444"
PROJECT = "almalinux-signing"


class FakeGoogleAPICallError(Exception):
    pass


class FakeNotFound(FakeGoogleAPICallError):
    pass


class FakePermissionDenied(FakeGoogleAPICallError):
    pass


def _payload(value: str):
    """Build the minimal shape of an AccessSecretVersionResponse."""
    return types.SimpleNamespace(
        payload=types.SimpleNamespace(data=value.encode("utf-8"))
    )


@pytest.fixture
def fake_gsm(monkeypatch):
    """Install stub `google.cloud.secretmanager` / `google.api_core` modules.

    Mirrors the real layout closely enough for the deferred imports inside
    ``fetch_passphrases`` to resolve without the client library installed.
    """
    google = types.ModuleType("google")
    cloud = types.ModuleType("google.cloud")
    secretmanager = types.ModuleType("google.cloud.secretmanager")
    api_core = types.ModuleType("google.api_core")
    gcp_exceptions = types.ModuleType("google.api_core.exceptions")

    gcp_exceptions.NotFound = FakeNotFound
    gcp_exceptions.PermissionDenied = FakePermissionDenied
    gcp_exceptions.GoogleAPICallError = FakeGoogleAPICallError

    secretmanager.SecretManagerServiceClient = MagicMock()
    api_core.exceptions = gcp_exceptions
    cloud.secretmanager = secretmanager
    google.cloud = cloud
    google.api_core = api_core

    for name, module in (
        ("google", google),
        ("google.cloud", cloud),
        ("google.cloud.secretmanager", secretmanager),
        ("google.api_core", api_core),
        ("google.api_core.exceptions", gcp_exceptions),
    ):
        monkeypatch.setitem(sys.modules, name, module)

    yield secretmanager


def _import_fetcher():
    # Import after the stubs are in place so the deferred imports inside the
    # function pick up the fake modules.
    from sign.pgp.gsm import fetch_passphrases
    return fetch_passphrases


def _client(fake_gsm):
    return fake_gsm.SecretManagerServiceClient.return_value


def test_fetch_passphrases_returns_keyid_map(fake_gsm):
    secrets = {
        f"projects/{PROJECT}/secrets/{KEY_A}/versions/latest": "secret-a",
        f"projects/{PROJECT}/secrets/{KEY_B}/versions/latest": "secret-b",
    }
    _client(fake_gsm).access_secret_version.side_effect = (
        lambda name: _payload(secrets[name])
    )

    fetch_passphrases = _import_fetcher()
    result = fetch_passphrases(keyids=[KEY_A, KEY_B], project_id=PROJECT)

    assert result == {KEY_A: "secret-a", KEY_B: "secret-b"}


def test_fetch_passphrases_honours_prefix_and_version(fake_gsm):
    name = f"projects/{PROJECT}/secrets/gpg-{KEY_A}/versions/3"
    _client(fake_gsm).access_secret_version.return_value = _payload("x")

    fetch_passphrases = _import_fetcher()
    fetch_passphrases(
        keyids=[KEY_A],
        project_id=PROJECT,
        secret_prefix="gpg-",
        secret_version="3",
    )

    _client(fake_gsm).access_secret_version.assert_called_once_with(name=name)


def test_fetch_passphrases_uses_service_account_file(fake_gsm):
    factory = fake_gsm.SecretManagerServiceClient.from_service_account_file
    factory.return_value.access_secret_version.return_value = _payload("x")

    fetch_passphrases = _import_fetcher()
    fetch_passphrases(
        keyids=[KEY_A],
        project_id=PROJECT,
        credentials_file="/run/secrets/gsm.json",
    )

    factory.assert_called_once_with("/run/secrets/gsm.json")
    fake_gsm.SecretManagerServiceClient.assert_not_called()


def test_fetch_passphrases_strips_only_trailing_newline(fake_gsm):
    _client(fake_gsm).access_secret_version.return_value = _payload(
        " pass phrase \n"
    )

    fetch_passphrases = _import_fetcher()
    result = fetch_passphrases(keyids=[KEY_A], project_id=PROJECT)

    assert result == {KEY_A: " pass phrase "}


def test_fetch_passphrases_requires_project_id(fake_gsm):
    fetch_passphrases = _import_fetcher()
    with pytest.raises(ConfigurationError, match="project ID"):
        fetch_passphrases(keyids=[KEY_A])
    fake_gsm.SecretManagerServiceClient.assert_not_called()


def test_fetch_passphrases_missing_secret_raises(fake_gsm):
    def _access(name):
        if KEY_B in name:
            raise FakeNotFound("nope")
        return _payload("secret-a")

    _client(fake_gsm).access_secret_version.side_effect = _access

    fetch_passphrases = _import_fetcher()
    with pytest.raises(ConfigurationError, match=KEY_B):
        fetch_passphrases(keyids=[KEY_A, KEY_B], project_id=PROJECT)


def test_fetch_passphrases_empty_passphrase_treated_as_missing(fake_gsm):
    _client(fake_gsm).access_secret_version.return_value = _payload("\n")

    fetch_passphrases = _import_fetcher()
    with pytest.raises(ConfigurationError, match=KEY_A):
        fetch_passphrases(keyids=[KEY_A], project_id=PROJECT)


def test_fetch_passphrases_permission_denied_is_reported_as_such(fake_gsm):
    _client(fake_gsm).access_secret_version.side_effect = (
        FakePermissionDenied("denied")
    )

    fetch_passphrases = _import_fetcher()
    with pytest.raises(ConfigurationError, match="secretAccessor"):
        fetch_passphrases(keyids=[KEY_A], project_id=PROJECT)


def test_fetch_passphrases_api_error_is_wrapped(fake_gsm):
    _client(fake_gsm).access_secret_version.side_effect = (
        FakeGoogleAPICallError("boom")
    )

    fetch_passphrases = _import_fetcher()
    with pytest.raises(ConfigurationError, match="Failed to read"):
        fetch_passphrases(keyids=[KEY_A], project_id=PROJECT)


def test_fetch_passphrases_without_client_library(monkeypatch):
    # Block both the client and the exceptions module the fetcher imports.
    monkeypatch.setitem(sys.modules, "google.cloud.secretmanager", None)
    monkeypatch.setitem(sys.modules, "google.api_core.exceptions", None)

    from sign.pgp.gsm import fetch_passphrases
    with pytest.raises(ConfigurationError, match="google-cloud-secret-manager"):
        fetch_passphrases(keyids=[KEY_A], project_id=PROJECT)
