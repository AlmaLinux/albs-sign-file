from types import SimpleNamespace

import pytest

from sign.pgp import secrets
from sign.pgp.errors import ConfigurationError

KEY_A = "AAAA1111BBBB2222"


def make_settings(**overrides):
    settings = SimpleNamespace(
        pgp_keys=[KEY_A],
        bitwarden_enabled=False,
        bitwarden_username=None,
        bitwarden_password=None,
        bitwarden_password_file=None,
        bitwarden_collection_id=None,
        vault_enabled=False,
        vault_addr=None,
        vault_token=None,
        vault_token_file=None,
        vault_role_id=None,
        vault_secret_id=None,
        vault_secret_id_file=None,
        vault_namespace=None,
        vault_mount="secret",
        vault_path_prefix="",
        vault_passphrase_field="passphrase",
        vault_ca_cert=None,
    )
    for key, value in overrides.items():
        setattr(settings, key, value)
    return settings


def test_no_provider_returns_none():
    assert secrets.resolve_passphrases(make_settings()) is None


def test_both_providers_enabled_raises():
    settings = make_settings(bitwarden_enabled=True, vault_enabled=True)
    with pytest.raises(ConfigurationError, match="Only one secret provider"):
        secrets.resolve_passphrases(settings)


def test_vault_provider_receives_settings(monkeypatch):
    captured = {}

    def fake_fetch(**kwargs):
        captured.update(kwargs)
        return {KEY_A: "from-vault"}

    monkeypatch.setattr(
        "sign.pgp.vault.fetch_passphrases", fake_fetch, raising=True
    )
    settings = make_settings(
        vault_enabled=True,
        vault_addr="https://vault.example.com:8200",
        vault_token_file="/run/secrets/vault_token",
        vault_path_prefix="albs/sign-keys",
    )

    assert secrets.resolve_passphrases(settings) == {KEY_A: "from-vault"}
    assert captured["keyids"] == [KEY_A]
    assert captured["addr"] == "https://vault.example.com:8200"
    assert captured["token_file"] == "/run/secrets/vault_token"
    assert captured["path_prefix"] == "albs/sign-keys"
    assert captured["field"] == "passphrase"


def test_bitwarden_provider_receives_settings(monkeypatch):
    captured = {}

    def fake_fetch(**kwargs):
        captured.update(kwargs)
        return {KEY_A: "from-bw"}

    monkeypatch.setattr(
        "sign.pgp.bitwarden.fetch_passphrases", fake_fetch, raising=True
    )
    settings = make_settings(
        bitwarden_enabled=True,
        bitwarden_username="signer@example.com",
        bitwarden_password_file="/run/secrets/bw_master",
    )

    assert secrets.resolve_passphrases(settings) == {KEY_A: "from-bw"}
    assert captured["keyids"] == [KEY_A]
    assert captured["username"] == "signer@example.com"
    assert captured["password_file"] == "/run/secrets/bw_master"


def test_enabled_providers_lists_only_active():
    assert secrets.enabled_providers(make_settings()) == []
    assert secrets.enabled_providers(make_settings(vault_enabled=True)) == [
        "vault"
    ]
    assert secrets.enabled_providers(
        make_settings(bitwarden_enabled=True, vault_enabled=True)
    ) == ["bitwarden", "vault"]


def test_provider_error_propagates(monkeypatch):
    def boom(**kwargs):
        raise ConfigurationError("vault is sealed")

    monkeypatch.setattr("sign.pgp.vault.fetch_passphrases", boom, raising=True)
    with pytest.raises(ConfigurationError, match="sealed"):
        secrets.resolve_passphrases(make_settings(vault_enabled=True))
