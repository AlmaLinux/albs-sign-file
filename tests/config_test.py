import pytest

from sign.config import Settings, create_settings


def test_no_secret_provider_enabled_by_default():
    assert Settings().get_secret_provider() is None


def test_single_provider_is_returned():
    assert Settings(bitwarden_enabled=True).get_secret_provider() == 'bitwarden'
    assert Settings(gsm_enabled=True).get_secret_provider() == 'gsm'


def test_two_providers_are_rejected():
    settings = Settings(bitwarden_enabled=True, gsm_enabled=True)

    assert settings.enabled_secret_providers() == ['bitwarden', 'gsm']
    with pytest.raises(ValueError, match="Only one GPG passphrase provider"):
        settings.get_secret_provider()


def test_create_settings_rejects_two_providers(monkeypatch):
    monkeypatch.setenv('SF_DB_URL', 'sqlite:///:memory:')
    monkeypatch.setenv('SF_BITWARDEN_ENABLED', 'True')
    monkeypatch.setenv('SF_GSM_ENABLED', 'True')

    with pytest.raises(ValueError, match="Only one GPG passphrase provider"):
        create_settings()


def test_create_settings_accepts_one_provider(monkeypatch):
    monkeypatch.setenv('SF_DB_URL', 'sqlite:///:memory:')
    monkeypatch.setenv('SF_GSM_ENABLED', 'True')
    monkeypatch.setenv('SF_GSM_PROJECT_ID', 'almalinux-signing')

    settings = create_settings()

    assert settings.get_secret_provider() == 'gsm'
    assert settings.gsm_project_id == 'almalinux-signing'
