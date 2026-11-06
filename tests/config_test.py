import pytest

from sign.config import create_settings

KMS_YAML = """
signing_backend: kms
kms:
  rpm_signer_binary: /opt/yaml/sign-file-rpm-signer
  keys:
    - kms_id: alias/rpm
      gpg_fingerprint: AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555
"""


@pytest.fixture
def config_file(tmp_path, monkeypatch):
    path = tmp_path / 'config.yaml'
    path.write_text(KMS_YAML)
    monkeypatch.setenv('SF_CONFIG_FILE', str(path))
    monkeypatch.delenv('SF_KMS_RPM_SIGNER_BINARY', raising=False)
    return path


def test_rpm_signer_binary_defaults_to_the_console_script(
    tmp_path, monkeypatch
):
    path = tmp_path / 'config.yaml'
    path.write_text('signing_backend: kms\n')
    monkeypatch.setenv('SF_CONFIG_FILE', str(path))
    monkeypatch.delenv('SF_KMS_RPM_SIGNER_BINARY', raising=False)

    assert create_settings().kms_rpm_signer_binary == 'sign-file-rpm-signer'


def test_rpm_signer_binary_from_yaml(config_file):
    settings = create_settings()

    assert settings.kms_rpm_signer_binary == '/opt/yaml/sign-file-rpm-signer'


def test_rpm_signer_binary_env_overrides_yaml(config_file, monkeypatch):
    monkeypatch.setenv('SF_KMS_RPM_SIGNER_BINARY', '/opt/env/signer')

    assert create_settings().kms_rpm_signer_binary == '/opt/env/signer'
