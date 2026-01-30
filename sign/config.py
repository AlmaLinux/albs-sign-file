import logging
import os
from typing import Dict, List, Optional

from pydantic import BaseSettings, Field

logger = logging.getLogger(__name__)

GPG_BINARY_DEFAULT = "/usr/bin/gpg2"
KEYRING_DEFAULT = os.path.abspath(os.path.expanduser("~/.gnupg/pubring.kbx"))
MAX_UPLOAD_BYTES_DEFAULT = 100000000
PASS_DB_DEV_PASS_DEFAULT = ""
PASS_DB_DEV_MODE_DEFAULT = False
TMP_FILE_DIR_DEFAULT = "/tmp"
DB_URL_DEFAULT = "sqlite:///./sign-file.sqlite3"
JWT_EXPIRE_MINUTES_DEFAULT = 30
JWT_ALGORITHM_DEFAULT = "HS256"
ROOT_URL_DEFAULT = ''
SERVICE_DEFAULT = 'albs-sign-service'
SENTRY_DSN = ''
SENTRY_TRACES_SAMPLE_RATE = 0.2
SENTRY_ENV = 'dev'
GPG_LOCKS_DIR = '/tmp/gpg_locks'
DB_POOL_SIZE_DEFAULT = 5
DB_MAX_OVERFLOW_DEFAULT = 10
DB_POOL_RECYCLE_DEFAULT = 3600
DB_POOL_PRE_PING_DEFAULT = True
DB_ECHO_DEFAULT = False
SIGNING_BACKEND_DEFAULT = "gpg"
KMS_SIGNING_ALGORITHM_DEFAULT = "RSASSA_PKCS1_V1_5_SHA_256"
KMS_MAX_WORKERS_DEFAULT = 10
CONFIG_FILE_DEFAULT = "/etc/sign-file/config.yaml"


def load_yaml_config(config_path: str) -> dict:
    """Load configuration from YAML file."""
    try:
        import yaml
    except ImportError:
        logger.warning("PyYAML not installed, skipping config file")
        return {}

    path = os.path.expanduser(config_path)
    if not os.path.exists(path):
        logger.debug("Config file not found: %s", path)
        return {}

    try:
        with open(path) as f:
            data = yaml.safe_load(f)
            return data if data else {}
    except Exception as e:
        logger.error("Failed to load config file %s: %s", path, e)
        return {}


class Settings(BaseSettings):
    gpg_binary: str = Field(
        default=GPG_BINARY_DEFAULT,
        description="path to GPG binary",
    )
    keyring: str = Field(
        default=KEYRING_DEFAULT,
        description="path to PGP keyring database",
    )
    max_upload_bytes: int = Field(
        default=MAX_UPLOAD_BYTES_DEFAULT,
        description="max size in bytes for file to sign",
    )
    pass_db_dev_mode: bool = Field(
        default=PASS_DB_DEV_MODE_DEFAULT,
    )
    pass_db_dev_pass: str = Field(
        default=PASS_DB_DEV_PASS_DEFAULT,
    )
    tmp_dir: str = Field(
        default=TMP_FILE_DIR_DEFAULT,
        description="dir to store temp files",
    )
    pgp_keys: List[str] = Field(
        default=[],
        description="list of GPG key IDs to use",
    )
    db_url: str = Field(
        default=DB_URL_DEFAULT,
        description="database url",
    )
    db_pool_size: int = Field(
        default=DB_POOL_SIZE_DEFAULT,
        description="database connection pool size (PostgreSQL only)",
    )
    db_max_overflow: int = Field(
        default=DB_MAX_OVERFLOW_DEFAULT,
        description="max overflow connections beyond pool_size",
    )
    db_pool_recycle: int = Field(
        default=DB_POOL_RECYCLE_DEFAULT,
        description="recycle connections after N seconds",
    )
    db_pool_pre_ping: bool = Field(
        default=DB_POOL_PRE_PING_DEFAULT,
        description="enable connection health checks",
    )
    db_echo: bool = Field(
        default=DB_ECHO_DEFAULT,
        description="enable SQL query logging",
    )
    jwt_secret_key: str = Field(
        default="",
        description="secret key for JWT access token generation",
    )
    jwt_expire_minutes: int = Field(
        default=JWT_EXPIRE_MINUTES_DEFAULT,
        description="expiration time (in minutes) for JWT access token",
    )
    jwt_algoritm: str = Field(
        default=JWT_ALGORITHM_DEFAULT,
        description="hash algorithm to use in JWT",
    )
    root_url: str = Field(
        default=ROOT_URL_DEFAULT,
        description="root url for api calls",
    )
    service: str = Field(
        default=SERVICE_DEFAULT,
        description="name of the service that will use sign-file",
    )
    sentry_dsn: str = Field(
        default=SENTRY_DSN,
        description="client key to send build data to Sentry",
    )
    sentry_traces_sample_rate: float = Field(
        default=SENTRY_TRACES_SAMPLE_RATE,
        description="percent of captured transactions for tracing",
    )
    sentry_environment: str = Field(
        default=SENTRY_ENV,
        description="filtering tag",
    )
    gpg_locks_dir: str = Field(
        default=GPG_LOCKS_DIR,
        description="directory to store locks for gpg",
    )
    signing_backend: str = Field(
        default=SIGNING_BACKEND_DEFAULT,
        description="signing backend to use: 'gpg' or 'kms'",
    )
    kms_access_key_id: Optional[str] = Field(
        default=None,
        description="AWS access key ID for KMS",
    )
    kms_secret_access_key: Optional[str] = Field(
        default=None,
        description="AWS secret access key for KMS",
    )
    kms_region: Optional[str] = Field(
        default=None,
        description="AWS region for KMS",
    )
    kms_signing_algorithm: str = Field(
        default=KMS_SIGNING_ALGORITHM_DEFAULT,
        description="KMS signing algorithm",
    )
    kms_max_workers: int = Field(
        default=KMS_MAX_WORKERS_DEFAULT,
        description="max concurrent KMS signing operations",
    )
    kms_keys: List[dict] = Field(
        default=[],
        description="list of KMS keys with kms_id and gpg_fingerprint",
    )

    def get_kms_key_ids(self) -> List[str]:
        """Get list of KMS key IDs from config."""
        return [k['kms_id'] for k in self.kms_keys if 'kms_id' in k]

    def get_kms_gpg_fingerprints(self) -> Dict[str, str]:
        """Get mapping of KMS key ID to GPG fingerprint."""
        return {
            k['kms_id']: k['gpg_fingerprint']
            for k in self.kms_keys
            if 'kms_id' in k and 'gpg_fingerprint' in k
        }

    class Config:
        case_sensitive = False


def create_settings() -> Settings:
    """
    Create Settings from YAML config file with env var overrides.

    Priority (highest to lowest):
    1. Environment variables (SF_* prefix)
    2. YAML config file
    3. Default values
    """
    config_file = os.environ.get('SF_CONFIG_FILE', CONFIG_FILE_DEFAULT)
    yaml_config = load_yaml_config(config_file)

    flat_config = {}

    if 'gpg' in yaml_config:
        gpg = yaml_config['gpg']
        if 'binary' in gpg:
            flat_config['gpg_binary'] = gpg['binary']
        if 'keyring' in gpg:
            flat_config['keyring'] = gpg['keyring']
        if 'locks_dir' in gpg:
            flat_config['gpg_locks_dir'] = gpg['locks_dir']
        if 'keys' in gpg:
            flat_config['pgp_keys'] = gpg['keys']

    if 'database' in yaml_config:
        db = yaml_config['database']
        if 'url' in db:
            flat_config['db_url'] = db['url']
        if 'pool_size' in db:
            flat_config['db_pool_size'] = db['pool_size']
        if 'max_overflow' in db:
            flat_config['db_max_overflow'] = db['max_overflow']
        if 'pool_recycle' in db:
            flat_config['db_pool_recycle'] = db['pool_recycle']
        if 'pool_pre_ping' in db:
            flat_config['db_pool_pre_ping'] = db['pool_pre_ping']
        if 'echo' in db:
            flat_config['db_echo'] = db['echo']

    if 'jwt' in yaml_config:
        jwt = yaml_config['jwt']
        if 'secret_key' in jwt:
            flat_config['jwt_secret_key'] = jwt['secret_key']
        if 'expire_minutes' in jwt:
            flat_config['jwt_expire_minutes'] = jwt['expire_minutes']
        if 'algorithm' in jwt:
            flat_config['jwt_algoritm'] = jwt['algorithm']

    if 'sentry' in yaml_config:
        sentry = yaml_config['sentry']
        if 'dsn' in sentry:
            flat_config['sentry_dsn'] = sentry['dsn']
        if 'traces_sample_rate' in sentry:
            flat_config['sentry_traces_sample_rate'] = sentry['traces_sample_rate']
        if 'environment' in sentry:
            flat_config['sentry_environment'] = sentry['environment']

    if 'signing_backend' in yaml_config:
        flat_config['signing_backend'] = yaml_config['signing_backend']

    if 'kms' in yaml_config:
        kms = yaml_config['kms']
        if 'access_key_id' in kms:
            flat_config['kms_access_key_id'] = kms['access_key_id']
        if 'secret_access_key' in kms:
            flat_config['kms_secret_access_key'] = kms['secret_access_key']
        if 'region' in kms:
            flat_config['kms_region'] = kms['region']
        if 'signing_algorithm' in kms:
            flat_config['kms_signing_algorithm'] = kms['signing_algorithm']
        if 'max_workers' in kms:
            flat_config['kms_max_workers'] = kms['max_workers']
        if 'keys' in kms:
            flat_config['kms_keys'] = kms['keys']

    if 'max_upload_bytes' in yaml_config:
        flat_config['max_upload_bytes'] = yaml_config['max_upload_bytes']
    if 'tmp_dir' in yaml_config:
        flat_config['tmp_dir'] = yaml_config['tmp_dir']
    if 'root_url' in yaml_config:
        flat_config['root_url'] = yaml_config['root_url']
    if 'service' in yaml_config:
        flat_config['service'] = yaml_config['service']

    env_mapping = {
        'SF_GPG_BINARY': 'gpg_binary',
        'SF_KEYRING': 'keyring',
        'SF_GPG_LOCKS_DIR': 'gpg_locks_dir',
        'SF_MAX_UPLOAD_BYTES': 'max_upload_bytes',
        'SF_TMP_FILE_DIR': 'tmp_dir',
        'SF_DB_URL': 'db_url',
        'SF_DB_POOL_SIZE': 'db_pool_size',
        'SF_DB_MAX_OVERFLOW': 'db_max_overflow',
        'SF_DB_POOL_RECYCLE': 'db_pool_recycle',
        'SF_DB_POOL_PRE_PING': 'db_pool_pre_ping',
        'SF_DB_ECHO': 'db_echo',
        'SF_JWT_SECRET_KEY': 'jwt_secret_key',
        'SF_JWT_EXPIRE_MINUTES': 'jwt_expire_minutes',
        'SF_JWT_ALGORITHM': 'jwt_algoritm',
        'SF_ROOT_URL': 'root_url',
        'TARGET_SERVICE': 'service',
        'SF_SENTRY_DSN': 'sentry_dsn',
        'SF_SENTRY_TRACES_SAMPLE_RATE': 'sentry_traces_sample_rate',
        'SF_SENTRY_ENV': 'sentry_environment',
        'SF_SIGNING_BACKEND': 'signing_backend',
        'SF_KMS_ACCESS_KEY_ID': 'kms_access_key_id',
        'SF_KMS_SECRET_ACCESS_KEY': 'kms_secret_access_key',
        'SF_KMS_REGION': 'kms_region',
        'SF_KMS_SIGNING_ALGORITHM': 'kms_signing_algorithm',
        'SF_KMS_MAX_WORKERS': 'kms_max_workers',
        'SF_PASS_DB_DEV_MODE': 'pass_db_dev_mode',
        'SF_PASS_DB_DEV_PASS': 'pass_db_dev_pass',
    }

    for env_var, field_name in env_mapping.items():
        if env_var in os.environ:
            flat_config[field_name] = os.environ[env_var]

    return Settings(**flat_config)


settings = create_settings()
