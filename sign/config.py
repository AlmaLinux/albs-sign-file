import os

from pydantic import BaseSettings, Field

GPG_BINARY_DEFAULT = "/usr/bin/gpg2"
KEYRING_DEFAULT = os.path.abspath(os.path.expanduser("~/.gnupg/pubring.kbx"))
MAX_UPLOAD_BYTES_DEFAULT = 100000000
PASS_DB_DEV_PASS_DEFAULT = ""
PASS_DB_DEV_MODE_DEFAULT = False
TMP_FILE_DIR_DEFAULT = "/tmp"
DB_URL_DEFAULT = "sqlite:///./sign-file.sqlite3"
# For PostgreSQL use: postgresql://user:password@host:port/dbname
# Example: postgresql://signfile:signfile@localhost:5432/signfile
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


class Settings(BaseSettings):
    gpg_binary: str = Field(
        default=GPG_BINARY_DEFAULT,
        description="path to GNU binary",
        env="SF_GPG_BINARY",
    )
    keyring: str = Field(
        default=KEYRING_DEFAULT,
        description="path to PGP keyring database",
        env="SF_KEYRING",
    )
    max_upload_bytes: int = Field(
        default=MAX_UPLOAD_BYTES_DEFAULT,
        description="max size in bytes for file to sign",
        env="SF_MAX_UPLOAD_BYTES",
    )
    pass_db_dev_mode: bool = Field(
        default=PASS_DB_DEV_MODE_DEFAULT,
        env="SF_PASS_DB_DEV_MODE",
    )
    pass_db_dev_pass: str = Field(
        default=PASS_DB_DEV_PASS_DEFAULT,
        env="SF_PASS_DB_DEV_PASS",
    )
    tmp_dir: str = Field(
        default=TMP_FILE_DIR_DEFAULT,
        description="dir to store temp files",
        env="SF_TMP_FILE_DIR",
    )
    pgp_keys: list[str] = Field(
        description="list of keyIDs to use",
        env="SF_PGP_KEYS_ID",
    )
    db_url: str = Field(
        default=DB_URL_DEFAULT,
        description="database url",
        env="SF_DB_URL",
    )
    db_pool_size: int = Field(
        default=DB_POOL_SIZE_DEFAULT,
        description="database connection pool size (PostgreSQL only)",
        env="SF_DB_POOL_SIZE",
    )
    db_max_overflow: int = Field(
        default=DB_MAX_OVERFLOW_DEFAULT,
        description="max overflow connections beyond pool_size (PostgreSQL only)",
        env="SF_DB_MAX_OVERFLOW",
    )
    db_pool_recycle: int = Field(
        default=DB_POOL_RECYCLE_DEFAULT,
        description="recycle connections after N seconds (PostgreSQL only)",
        env="SF_DB_POOL_RECYCLE",
    )
    db_pool_pre_ping: bool = Field(
        default=DB_POOL_PRE_PING_DEFAULT,
        description="enable connection health checks (PostgreSQL only)",
        env="SF_DB_POOL_PRE_PING",
    )
    db_echo: bool = Field(
        default=DB_ECHO_DEFAULT,
        description="enable SQL query logging",
        env="SF_DB_ECHO",
    )
    jwt_secret_key: str = Field(
        description="secret key to use for JWT access token generation",
        env="SF_JWT_SECRET_KEY",
    )
    jwt_expire_minutes: int = Field(
        default=JWT_EXPIRE_MINUTES_DEFAULT,
        description="expiration time (in minutes) for JWT access token",
        env="SF_JWT_EXPIRE_MINUTES",
    )
    jwt_algoritm: str = Field(
        default=JWT_ALGORITHM_DEFAULT,
        description="hash aloritm to use in JWT",
        env="SF_JWT_ALGORITHM",
    )
    root_url: str = Field(
        default=ROOT_URL_DEFAULT,
        description="root url for api calls",
        env="SF_ROOT_URL",
    )
    service: str = Field(
        default=SERVICE_DEFAULT,
        description="name of the service that will use sign-file",
        env="TARGET_SERVICE",
    )
    sentry_dsn: str = Field(
        default=SENTRY_DSN,
        description="client key to send build data to Sentry",
        env="SF_SENTRY_DSN",
    )
    sentry_traces_sample_rate: float = Field(
        default=SENTRY_TRACES_SAMPLE_RATE,
        description="percent of captured transactions for tracing (from 0.0 to 1.0)",
        env="SF_SENTRY_TRACES_SAMPLE_RATE",
    )
    sentry_environment: str = Field(
        default=SENTRY_ENV,
        description="filtering tag",
        env="SF_SENTRY_ENV",
    )
    gpg_locks_dir: str = Field(
        default=GPG_LOCKS_DIR,
        description="directory to store locks for gpg",
        env="SF_GPG_LOCKS_DIR",
    )

    class Config:
        case_sensitive = False
        env_file = '.env'


settings = Settings()
