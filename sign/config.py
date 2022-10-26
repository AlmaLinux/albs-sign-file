from email.policy import default
from pydantic import BaseSettings, Field
from sqlalchemy import desc

GPG_BINARY_DEFAULT = "/usr/bin/gpg2"
KEYRING_DEFAULT = "/home/alt/.gnupg/pubring.kbx"
MAX_UPLOAD_BYTES_DEFAULT = 100000000
PASS_DB_DEV_PASS_DEFAULT = ""
PASS_DB_DEV_MODE_DEFAULT = False
TMP_FILE_DIR_DEFAULT = "/tmp"
DB_URL_DEFAULT = "sqlite:///./sign-file.sqlite3"
JWT_EXPIRE_MINUTES_DEFAULT = 30
JWT_ALGORITHM_DEFAULT = "HS256"


class Settings(BaseSettings):
    gpg_binary: str = Field(default=GPG_BINARY_DEFAULT,
                            description="path to GNU binary",
                            env="SF_GPG_BINARY")
    keyring: str = Field(default=KEYRING_DEFAULT,
                         description="path to PGP keyring database",
                         env="SF_KEYRING")
    max_upload_bytes = Field(default=MAX_UPLOAD_BYTES_DEFAULT,
                             description="max size in bytes for file to sign",
                             env="SF_SMAX_UPLOAD_BYTES")
    pass_db_dev_mode: bool = Field(default=PASS_DB_DEV_MODE_DEFAULT,
                                   env="SF_PASS_DB_DEV_MODE")
    pass_db_dev_pass: str = Field(default=PASS_DB_DEV_PASS_DEFAULT,
                                  env="SF_PASS_DB_DEV_PASS")
    tmp_dir: str = Field(default=TMP_FILE_DIR_DEFAULT,
                         description="dir to store temp files",
                         env="SF_TMP_FILE_DIR")
    pgp_keys: list[str] = Field(description="list of keyIDs to use",
                                env="SF_PGP_KEYS_ID")
    db_url: str = \
        Field(default=DB_URL_DEFAULT, description="database url",
              env="SF_DB_URL")
    jwt_secret_key: str = \
        Field(description="secret key to use for JWT access token generation",
              env="SF_JWT_SECRET_KEY")
    jwt_expire_minutes: int = \
        Field(default=JWT_EXPIRE_MINUTES_DEFAULT,
              description="expiration time (in minutes) for JWT access token",
              env="SF_JWT_EXPIRE_MINUTES")
    jwt_algoritm: str = \
        Field(default=JWT_ALGORITHM_DEFAULT,
              description="hash aloritm to use in JWT",
              env="SF_JWT_ALGORITHM")

    class Config:
        case_sensitive = False
        env_file = '.env'

settings = Settings()
