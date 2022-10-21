from email.policy import default
from pydantic import BaseSettings, Field

GPG_BINARY_DEFAULT = "/usr/bin/gpg2"
KEYRING_DEFAULT = "/home/alt/.gnupg/pubring.kbx"
MAX_UPLOAD_BYTES_DEFAULT = 100000000
PASS_DB_DEV_PASS_DEFAULT = ""
PASS_DB_DEV_MODE_DEFAULT = False
TMP_FILE_DIR_DEFAULT = "/tmp"
PGP_KEYS_ID_DEFAULT = ["EF0F6DF0AFE52FD5", ]
DB_URL_DEFAULT = "sqlite:///./sign-file.sqlite3"


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
    pgp_keys: list[str] = Field(default=PGP_KEYS_ID_DEFAULT,
                                description="list of keyIDs to use",
                                env="SF_PGP_KEYS_ID")

    class Config:
        case_sensitive = False
        env_file = '.env'


settings = Settings()
