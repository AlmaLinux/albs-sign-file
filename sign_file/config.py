from pydantic import BaseSettings

GPG_BINARY_DEFAULT = "/usr/local/MacGPG2/bin/gpg2"
KEYRING_DEFAULT = "/Users/kzhukov/.gnupg/pubring.kbx"
MAX_UPLOAD_BYTES_DEFAULT = 100000000
PASS_DB_DEV_PASS_DEFAULT = ""
PASS_DB_DEV_MODE_DEFAULT = False
TMP_FILE_DIR_DEFAULT = "/tmp"
PGP_KEYS_ID_DEFAULT = ["EF0F6DF0AFE52FD5", ]


class Settings(BaseSettings):

    gpg_binary: str = GPG_BINARY_DEFAULT
    keyring: str = KEYRING_DEFAULT
    max_upload_bytes = MAX_UPLOAD_BYTES_DEFAULT
    pass_db_dev_pass: str = PASS_DB_DEV_PASS_DEFAULT
    pass_db_dev_mode: bool = False
    tmp_dir: str = TMP_FILE_DIR_DEFAULT
    pgp_keys: list[str] = PGP_KEYS_ID_DEFAULT


settings = Settings()
