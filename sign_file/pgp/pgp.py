from .pgp_password_db import PGPPasswordDB
import gnupg


class PGP():
    def __init__(self,
                 keyring: str, gpg_binary: str,
                 pgp_keys: list[str],
                 pass_db_dev_mode: bool = False,
                 pass_db_dev_pass: str = None):
        self.__gpg = gnupg.GPG(gpgbinary=gpg_binary,
                               keyring=keyring)
        self.__pass_db = PGPPasswordDB(
            self.__gpg, pgp_keys,
            pass_db_dev_mode, pass_db_dev_pass)
        self.__pass_db.ask_for_passwords()

    def list_keys(self):
        return self.__gpg.list_keys()

    def sign(self, keyid: str, fpath: str):
        password = self.__pass_db.get_password(keyid)
        res = self.__gpg.sign_file(
            fpath, keyid, passphrase=password, detach=True)
        return res
