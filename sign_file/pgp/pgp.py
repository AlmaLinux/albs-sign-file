from .pgp_password_db import PGPPasswordDB
from .helpers import init_gpg

class PGP():
    def __init__(self, 
        keyring: str, gpg_binary: str,
        pgp_keys: list[str], 
        pass_db_dev_mode: bool = False,
        pass_db_dev_pass: str = None):
        self.__gpg = init_gpg(keyring=keyring,
                             gpg_binary=gpg_binary)
        self.__pass_db = PGPPasswordDB(
            self.__gpg, pgp_keys, 
            pass_db_dev_mode, pass_db_dev_pass)
        self.__pass_db.ask_for_passwords()
    
    def list_keys(self):
        return self.__gpg.list_keys()


    def sign(self, keyid: str, fpath: str) -> str:
        password = self.__pass_db.get_password(keyid)
        with open(fpath, 'r') as fl:
            result = self.__gpg.sign_file(
                file=fl, keyid=keyid, passphrase=password)
        return result    