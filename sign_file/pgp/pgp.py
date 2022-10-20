from .pgp_password_db import PGPPasswordDB
import gnupg
import logging
import plumbum
import pexpect
import aiofiles
from aiofiles.os import remove


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

    async def sign(self, keyid: str, fpath: str) -> gnupg.Sign:
        password = self.__pass_db.get_password(keyid)
        # using gpg.sign_file() will result in wrong PGP signature
        # https://stackoverflow.com/questions/52065521/python-gnupg-sign-verify-a-tar-archive
        sign_cmd = plumbum.local['gpg'][
            '--yes', '--detach-sign', '--armor',
            '--default-key', keyid, fpath]
        out, status = pexpect.run(
            command=' '.join(sign_cmd.formulate()),
            events={"Enter passphrase:.*": "{0}\r".format(password)},
            env={"LC_ALL": "en_US.UTF-8"},
            timeout=1200,
            withexitstatus=1,
        )
        if status != 0:
            message = f'gpg failed to sign file, error: {out}'
            logging.error(message)
            raise Exception(message)

        async with aiofiles.open(f"{fpath}.asc") as fl:
            contents = await fl.read()
        await remove(f"{fpath}.asc")

        return contents
