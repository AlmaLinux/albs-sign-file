import aiofiles
from aiofiles.os import remove
from fastapi import UploadFile
import logging
import plumbum
import pexpect
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

    def key_exists(self, keyid: str) -> bool:
        return keyid in self.__pass_db.__keys.keys()

    async def sign(self, keyid: str, file: UploadFile):
        password = self.__pass_db.get_password(keyid)
        async with aiofiles.tempfile.NamedTemporaryFile(
                'w', delete=True) as fd:
            content = await file.read()
            await fd.write(content.decode(encoding="utf-8"))
            await fd.flush()
            # using pgp.sign_file() will result in wrong signature
            sign_cmd = plumbum.local['gpg'][
                '--yes', '--detach-sign', '--armor',
                '--default-key', keyid, fd.name
            ]
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
        async with aiofiles.open(f'{fd.name}.asc', 'r') as fl:
            answer = await fl.read()
        await remove(f'{fd.name}.asc')
        return answer
