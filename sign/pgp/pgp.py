import os
import aiofiles
from aiofiles.os import remove
from fastapi import UploadFile
import gnupg
import logging
import plumbum
import pexpect

from sign.config import settings
from sign.log import SysLog
from sign.pgp.pgp_password_db import PGPPasswordDB
from sign.pgp.helpers import restart_gpg_agent
from sign.errors import FileTooBigError
from sign.utils.hashing import get_hasher, hash_file
from sign.utils.locking import exclusive_lock


class PGP:
    def __init__(self,
                 keyring: str, gpg_binary: str,
                 pgp_keys: list[str],
                 max_upload_bytes: int,
                 pass_db_dev_mode: bool = False,
                 pass_db_dev_pass: str = None,
                 tmp_dir: str = '/tmp'):
        self.__gpg = gnupg.GPG(gpgbinary=gpg_binary,
                               keyring=keyring)
        self.__pass_db = PGPPasswordDB(
            self.__gpg, pgp_keys,
            pass_db_dev_mode, pass_db_dev_pass)
        self.max_upload_bytes = max_upload_bytes
        self.tmp_dir = tmp_dir
        self.__pass_db.ask_for_passwords()
        self.__syslog = SysLog(tag_name=settings.service)

    def list_keys(self):
        return self.__gpg.list_keys()

    def key_exists(self, keyid: str) -> bool:
        return keyid in self.__pass_db._PGPPasswordDB__keys.keys()

    async def sign(
        self,
        keyid: str,
        file: UploadFile,
        detach_sign: bool = True,
        digest_algo: str = 'SHA256',
    ):
        upload_size = 0
        async with aiofiles.tempfile.NamedTemporaryFile(
                'wb', delete=True, dir=self.tmp_dir) as fd:
            # writing content to temp file
            while content := await file.read(1024 * 1024):
                upload_size += len(content)
                if upload_size > self.max_upload_bytes:
                    raise FileTooBigError
                await fd.write(content)
                await fd.flush()
            file.file.close()

            hash_before = hash_file(
                fd.name,
                hasher=get_hasher(),
            )

            # signing tmp file with gpg binary
            # using pgp.sign_file() will result in wrong signature
            password = self.__pass_db.get_password(keyid)
            sign_cmd = plumbum.local[self.__gpg.gpgbinary][
                '--yes',
                '--pinentry-mode', 'loopback',
                '--digest-algo', digest_algo,
                '--detach-sign' if detach_sign else '--clear-sign',
                '--armor',
                '--default-key', keyid,
                fd.name
            ]
            with exclusive_lock(settings.gpg_locks_dir, keyid):
                out, status = pexpect.run(
                    command=' '.join(sign_cmd.formulate()),
                    events={"Enter passphrase:.*": "{0}\r".format(password)},
                    env={"LC_ALL": "en_US.UTF-8"},
                    timeout=1200,
                    withexitstatus=1,
                )
                restart_gpg_agent()
            hash_after = hash_file(
                fd.name,
                hasher=get_hasher(),
            )

            # it would be nice if we could know the platform too
            self.__syslog.sign_log(
                os.path.basename(fd.name),
                hash_before,
                hash_after,
                keyid,
            )
            if status != 0:
                message = f'gpg failed to sign file, error: {out}'
                logging.error(message)
                raise Exception(message)

        # reading PGP signature
        async with aiofiles.open(f'{fd.name}.asc', 'r') as fl:
            answer = await fl.read()
        await remove(f'{fd.name}.asc')

        return answer
