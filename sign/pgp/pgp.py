import asyncio
import logging
import os
from typing import List, Tuple

import aiofiles
import gnupg
import pexpect
import plumbum
from aiofiles.os import remove
from fastapi import UploadFile

from sign.config import settings
from sign.errors import FileTooBigError
from sign.log import SysLog
from sign.pgp.helpers import restart_gpg_agent
from sign.pgp.pgp_password_db import PGPPasswordDB
from sign.utils.hashing import get_hasher, hash_file
from sign.utils.locking import exclusive_lock


class PGP:
    def __init__(
        self,
        keyring: str,
        gpg_binary: str,
        pgp_keys: List[str],
        max_upload_bytes: int,
        pass_db_dev_mode: bool = False,
        pass_db_dev_pass: str = None,
        tmp_dir: str = '/tmp',
    ):
        self.__gpg = gnupg.GPG(gpgbinary=gpg_binary, keyring=keyring)
        self.__pass_db = PGPPasswordDB(
            self.__gpg, pgp_keys, pass_db_dev_mode, pass_db_dev_pass
        )
        self.max_upload_bytes = max_upload_bytes
        self.tmp_dir = tmp_dir
        self.__pass_db.ask_for_passwords()
        self.__syslog = SysLog(tag_name=settings.service)
        # Semaphore to control GPG operations and agent restarts
        self.__gpg_semaphore = asyncio.Semaphore(1)

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
            'wb',
            delete=True,
            dir=self.tmp_dir,
        ) as fd:
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
                '--pinentry-mode',
                'loopback',
                '--digest-algo',
                digest_algo,
                '--detach-sign' if detach_sign else '--clear-sign',
                '--armor',
                '--default-key',
                keyid,
                fd.name,
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

    async def _sign_batch_file(
        self,
        keyid: str,
        file: UploadFile,
        detach_sign: bool,
        digest_algo: str,
    ) -> Tuple[str, str]:
        """Helper method for batch signing with semaphore protection."""
        upload_size = 0
        async with aiofiles.tempfile.NamedTemporaryFile(
            'wb', delete=True, dir=self.tmp_dir
        ) as fd:
            while content := await file.read(1024 * 1024):
                upload_size += len(content)
                if upload_size > self.max_upload_bytes:
                    raise FileTooBigError
                await fd.write(content)
                await fd.flush()
            file.file.close()

            hash_before = hash_file(fd.name, hasher=get_hasher())

            password = self.__pass_db.get_password(keyid)
            sign_cmd = plumbum.local[self.__gpg.gpgbinary][
                '--yes',
                '--pinentry-mode',
                'loopback',
                '--digest-algo',
                digest_algo,
                '--detach-sign' if detach_sign else '--clear-sign',
                '--armor',
                '--default-key',
                keyid,
                fd.name,
            ]

            # Use semaphore to protect GPG operation and agent restart
            async with self.__gpg_semaphore:
                out, status = pexpect.run(
                    command=' '.join(sign_cmd.formulate()),
                    events={"Enter passphrase:.*": "{0}\r".format(password)},
                    env={"LC_ALL": "en_US.UTF-8"},
                    timeout=1200,
                    withexitstatus=1,
                )
                restart_gpg_agent()

            hash_after = hash_file(fd.name, hasher=get_hasher())
            self.__syslog.sign_log(
                os.path.basename(fd.name),
                hash_before,
                hash_after,
                keyid,
            )

            if status != 0:
                raise Exception(f'gpg failed to sign file, error: {out}')

            async with aiofiles.open(f'{fd.name}.asc', 'r') as fl:
                signature = await fl.read()

        await remove(f'{fd.name}.asc')
        return fd.name, signature

    async def _sign_single_file_for_batch(
        self,
        keyid: str,
        file: UploadFile,
        detach_sign: bool = True,
        digest_algo: str = 'SHA256',
    ) -> Tuple[str, str]:
        """Helper method for batch signing - raises on error for fail-fast behavior."""
        filename = file.filename
        _, signature = await self._sign_batch_file(
            keyid=keyid,
            file=file,
            detach_sign=detach_sign,
            digest_algo=digest_algo,
        )
        return filename, signature

    async def sign_batch(
        self,
        keyid: str,
        files: List[UploadFile],
        detach_sign: bool = True,
        digest_algo: str = 'SHA256',
    ) -> List[Tuple[str, str]]:
        """
        Sign multiple files asynchronously.

        Uses exclusive_lock for cross-process protection and semaphore
        for safe agent restarts within the process.

        Raises exception immediately if any file fails (fail-fast).
        """
        logging.info(
            "Starting batch signing of %d files with key %s", len(files), keyid
        )

        with exclusive_lock(settings.gpg_locks_dir, keyid):
            tasks = [
                self._sign_single_file_for_batch(
                    keyid=keyid,
                    file=file,
                    detach_sign=detach_sign,
                    digest_algo=digest_algo,
                )
                for file in files
            ]

            results = await asyncio.gather(*tasks)

        logging.info(
            "Batch signing completed successfully: %d files", len(results)
        )

        return results
