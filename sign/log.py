import logging
import logging.handlers

class SysLog:

    def __init__(self, tag_name: str, level: int = logging.INFO):
        self._tag_name = tag_name
        self._logger = logging.getLogger()
        self._level = level
        self._logger.setLevel(self._level)
        formatter = logging.Formatter(self._tag_name + ': %(message)s')
        handler = logging.handlers.SysLogHandler(address='/dev/log')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def sign_log(
        self,
        file_name: str,
        hash_before: str,
        hash_after: str,
        pgp_keyid: str,
    ):
        self._logger.info(
            'Filename: %s. Hash before: %s. '
            'Hash after: %s. Sign key ID: %s',
            file_name,
            hash_before,
            hash_after,
            pgp_keyid,
        )

    @property
    def logger(self) -> logging.Logger:
        return self._logger
