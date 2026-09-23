import logging
import logging.handlers
import os
import sys



class SysLog:

    def __init__(self, tag_name: str, level: int = logging.INFO):
        self._tag_name = tag_name
        self._level = level
        self._logger = logging.getLogger('sign.audit')
        self._logger.setLevel(self._level)
        self._logger.propagate = False

        if not self._logger.handlers:
            formatter = logging.Formatter(self._tag_name + ': %(message)s')
            handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
            if os.path.exists('/dev/log'):
                handlers.append(
                    logging.handlers.SysLogHandler(address='/dev/log')
                )
            for handler in handlers:
                handler.setFormatter(formatter)
                self._logger.addHandler(handler)

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

    def rpm_sign_log(
        self,
        user_email: str,
        file_name: str,
        package_nevra: str,
        hash_before: str,
        hash_after: str,
        pgp_keyid: str,
    ):
        """
        Audit line for an RPM header signing request.

        Carries the caller alongside the package identity: unlike file
        signing, this path is reachable by callers outside the build
        system, so the syslog trail has to say who asked.
        """
        self._logger.info(
            'RPM header sign. User: %s. Filename: %s. Package: %s. '
            'Hash before: %s. Hash after: %s. Sign key ID: %s',
            user_email,
            file_name,
            package_nevra,
            hash_before,
            hash_after,
            pgp_keyid,
        )

    @property
    def logger(self) -> logging.Logger:
        return self._logger
