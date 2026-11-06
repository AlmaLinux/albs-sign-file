import logging
import logging.handlers

from sentry_sdk.scrubber import DEFAULT_DENYLIST, EventScrubber

# Variable and key names Sentry must not report besides its defaults. The KMS
# RPM signer gets AWS credentials through an environment dict, which a
# failing frame would otherwise carry into the event with its locals.
SENTRY_DENYLIST = [
    'access_key_id',
    'aws_access_key_id',
    'aws_secret_access_key',
    'aws_session_token',
    'aws_security_token',
    'secret_access_key',
]


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
            'Filename: %s. Hash before: %s. ' 'Hash after: %s. Sign key ID: %s',
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


def sentry_event_scrubber() -> EventScrubber:
    """
    Scrubber for sentry_sdk.init: the default denylist plus SENTRY_DENYLIST,
    applied to nested dicts too, since credentials sit inside an env dict
    rather than in a variable of their own.
    """
    return EventScrubber(
        denylist=DEFAULT_DENYLIST + SENTRY_DENYLIST,
        recursive=True,
    )
