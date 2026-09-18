class UserNotFoundError(Exception):
    pass


class FileTooBigError(Exception):
    pass


class NotAnRpmError(Exception):
    """Uploaded file is not an RPM/SRPM package."""


class RpmSignError(Exception):
    """rpmsign failed, or produced a package without the expected signature."""


class KeyNotAllowedError(Exception):
    """The caller is not authorized to sign with the requested key."""

    def __init__(self, email: str, keyid: str):
        self.email = email
        self.keyid = keyid
        super().__init__(
            f'user {email} is not authorized to sign with key {keyid}'
        )


class AuditWriteError(Exception):
    """The signing request could not be written to the audit trail."""
