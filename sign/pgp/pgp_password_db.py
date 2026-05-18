import getpass
from typing import Dict, Optional

import gnupg

from sign.pgp.errors import ConfigurationError
from sign.pgp.helpers import verify_pgp_key_password


class PGPPasswordDB(object):
    def __init__(self, gpg: gnupg.GPG, pgp_keys: list[str],
                 development_mode: bool = False,
                 development_password: str = None,
                 preloaded_passwords: Optional[Dict[str, str]] = None):
        """
        Password DB initialization.
        This structure stores GPG keys passwords

        Parameters
        ----------
        gpg : gnupg.GPG
            Gpg wrapper.
        pgp_keys : list of str
            List of PGP keyids.
        development_mode : bool
            If True, use ``development_password`` for every key.
        development_password : str
            Single passphrase to use in development mode.
        preloaded_passwords : dict, optional
            Mapping of keyid -> passphrase fetched from an external source
            (e.g. Bitwarden). Takes precedence over ``development_mode`` and
            interactive prompting.
        """
        self.__gpg = gpg
        self.__keys = {keyid: {'password': ''} for keyid in pgp_keys}
        if development_mode and not development_password:
            raise ConfigurationError('You need to provide development PGP '
                                     'password when running in development '
                                     'mode')
        self.__development_mode = development_mode
        self.__development_password = development_password
        self.__preloaded_passwords = preloaded_passwords or {}

    def ask_for_passwords(self):
        """
        Populates the DB with PGP private key passphrases.

        Source precedence: preloaded passwords (e.g. Bitwarden) >
        development mode > interactive prompt.

        Raises
        ------
        sign.pgp.errors.ConfigurationError
            If a private GPG key is not found or a passphrase is incorrect.
        """
        existent_keys = {key["keyid"]: key
                         for key in self.__gpg.list_keys(True)}
        for keyid in self.__keys:
            key = existent_keys.get(keyid)
            if not key:
                raise ConfigurationError(
                    "PGP key {0} is not found in the gnupg2 database "
                    "available keys {1}".format(keyid, str(existent_keys.keys()))
                )
            if keyid in self.__preloaded_passwords:
                password = self.__preloaded_passwords[keyid]
            elif self.__development_mode:
                password = self.__development_password
            else:
                password = getpass.getpass('\nPlease enter the {0} PGP key '
                                           'password: '.format(keyid))
            if not verify_pgp_key_password(self.__gpg, keyid, password):
                raise ConfigurationError(
                    "PGP key {0} password is not valid".format(keyid)
                )
            self.__keys[keyid]["password"] = password
            self.__keys[keyid]["fingerprint"] = key["fingerprint"]
            self.__keys[keyid]["subkeys"] = [
                subkey[0] for subkey in key.get("subkeys", [])
            ]

    def get_password(self, keyid):
        return self.__keys[keyid]["password"]

    def get_fingerprint(self, keyid):
        return self.__keys[keyid]["fingerprint"]

    def get_subkeys(self, keyid):
        return self.__keys[keyid]["subkeys"]
