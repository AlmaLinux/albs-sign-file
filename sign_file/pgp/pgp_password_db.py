import getpass
import gnupg
from .errors import ConfigurationError
from .helpers import verify_pgp_key_password


class PGPPasswordDB(object):
    def __init__(self, gpg: gnupg.GPG, pgp_keys: list[str],
                 development_mode: bool = False,
                 development_password: str = None):
        """
        Password DB initialization.
        This structure stores GPG keys passwords

        Parameters
        ----------
        gpg : gnupg.GPG
            Gpg wrapper.
        keyids : list of str
            List of PGP keyids.
        """
        self.__gpg = gpg
        self.__keys = {keyid: {'password': ''} for keyid in pgp_keys}
        if development_mode and not development_password:
            raise ConfigurationError('You need to provide development PGP '
                                     'password when running in development '
                                     'mode')
        self.__development_mode = development_mode
        self.__development_password = development_password

    def ask_for_passwords(self):
        """
        Asks a user for PGP private key passwords and stores them in the DB.

        RaisesF
        ------
        castor.errors.ConfigurationError
            If a private GPG key is not found or an entered password is
            incorrect.
        """
        existent_keys = {key["keyid"]: key
                         for key in self.__gpg.list_keys(True)}
        for keyid in self.__keys:
            key = existent_keys.get(keyid)
            if not key:
                raise ConfigurationError(
                    "PGP key {0} is not found in the " "gnupg2 "
                    "database".format(keyid)
                )
            if self.__development_mode:
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
        """
        Returns a password for the specified private PGP key.

        Parameters
        ----------
        keyid : str
            Private PGP key keyid.

        Returns
        -------
        str
            Password.
        """
        return self.__keys[keyid]["password"]

    def get_fingerprint(self, keyid):
        """
        Returns a fingerprint for the specified private PGP key.

        Parameters
        ----------
        keyid : str
            Private PGP key keyid.

        Returns
        -------
        str
            fingerprint.
        """
        return self.__keys[keyid]["fingerprint"]

    def get_subkeys(self, keyid):
        """
        Returns a list of subkey fingerprints.

        Parameters
        ----------
        keyid : str
            Private PGP key keyid.

        Returns
        -------
        list
            Subkey fingerprints.
        """
        return self.__keys[keyid]["subkeys"]
