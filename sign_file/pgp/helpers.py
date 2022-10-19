# -*- mode:python; coding:utf-8; -*-
# author: Eugene Zamriy <ezamriy@cloudlinux.com>
#         Sergey Fokin <sfokin@cloudlinux.com>
# created: 2018-03-28

"""CloudLinux Build System PGP related utility functions."""

import datetime
import gnupg
import plumbum



__all__ = [
    "init_gpg",
    "scan_pgp_info_from_file",
    "verify_pgp_key_password",
    "restart_gpg_agent",
    "PGPPasswordDB",
]


def init_gpg(keyring: str = "/home/alt/.gnupg/pubring.kbx",
             gpg_binary: str = "/usr/bin/gpg2"):
    """
    A gpg binding initialization function.

    Returns
    -------
    gnupg.GPG
        Initialized gpg wrapper.
    """
    gpg = gnupg.GPG(gpgbinary=gpg_binary,
                    keyring=keyring)
    return gpg


def scan_pgp_info_from_file(gpg, key_file):
    """
    Extracts a PGP key information from the specified key file.

    Parameters
    ----------
    gpg : gnupg.GPG
        Gpg wrapper.
    key_file : str
        Key file path.

    Returns
    -------
    dict
        PGP key information.

    ValueError
    ----------
    If a given file doesn't contain a valid PGP key.
    """
    keys = gpg.scan_keys(key_file)
    if not keys:
        raise ValueError("there is no PGP key found")
    key = keys[0]
    return {
        "fingerprint": key["fingerprint"],
        "keyid": key["keyid"],
        "uid": key["uids"][0],
        "date": datetime.date.fromtimestamp(float(key["date"])),
    }


def restart_gpg_agent():
    """
    Restarts gpg-agent.
    """
    plumbum.local["gpgconf"]["--reload", "gpg-agent"].run(retcode=None)


def verify_pgp_key_password(gpg, keyid, password):
    """
    Checks the provided PGP key password validity.

    Parameters
    ----------
    gpg : gnupg.GPG
        Gpg wrapper.
    keyid : str
        Private key keyid.
    password : str
        Private key password.

    Returns
    -------
    bool
        True if password is correct, False otherwise.
    """
    # Clean all cached passwords.
    restart_gpg_agent()
    return gpg.verify(gpg.sign("test", keyid=keyid, passphrase=password).data).valid
