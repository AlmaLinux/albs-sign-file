"""
temporary file for manual tests
"""
import asyncio
from platform import python_branch
from sign_file.pgp import PGP
import json

# change this as you see fit
gpg_binary = "/usr/local/MacGPG2/bin/gpg2"
keyring = '/Users/kzhukov/.gnupg/pubring.kbx'
pass_db_dev_pass = ""
pass_db_dev_mode = False
pgp_keys = ['EF0F6DF0AFE52FD5', "0673DB399D3E2894"]
test_file = '/Users/kzhukov/projects/cloudlinux/albs-sign-file/setup.py'

pgp = PGP(
    keyring=keyring,
    gpg_binary=gpg_binary,
    pgp_keys=pgp_keys,
    pass_db_dev_mode=pass_db_dev_mode,
    pass_db_dev_pass=pass_db_dev_pass)


print(pgp.sign(pgp_keys[0], test_file))
