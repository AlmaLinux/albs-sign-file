"""
temporary file for manual tests
"""
import asyncio
from sign_file.pgp import PGP
import json

# change this as you see fit
gpg_binary = "/usr/local/MacGPG2/bin/gpg2"
keyring = '/Users/kzhukov/.gnupg/pubring.kbx'
pass_db_dev_pass = ""
pass_db_dev_mode = False
pgp_keys = ['EF0F6DF0AFE52FD5', "0673DB399D3E2894"]
test_file = '/Users/kzhukov/projects/cloudlinux/albs-sign-file/requirements.txt'

pgp = PGP(
    keyring=keyring,
    gpg_binary=gpg_binary,
    pgp_keys=pgp_keys,
    pass_db_dev_mode=pass_db_dev_mode,
    pass_db_dev_pass=pass_db_dev_pass)


async def run():
    res = await pgp.sign(keyid=pgp_keys[0], fpath=test_file)
    print(res)

loop = asyncio.get_event_loop()

loop.run_until_complete(run())
