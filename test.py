"""
temporary file for manual tests
"""
from sign_file.pgp import PGP

# change this as you see fit
gpg_binary="/usr/local/MacGPG2/bin/gpg2"
keyring='/Users/kzhukov/.gnupg/pubring.kbx'
pass_db_dev_pass = ""
pass_db_dev_mode = False
pgp_keys = ['E381F153E1B9DE02']

pgp = PGP(
    keyring=keyring,
    gpg_binary=gpg_binary,
    pgp_keys=pgp_keys,
    pass_db_dev_mode=pass_db_dev_mode,
    pass_db_dev_pass=pass_db_dev_pass)


print(pgp.sign(pgp_keys[0], './requirements.txt'))