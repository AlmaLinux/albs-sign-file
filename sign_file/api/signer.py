from ..pgp import PGP
from ..config import settings

pgp = PGP(keyring=settings.keyring,
          gpg_binary=settings.gpg_binary,
          pgp_keys=settings.pgp_keys,
          pass_db_dev_mode=settings.pass_db_dev_mode,
          pass_db_dev_pass=settings.pass_db_dev_pass)
