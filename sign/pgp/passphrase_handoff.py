"""
Hand GPG key passphrases from the launcher process to its web workers.

With several uvicorn workers, every worker builds its own signing backend.
If each of them asked for the passphrases itself, they would all prompt at
once on the same terminal: one worker reads the typed line, the others hit
EOF and die, and uvicorn keeps respawning them into the same failure. A
worker respawned later would have nobody to answer its prompt at all.

So the launcher (``start.py``) collects and verifies the passphrases once,
before uvicorn spawns any worker, and publishes them in an environment
variable that the workers inherit. Each worker takes the passphrases and
removes the variable from its own environment, so the gpg/rpmsign
subprocesses it runs never see them. The launcher keeps the variable, so
workers that uvicorn respawns later get the passphrases too.
"""

import json
import os
from typing import Dict, Optional

PASSPHRASES_ENV_VAR = 'SF_INTERNAL_PGP_PASSPHRASES'

__all__ = [
    'PASSPHRASES_ENV_VAR',
    'publish_passphrases',
    'take_passphrases',
]


def publish_passphrases(passwords: Dict[str, str]) -> None:
    """Make verified passphrases available to worker processes."""
    os.environ[PASSPHRASES_ENV_VAR] = json.dumps(passwords)


def take_passphrases() -> Optional[Dict[str, str]]:
    """
    Return the passphrases published by the launcher, if any.

    The variable is removed from this process' environment, so child
    processes started afterwards do not inherit it.
    """
    raw = os.environ.pop(PASSPHRASES_ENV_VAR, None)
    if not raw:
        return None
    passwords = json.loads(raw)
    if not isinstance(passwords, dict):
        raise ValueError(f'{PASSPHRASES_ENV_VAR} must hold a JSON object')
    return passwords
