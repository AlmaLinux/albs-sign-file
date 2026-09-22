"""gpg-agent helpers shared by the file and RPM signing paths."""

import plumbum

__all__ = ['restart_gpg_agent']


def restart_gpg_agent():
    """
    Restarts gpg-agent.
    """
    plumbum.local["gpgconf"]["--reload", "gpg-agent"].run(retcode=None)
