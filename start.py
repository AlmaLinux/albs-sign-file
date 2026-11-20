import uvicorn

from sign.config import settings


def main():
    if settings.signing_backend == 'gpg':
        from sign.pgp.passphrase_handoff import publish_passphrases
        from sign.signing.backend import collect_gpg_passphrases

        # Ask for (or fetch) the GPG passphrases once, here, before uvicorn
        # spawns the workers; they pick them up from the environment instead
        # of each prompting on the same terminal. See passphrase_handoff.
        publish_passphrases(collect_gpg_passphrases())

    uvicorn.run(
        "sign.app:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="debug",
        workers=4,
    )


if __name__ == "__main__":
    main()
