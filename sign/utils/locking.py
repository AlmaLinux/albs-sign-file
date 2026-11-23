"""
Build System functions to work with locked files.
"""

import asyncio
import contextlib
import fcntl
from pathlib import Path

GPG_AGENT_LOCK_FILENAME = '.gpg-agent'


@contextlib.contextmanager
def exclusive_lock(path: str, filename: str):
    locks_dir = Path(path)
    locks_dir.mkdir(exist_ok=True, parents=True)
    with Path(locks_dir, filename).open('w+') as file:
        fcntl.flock(file, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(file, fcntl.LOCK_UN)


@contextlib.contextmanager
def shared_lock(path: str, filename: str):
    locks_dir = Path(path)
    locks_dir.mkdir(exist_ok=True, parents=True)
    with Path(locks_dir, filename).open('w+') as file:
        fcntl.flock(file, fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(file, fcntl.LOCK_UN)


@contextlib.asynccontextmanager
async def _async_flock(path: str, filename: str, operation: int):
    """
    Hold an flock from a coroutine without blocking the event loop.

    The (possibly long) wait for the lock runs on a worker thread. Blocking
    the loop instead deadlocks a worker: a coroutine that already holds the
    lock can never resume to release it.
    """
    locks_dir = Path(path)
    locks_dir.mkdir(exist_ok=True, parents=True)
    # Not a `with` block: the file stays open, holding the lock, across the
    # yield below, and is closed on every path out of this function.
    file = Path(locks_dir, filename).open('w+')  # pylint: disable=R1732
    acquire = asyncio.ensure_future(
        asyncio.to_thread(fcntl.flock, file, operation)
    )
    try:
        await asyncio.shield(acquire)
    except BaseException:
        # Cancelled (or failed) while waiting: let the pending flock call
        # finish before closing the file, which releases the lock if it
        # was granted meanwhile.
        with contextlib.suppress(BaseException):
            await acquire
        file.close()
        raise
    try:
        yield
    finally:
        fcntl.flock(file, fcntl.LOCK_UN)
        file.close()


def async_exclusive_lock(path: str, filename: str):
    """``exclusive_lock`` for coroutines; waits off the event loop."""
    return _async_flock(path, filename, fcntl.LOCK_EX)


def async_shared_lock(path: str, filename: str):
    """``shared_lock`` for coroutines; waits off the event loop."""
    return _async_flock(path, filename, fcntl.LOCK_SH)
