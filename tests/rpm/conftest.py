from typing import Callable, Dict, List, Tuple

import pytest


class FakeCommand:
    """Stand-in for a plumbum local command."""

    def __init__(self, name: str, handler: Callable, calls: List):
        self._name = name
        self._handler = handler
        self._calls = calls

    def run(self, args, retcode=None):
        self._calls.append((self._name, list(args)))
        return self._handler(list(args))


class FakeLocal:
    """Stand-in for ``plumbum.local``: maps a binary name to a handler."""

    def __init__(self, handlers: Dict[str, Callable], calls: List):
        self._handlers = handlers
        self._calls = calls

    def __getitem__(self, name):
        try:
            handler = self._handlers[name]
        except KeyError:
            raise AssertionError(f'unexpected binary invoked: {name}')
        return FakeCommand(name, handler, self._calls)


@pytest.fixture
def fake_plumbum(monkeypatch):
    """
    Install a fake ``plumbum.local`` into sign.rpm.rpm_sign.

    Usage::

        calls = fake_plumbum({'rpmsign': lambda args: (0, '', '')})
    """
    from sign.rpm import rpm_sign

    def _install(handlers: Dict[str, Callable]) -> List[Tuple[str, List[str]]]:
        calls: List[Tuple[str, List[str]]] = []
        fake = type('P', (), {'local': FakeLocal(handlers, calls)})
        monkeypatch.setattr(rpm_sign, 'plumbum', fake)
        return calls

    return _install


@pytest.fixture
def rpm_file(tmp_path):
    """An otherwise empty file that starts with the RPM lead magic."""
    from sign.rpm.rpm_sign import RPM_LEAD_MAGIC

    path = tmp_path / 'pkg-1.0-1.el9.x86_64.rpm'
    path.write_bytes(RPM_LEAD_MAGIC + b'\x03\x00' + b'\x00' * 90)
    return str(path)
