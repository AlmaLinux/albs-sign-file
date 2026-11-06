"""
Sentry must not receive the AWS credentials the KMS RPM signer is handed.

They travel in an environment dict, and Sentry reports the local variables
of every frame of a captured exception: dicts as dicts, which the scrubber
walks, and anything else by its repr, which it cannot look into.
"""

import functools
import importlib
import secrets

import pytest
import sentry_sdk

from sign.config import settings
from sign.kms.rpm_signer import signer_env
from sign.log import sentry_event_scrubber
from tests.sentry_capture import captured_event

# Made up at import: a literal would show up in the source context Sentry
# attaches to frames of this file.
SECRET = secrets.token_hex(16)


def _env():
    return signer_env(
        'alias/rpm',
        'A' * 40,
        'RSASSA_PKCS1_V1_5_SHA_256',
        access_key_id='AKIAEXAMPLE',
        secret_access_key=SECRET,
    )


def _fail_with_env_in_scope():
    env = _env()
    raise RuntimeError(f'rpmsign failed with {len(env)} variables set')


def _fail_with_env_in_a_partial(env_factory=_env):
    # what asyncio.to_thread keeps while the worker thread runs
    func_call = functools.partial(print, env=env_factory())
    raise RuntimeError(f'{func_call.func.__name__} failed')


def test_default_scrubbing_would_leak_the_secret():
    """Without the service's scrubber the test would prove nothing."""
    assert SECRET in captured_event(_fail_with_env_in_scope)


def test_service_initializes_sentry_with_its_scrubber(monkeypatch):
    import sign.app

    options = {}
    monkeypatch.setattr(settings, 'sentry_dsn', 'http://key@127.0.0.1:9/1')
    monkeypatch.setattr(sentry_sdk, 'init', lambda **kw: options.update(kw))

    importlib.reload(sign.app)

    scrubber = options['event_scrubber']
    assert 'aws_secret_access_key' in scrubber.denylist
    assert scrubber.recursive


@pytest.mark.parametrize(
    'variable',
    ['AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_SECURITY_TOKEN'],
)
def test_service_scrubber_drops_aws_credentials(variable):
    event = captured_event(
        _fail_with_env_in_scope, event_scrubber=sentry_event_scrubber()
    )

    assert SECRET not in event
    assert variable in event  # the key stays, its value is replaced


def test_a_plain_dict_in_a_partial_would_leak_despite_the_scrubber():
    """Why the signer's environment is not a plain dict."""
    event = captured_event(
        functools.partial(_fail_with_env_in_a_partial, lambda: dict(_env())),
        event_scrubber=sentry_event_scrubber(),
    )

    assert SECRET in event


def test_signer_env_in_a_partial_does_not_leak():
    event = captured_event(
        _fail_with_env_in_a_partial, event_scrubber=sentry_event_scrubber()
    )

    assert SECRET not in event
    assert 'AWS_SECRET_ACCESS_KEY' in event


def test_signer_env_repr_names_variables_only():
    env = _env()

    assert SECRET not in repr(env)
    assert SECRET not in str(env)
    assert 'AWS_SECRET_ACCESS_KEY' in repr(env)
