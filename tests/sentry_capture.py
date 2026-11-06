import json

import sentry_sdk
from sentry_sdk.transport import Transport


class NullTransport(Transport):
    def capture_envelope(self, envelope):
        pass


def captured_event(fail, **client_options) -> str:
    """
    The event Sentry would send for the exception ``fail()`` raises, after
    scrubbing, as JSON. Uses a client of its own, not the global one.
    """
    events = []
    client = sentry_sdk.Client(
        dsn='http://key@127.0.0.1:9/1',
        transport=NullTransport,
        before_send=lambda event, hint: events.append(event),
        **client_options,
    )
    try:
        with sentry_sdk.isolation_scope() as scope:
            scope.set_client(client)
            try:
                fail()
            except Exception as exc:  # pylint: disable=broad-except
                scope.capture_exception(exc)
    finally:
        client.close()
    [event] = events
    return json.dumps(event, default=str)
