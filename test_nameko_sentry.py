import logging

import pytest
from eventlet.event import Event
from mock import Mock, patch
from nameko.containers import WorkerContext
from nameko.extensions import Entrypoint
from nameko.testing.services import dummy, entrypoint_hook, entrypoint_waiter
from nameko.web.handlers import http
from nameko_sentry import SentryReporter
from raven import Client
from raven.transport.eventlet import EventletHTTPTransport
from six.moves.urllib import parse


class CustomException(Exception):
    pass


@pytest.fixture
def config():
    return {
        'SENTRY': {
            'DSN': 'eventlet+http://user:pass@localhost:9000/1',
            'CLIENT_CONFIG': {
                'site': 'site name'
            }
        }
    }


@pytest.fixture
def service_cls():

    class Service(object):
        name = "service"

        sentry = SentryReporter()

        @dummy
        def broken(self):
            raise CustomException("Error!")

    return Service


@pytest.fixture
def container(config):
    return Mock(config=config)


@pytest.fixture(params=[tuple(), CustomException])  # expected exceptions
def worker_ctx(request, container):

    service = Mock()
    entrypoint = Mock(spec=Entrypoint, expected_exceptions=request.param)
    args = ("a", "b", "c")
    kwargs = {"d": "d", "e": "e"}
    data = {
        'call_id': 'service.entrypoint.1',
        'call_id_stack': [
            'standalone_rpc_proxy.call.0'
        ]
    }

    return WorkerContext(
        container, service, entrypoint, args=args, kwargs=kwargs, data=data
    )


@pytest.yield_fixture
def reporter(container):
    with patch.object(Client, 'captureException'):
        yield SentryReporter().bind(container, "sentry")


def test_setup(reporter, config):
    reporter.setup()

    # client config and DSN applied correctly
    assert reporter.client.site == "site name"
    assert reporter.client.get_public_dsn() == "//user@localhost:9000/1"
    assert reporter.client.is_enabled()

    # transport set correctly
    transport = reporter.client.remote.get_transport()
    assert isinstance(transport, EventletHTTPTransport)


def test_setup_without_optional_config(request, config):

    del config['SENTRY']['CLIENT_CONFIG']
    container = Mock(config=config)

    reporter = SentryReporter().bind(container, "sentry")
    reporter.setup()

    # DSN applied correctly
    assert reporter.client.get_public_dsn() == "//user@localhost:9000/1"
    assert reporter.client.is_enabled()

    # transport set correctly
    transport = reporter.client.remote.get_transport()
    assert isinstance(transport, EventletHTTPTransport)


def test_disabled(config):
    config['SENTRY']['DSN'] = None
    container = Mock(config=config)

    reporter = SentryReporter().bind(container, "sentry")
    reporter.setup()

    # DSN applied correctly
    assert reporter.client.get_public_dsn() is None
    assert not reporter.client.is_enabled()


def test_worker_result(reporter, worker_ctx):
    result = "OK!"

    reporter.setup()
    reporter.worker_result(worker_ctx, result, None)

    assert reporter.client.captureException.call_count == 0


def test_worker_exception(reporter, worker_ctx):

    exc = CustomException("Error!")
    exc_info = (CustomException, exc, None)

    reporter.setup()
    reporter.worker_result(worker_ctx, None, exc_info)

    # generate expected call args
    logger = "{}.{}".format(
        worker_ctx.service_name, worker_ctx.entrypoint.method_name)
    expected_message = "Unhandled exception in call {}: {} {!r}".format(
        worker_ctx.call_id, CustomException.__name__, str(exc)
    )
    expected_extra = {'exc': exc}

    if isinstance(exc, worker_ctx.entrypoint.expected_exceptions):
        loglevel = logging.WARNING
    else:
        loglevel = logging.ERROR

    expected_data = {
        'logger': logger,
        'level': loglevel,
        'message': expected_message,
        'tags': {
            'call_id': worker_ctx.call_id,
            'parent_call_id': worker_ctx.immediate_parent_call_id
        }
    }

    assert reporter.client.captureException.call_count == 1

    _, kwargs = reporter.client.captureException.call_args
    assert kwargs['message'] == expected_message
    assert kwargs['extra'] == expected_extra
    assert kwargs['data'] == expected_data


@patch.object(EventletHTTPTransport, '_send_payload')
def test_raven_transport_does_not_affect_container(
    send_mock, container_factory, service_cls, config
):
    """ Allowing raven to use the eventlet transport should not affect the
    nameko container, even if raven blocks trying to make calls.
    """
    def block(*args):
        Event().wait()

    send_mock.side_effect = block

    container = container_factory(service_cls, config)
    container.start()

    with entrypoint_hook(container, 'broken') as broken:
        with entrypoint_waiter(container, 'broken'):
            with pytest.raises(CustomException):
                broken()

    container.stop()
