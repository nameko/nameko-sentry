import logging

from mock import Mock, patch, call
import pytest

from nameko.containers import WorkerContext
from nameko.extensions import Entrypoint
from nameko.testing.services import dummy, entrypoint_hook, entrypoint_waiter
from nameko.testing.utils import get_extension
from raven.transport.eventlet import EventletHTTPTransport

from nameko_sentry import SentryReporter


class CustomException(Exception):
    pass


@pytest.fixture
def config():
    return {
        'SENTRY': {
            'DSN': 'http://user:pass@localhost:9000/1',
            'CLIENT_CONFIG': {
                'site': 'site name'
            }
        }
    }


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


@pytest.fixture
def reporter(container):
    return SentryReporter().bind(container, "sentry")


def test_setup(reporter):
    reporter.setup()

    # client config and DSN applied correctly
    assert reporter.client.site == "site name"
    assert reporter.client.get_public_dsn() == "//user@localhost:9000/1"
    assert reporter.client.is_enabled()

    # transport set correctly
    transport = reporter.client.remote.get_transport()
    assert isinstance(transport, EventletHTTPTransport)


def test_setup_without_optional_config(config):

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
    assert reporter.client.get_public_dsn() == None
    assert not reporter.client.is_enabled()


def test_worker_result(reporter, worker_ctx):
    result = "OK!"

    reporter.setup()
    with patch.object(reporter, 'client') as client:
        reporter.worker_result(worker_ctx, result, None)

    assert not client.captureException.called


def test_worker_exception(reporter, worker_ctx):

    exc = CustomException("Error!")
    exc_info = (CustomException, exc, None)

    reporter.setup()
    with patch.object(reporter, 'client') as client:
        reporter.worker_result(worker_ctx, None, exc_info)

    # generate expected call args
    logger = "{}.{}".format(
        worker_ctx.service_name, worker_ctx.entrypoint.method_name)
    message = "Unhandled exception in call {}: {} {!r}".format(
        worker_ctx.call_id, CustomException.__name__, str(exc)
    )
    extra = {'exc': exc}

    if isinstance(exc, worker_ctx.entrypoint.expected_exceptions):
        loglevel = logging.WARNING
    else:
        loglevel = logging.ERROR

    data = {
        'logger': logger,
        'level': loglevel,
        'message': message,
        'tags': {
            'call_id': worker_ctx.call_id,
            'parent_call_id': worker_ctx.immediate_parent_call_id
        }
    }

    # verify call
    assert client.captureException.call_args_list == [
        call(exc_info, message=message, extra=extra, data=data)
    ]


def test_end_to_end(container_factory, config):

    class Service(object):
        name = "service"

        sentry = SentryReporter()

        @dummy
        def broken(self):
            raise CustomException("Error!")

    container = container_factory(Service, config)
    container.start()

    reporter = get_extension(container, SentryReporter)

    with patch.object(reporter, 'client') as client:
        with entrypoint_hook(container, 'broken') as broken:
            with entrypoint_waiter(container, 'broken'):
                with pytest.raises(CustomException):
                    broken()
    assert client.captureException.call_count == 1
