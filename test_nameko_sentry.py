import logging

import pytest
from mock import Mock, call, patch
from nameko.containers import WorkerContext
from nameko.extensions import Entrypoint
from nameko.testing.services import dummy, entrypoint_hook, entrypoint_waiter
from nameko.testing.utils import get_extension
from nameko_sentry import SentryReporter
from raven.transport.threaded import ThreadedHTTPTransport
from util import wait_for_call  # TODO: new lib


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
    assert isinstance(transport, ThreadedHTTPTransport)


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
    assert isinstance(transport, ThreadedHTTPTransport)


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
    reporter.worker_result(worker_ctx, result, None)

    assert reporter.queue.qsize() == 0


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

    assert reporter.queue.qsize() == 1

    _, message, extra, data = reporter.queue.get()
    assert message == expected_message
    assert extra == expected_extra
    assert data == expected_data


def test_run(reporter):

    exc = CustomException("Error!")
    exc_info = (CustomException, exc, None)

    message = "message"
    extra = "extra"
    data = "data"

    reporter.setup()

    reporter.queue.put((exc_info, message, extra, data))
    reporter.queue.put(None)

    with patch.object(reporter, 'client') as client:
        reporter._run()

    assert client.captureException.call_args_list == [
        call(exc_info, message=message, extra=extra, data=data)
    ]


def test_start(container_factory, service_cls, config):

    container = container_factory(service_cls, config)
    reporter = get_extension(container, SentryReporter)

    reporter.setup()

    with patch.object(reporter, 'queue') as queue:
        with wait_for_call(queue, 'get') as get:
            reporter.start()

    assert reporter._gt is not None
    assert get.called  # do you need to patch as well?


def test_stop(container_factory, service_cls, config):

    container = container_factory(service_cls, config)
    reporter = get_extension(container, SentryReporter)

    reporter.setup()
    reporter.start()
    assert not reporter._gt.dead
    reporter.stop()
    assert reporter._gt.dead


def test_end_to_end(container_factory, service_cls, config):

    container = container_factory(service_cls, config)
    container.start()

    reporter = get_extension(container, SentryReporter)

    with patch.object(reporter, 'client') as client:
        with entrypoint_hook(container, 'broken') as broken:
            with entrypoint_waiter(container, 'broken'):
                with pytest.raises(CustomException):
                    broken()
    assert client.captureException.call_count == 1
