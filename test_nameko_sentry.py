import logging
import socket

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
def container(config, service_cls, predictable_call_ids):
    return Mock(service_name=service_cls.name, config=config)


@pytest.fixture
def worker_ctx(container):

    service = Mock()
    entrypoint = Mock(
        spec=Entrypoint,
        method_name="entrypoint",
        expected_exceptions=CustomException
    )
    args = ("a", "b", "c")
    kwargs = {"d": "d", "e": "e"}
    data = {
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


def test_setup(reporter):
    reporter.setup()

    # client config and DSN applied correctly
    assert reporter.client.site == "site name"
    assert reporter.client.get_public_dsn() == "//user@localhost:9000/1"
    assert reporter.client.is_enabled()

    # transport set correctly
    transport = reporter.client.remote.get_transport()
    assert isinstance(transport, EventletHTTPTransport)


def test_setup_without_optional_config(service_cls, config):

    del config['SENTRY']['CLIENT_CONFIG']
    container = Mock(service_name=service_cls.name, config=config)

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


@pytest.mark.parametrize("exception_cls,expected_level", [
    (CustomException, logging.WARNING),
    (KeyError, logging.ERROR)
])
def test_worker_exception(
    exception_cls, expected_level, reporter, worker_ctx
):
    exc = exception_cls("Error!")
    exc_info = (exception_cls, exc, None)

    reporter.setup()
    reporter.worker_result(worker_ctx, None, exc_info)

    # generate expected call args
    expected_logger = "{}.{}".format(
        worker_ctx.service_name, worker_ctx.entrypoint.method_name
    )
    expected_message = "Unhandled exception in call {}: {} {!r}".format(
        worker_ctx.call_id, exception_cls.__name__, str(exc)
    )
    expected_extra = worker_ctx.context_data
    expected_tags = {
        'call_id': worker_ctx.call_id,
        'parent_call_id': worker_ctx.immediate_parent_call_id,
        'service_name': worker_ctx.container.service_name,
        'method_name': worker_ctx.entrypoint.method_name
    }
    expected_user = {}
    expected_http = {}
    expected_data = {
        'logger': expected_logger,
        'level': expected_level,
        'tags': expected_tags,
        'user': expected_user,
        'request': expected_http
    }

    assert reporter.client.captureException.call_count == 1

    _, kwargs = reporter.client.captureException.call_args
    assert kwargs['message'] == expected_message
    assert kwargs['extra'] == expected_extra
    assert kwargs['data'] == expected_data


@pytest.mark.parametrize("exception_cls,expected_count", [
    (CustomException, 0),
    (KeyError, 1)
])
def test_expected_exception_not_reported(
    exception_cls, expected_count, config, worker_ctx
):

    exc = exception_cls("Error!")
    exc_info = (exception_cls, exc, None)

    config['SENTRY']['REPORT_EXPECTED_EXCEPTIONS'] = False
    container = Mock(config=config)

    reporter = SentryReporter().bind(container, "sentry")
    reporter.setup()

    with patch.object(reporter.client, 'captureException') as capture:
        reporter.worker_result(worker_ctx, None, exc_info)

    assert capture.call_count == expected_count


class TestContext(object):

    def test_user_defaults(self, reporter, worker_ctx):

        user_data = {
            'user': 'matt',
            'username': 'matt',
            'user_id': 1,
            'email': 'matt@example.com',
            'email_address': 'matt@example.com',
            'session_id': 1
        }
        non_user_data = {
            'language': 'en-gb'
        }

        worker_ctx.data.update(user_data)
        worker_ctx.data.update(non_user_data)

        exc = CustomException("Error!")
        exc_info = (CustomException, exc, None)

        reporter.setup()
        reporter.worker_result(worker_ctx, None, exc_info)

        assert reporter.client.captureException.call_count == 1

        _, kwargs = reporter.client.captureException.call_args
        assert kwargs['data']['user'] == user_data
        for key in non_user_data:
            assert key not in kwargs['data']['user']

    def test_user_custom(self, config, worker_ctx):

        config['SENTRY']['USER_TYPE_CONTEXT_KEYS'] = (
            'user|email',  # excludes session
            'other_pattern'
        )
        container = Mock(config=config)

        reporter = SentryReporter().bind(container, "sentry")
        reporter.setup()

        user_data = {
            'user': 'matt',
            'username': 'matt',
            'user_id': 1,
            'email': 'matt@example.com',
            'email_address': 'matt@example.com',
        }
        non_user_data = {
            'session_id': 1,  # exclude session
            'language': 'en-gb'
        }

        worker_ctx.data.update(user_data)
        worker_ctx.data.update(non_user_data)

        exc = CustomException("Error!")
        exc_info = (CustomException, exc, None)

        reporter.setup()
        with patch.object(reporter.client, 'captureException') as capture:
            reporter.worker_result(worker_ctx, None, exc_info)

        assert capture.call_count == 1

        _, kwargs = capture.call_args
        assert kwargs['data']['user'] == user_data
        for key in non_user_data:
            assert key not in kwargs['data']['user']

    def test_tags_defaults(self, reporter, worker_ctx):

        default_tags = {
            'call_id': worker_ctx.call_id,
            'parent_call_id': worker_ctx.immediate_parent_call_id,
            'service_name': worker_ctx.container.service_name,
            'method_name': worker_ctx.entrypoint.method_name
        }

        exc = CustomException("Error!")
        exc_info = (CustomException, exc, None)

        reporter.setup()
        reporter.worker_result(worker_ctx, None, exc_info)

        assert reporter.client.captureException.call_count == 1

        _, kwargs = reporter.client.captureException.call_args
        assert kwargs['data']['tags'] == default_tags

    def test_tags_custom(self, config, worker_ctx):

        config['SENTRY']['TAG_TYPE_CONTEXT_KEYS'] = (
            'session',
            'other_pattern'
        )
        container = Mock(config=config)

        reporter = SentryReporter().bind(container, "sentry")
        reporter.setup()

        context_data = {
            'user': 'matt',
            'username': 'matt',
            'user_id': 1,
            'email': 'matt@example.com',
            'email_address': 'matt@example.com',
            'session_id': 1,
        }

        worker_ctx.data.update(context_data)

        default_tags = {
            'call_id': worker_ctx.call_id,
            'parent_call_id': worker_ctx.immediate_parent_call_id,
            'service_name': worker_ctx.container.service_name,
            'method_name': worker_ctx.entrypoint.method_name
        }
        additional_tags = {
            'session_id': 1
        }
        expected_tags = default_tags.copy()
        expected_tags.update(additional_tags)

        exc = CustomException("Error!")
        exc_info = (CustomException, exc, None)

        reporter.setup()
        with patch.object(reporter.client, 'captureException') as capture:
            reporter.worker_result(worker_ctx, None, exc_info)

        assert capture.call_count == 1

        _, kwargs = capture.call_args
        assert kwargs['data']['tags'] == expected_tags

    def test_http(self, reporter, worker_ctx):
        pass

    def test_http_unsupported_entrypoint(self, reporter, worker_ctx):
        pass

    def test_extra(self, reporter, worker_ctx):

        extra_data = {
            'session_id': 1,
            'locale': 'en-gb'
        }

        worker_ctx.data.update(extra_data)

        exc = CustomException("Error!")
        exc_info = (CustomException, exc, None)

        reporter.setup()
        reporter.worker_result(worker_ctx, None, exc_info)

        assert reporter.client.captureException.call_count == 1

        _, kwargs = reporter.client.captureException.call_args
        for key, value in extra_data.items():
            assert kwargs['extra'][key] == value


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


class TestEndToEnd(object):

    @pytest.fixture
    def tracker(self):
        return Mock()

    @pytest.fixture
    def free_port(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        sock.close()
        return port

    @pytest.fixture
    def sentry_dsn(self, free_port):
        return 'eventlet+http://user:pass@localhost:{}/1'.format(free_port)

    @pytest.fixture
    def sentry_stub(self, container_factory, sentry_dsn, tracker):
        """ Start a container to imitate a sentry server
        """

        class SentryStub(object):
            name = "sentry"

            @http('POST', "/api/1/store/")
            def report(self, request):
                tracker(request.get_data())
                return 200, "OK"

        address = parse.urlparse(sentry_dsn).netloc.split("@")[-1]
        config = {
            'WEB_SERVER_ADDRESS': address
        }

        container = container_factory(SentryStub, config)
        container.start()

        return container

    @pytest.fixture
    def config(self, config, sentry_dsn):
        config['SENTRY']['DSN'] = sentry_dsn
        return config

    def test_end_to_end(
        self, container_factory, service_cls, config, sentry_stub, tracker
    ):

        container = container_factory(service_cls, config)
        container.start()

        with entrypoint_waiter(sentry_stub, 'report'):
            with entrypoint_hook(container, 'broken') as broken:
                with entrypoint_waiter(container, 'broken'):
                    with pytest.raises(CustomException):
                        broken()

        assert tracker.called
