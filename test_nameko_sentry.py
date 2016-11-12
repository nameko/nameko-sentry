import logging
import socket

import pytest
from eventlet.event import Event
from mock import ANY, Mock, patch
from nameko.exceptions import RemoteError
from nameko.rpc import rpc
from nameko.standalone.rpc import ServiceRpcProxy
from nameko.testing.services import (
    entrypoint_hook, entrypoint_waiter, get_extension)
from nameko.web.handlers import HttpRequestHandler, http
from nameko_sentry import SentryReporter
from raven import Client
from raven.transport.eventlet import EventletHTTPTransport
from six.moves.urllib import parse


class CustomException(Exception):
    pass


@pytest.fixture
def config(rabbit_config):
    config = rabbit_config.copy()
    config.update({
        'SENTRY': {
            'DSN': 'eventlet+http://user:pass@localhost:9000/1',
            'CLIENT_CONFIG': {
                'site': 'site name'
            }
        }
    })
    return config


@pytest.fixture
def service_cls():

    class Service(object):
        name = "service"

        sentry = SentryReporter()

        @rpc(expected_exceptions=CustomException)
        def broken(self):
            raise CustomException("Error!")

        @rpc
        def fine(self):
            return "OK"

    return Service


@pytest.yield_fixture
def patched_sentry():
    with patch.object(Client, 'captureException'):
        yield


@pytest.mark.usefixtures('patched_sentry')
def test_setup(container_factory, service_cls, config):

    container = container_factory(service_cls, config)
    container.start()

    sentry = get_extension(container, SentryReporter)

    # client config and DSN applied correctly
    assert sentry.client.site == "site name"
    assert sentry.client.get_public_dsn() == "//user@localhost:9000/1"
    assert sentry.client.is_enabled()

    # transport set correctly
    transport = sentry.client.remote.get_transport()
    assert isinstance(transport, EventletHTTPTransport)


@pytest.mark.usefixtures('patched_sentry')
def test_setup_without_optional_config(container_factory, service_cls, config):

    del config['SENTRY']['CLIENT_CONFIG']

    container = container_factory(service_cls, config)
    container.start()

    sentry = get_extension(container, SentryReporter)

    # DSN applied correctly
    assert sentry.client.get_public_dsn() == "//user@localhost:9000/1"
    assert sentry.client.is_enabled()

    # transport set correctly
    transport = sentry.client.remote.get_transport()
    assert isinstance(transport, EventletHTTPTransport)


@pytest.mark.usefixtures('patched_sentry')
def test_disabled(container_factory, service_cls, config):

    config['SENTRY']['DSN'] = None

    container = container_factory(service_cls, config)
    container.start()

    sentry = get_extension(container, SentryReporter)

    # DSN applied correctly
    assert sentry.client.get_public_dsn() is None
    assert not sentry.client.is_enabled()


@pytest.mark.usefixtures('patched_sentry')
def test_worker_result(container_factory, service_cls, config):
    container = container_factory(service_cls, config)
    container.start()

    with entrypoint_hook(container, 'fine') as fine:
        with entrypoint_waiter(container, 'fine'):
            assert fine() == "OK"

    sentry = get_extension(container, SentryReporter)

    assert sentry.client.captureException.call_count == 0


@pytest.mark.usefixtures('patched_sentry', 'predictable_call_ids')
@pytest.mark.parametrize("exception_cls,expected_level", [
    (CustomException, logging.WARNING),
    (KeyError, logging.ERROR)
])
def test_worker_exception(
    exception_cls, expected_level, container_factory, config
):

    class Service(object):
        name = "service"

        sentry = SentryReporter()

        @rpc(expected_exceptions=CustomException)
        def broken(self):
            raise exception_cls("Error!")

    container = container_factory(Service, config)
    container.start()

    with entrypoint_waiter(container, 'broken') as result:
        with ServiceRpcProxy('service', config) as rpc_proxy:
            with pytest.raises(RemoteError):
                rpc_proxy.broken()

        with pytest.raises(exception_cls) as raised:
            result.get()

    sentry = get_extension(container, SentryReporter)

    assert sentry.client.captureException.call_count == 1

    # generate expected call args
    expected_logger = "service.broken"
    expected_message = "Unhandled exception in call {}: {} {!r}".format(
         'service.broken.1', exception_cls.__name__, str(raised.value)
    )
    expected_extra = ANY
    expected_data = {
        'logger': expected_logger,
        'level': expected_level,
        'tags': ANY,
        'user': {},
        'request': {}
    }

    _, kwargs = sentry.client.captureException.call_args
    assert kwargs['message'] == expected_message
    assert kwargs['extra'] == expected_extra
    assert kwargs['data'] == expected_data


@pytest.mark.usefixtures('patched_sentry')
@pytest.mark.parametrize("exception_cls,expected_count", [
    (CustomException, 0),
    (KeyError, 1)
])
def test_expected_exception_not_reported(
    exception_cls, expected_count, container_factory, config
):

    class Service(object):
        name = "service"

        sentry = SentryReporter()

        @rpc(expected_exceptions=CustomException)
        def broken(self):
            raise exception_cls("Error!")

    config['SENTRY']['REPORT_EXPECTED_EXCEPTIONS'] = False

    container = container_factory(Service, config)
    container.start()

    with entrypoint_waiter(container, 'broken') as result:
        with ServiceRpcProxy('service', config) as rpc_proxy:
            with pytest.raises(RemoteError):
                rpc_proxy.broken()

        with pytest.raises(exception_cls):
            result.get()

    sentry = get_extension(container, SentryReporter)

    assert sentry.client.captureException.call_count == expected_count


@pytest.mark.usefixtures('patched_sentry')
class TestUserContext(object):

    def test_user_defaults(self, container_factory, service_cls, config):

        user_data = {
            'user': 'matt',
            'username': 'matt',
            'user_id': 1,
            'email': 'matt@example.com',
            'email_address': 'matt@example.com',
            'session_id': 1
        }

        container = container_factory(service_cls, config)
        container.start()

        context_data = {
            'language': 'en-gb'
        }
        context_data.update(user_data)

        with ServiceRpcProxy(
            'service', config, context_data=context_data
        ) as rpc_proxy:
            with pytest.raises(RemoteError):
                rpc_proxy.broken()

        sentry = get_extension(container, SentryReporter)

        assert sentry.client.captureException.call_count == 1

        _, kwargs = sentry.client.captureException.call_args
        assert kwargs['data']['user'] == user_data

    def test_user_custom(self, container_factory, service_cls, config):

        config['SENTRY']['USER_TYPE_CONTEXT_KEYS'] = (
            'user|email',  # excludes session
            'other_pattern'
        )

        container = container_factory(service_cls, config)
        container.start()

        user_data = {
            'user': 'matt',
            'username': 'matt',
            'user_id': 1,
            'email': 'matt@example.com',
            'email_address': 'matt@example.com',
        }

        context_data = {
            'session_id': 1,  # exclude session
            'language': 'en-gb'
        }
        context_data.update(user_data)

        with ServiceRpcProxy(
            'service', config, context_data=context_data
        ) as rpc_proxy:
            with pytest.raises(RemoteError):
                rpc_proxy.broken()

        sentry = get_extension(container, SentryReporter)

        assert sentry.client.captureException.call_count == 1

        _, kwargs = sentry.client.captureException.call_args
        assert kwargs['data']['user'] == user_data


@pytest.mark.usefixtures('predictable_call_ids')
@pytest.mark.usefixtures('patched_sentry')
class TestExtraContext(object):

    def test_extra(self, container_factory, service_cls, config):

        container = container_factory(service_cls, config)
        container.start()

        context_data = {
            'language': 'en-gb'
        }

        with ServiceRpcProxy(
            'service', config, context_data=context_data
        ) as rpc_proxy:
            with pytest.raises(RemoteError):
                rpc_proxy.broken()

        sentry = get_extension(container, SentryReporter)

        assert sentry.client.captureException.call_count == 1

        expected_extra = {
            'call_id_stack': [
                'standalone_rpc_proxy.call.0', 'service.broken.1'
            ],
            'language': 'en-gb'
        }

        _, kwargs = sentry.client.captureException.call_args
        assert kwargs['extra'] == expected_extra


@pytest.mark.usefixtures('predictable_call_ids')
@pytest.mark.usefixtures('patched_sentry')
class TestTagContext(object):

    def test_tags_defaults(self, container_factory, service_cls, config):

        container = container_factory(service_cls, config)
        container.start()

        with ServiceRpcProxy('service', config) as rpc_proxy:
            with pytest.raises(RemoteError):
                rpc_proxy.broken()

        sentry = get_extension(container, SentryReporter)

        assert sentry.client.captureException.call_count == 1

        expected_tags = {
            'call_id': 'service.broken.1',
            'parent_call_id': 'standalone_rpc_proxy.call.0',
            'service_name': 'service',
            'method_name': 'broken'
        }

        _, kwargs = sentry.client.captureException.call_args
        assert kwargs['data']['tags'] == expected_tags

    def test_tags_custom(self, container_factory, service_cls, config):

        config['SENTRY']['TAG_TYPE_CONTEXT_KEYS'] = (
            'session',
            'other_pattern'
        )

        container = container_factory(service_cls, config)
        container.start()

        context_data = {
            'call_id_stack': ["standalone_rpc_proxy.call.0"],
            'session_id': 1,
            'email_address': 'matt@example.com',
        }

        with ServiceRpcProxy(
            'service', config, context_data=context_data
        ) as rpc_proxy:
            with pytest.raises(RemoteError):
                rpc_proxy.broken()

        sentry = get_extension(container, SentryReporter)

        assert sentry.client.captureException.call_count == 1

        expected_tags = {
            'call_id': 'service.broken.1',
            'parent_call_id': 'standalone_rpc_proxy.call.0',
            'service_name': 'service',
            'method_name': 'broken',
            'session_id': 1,  # extra
        }

        _, kwargs = sentry.client.captureException.call_args
        assert kwargs['data']['tags'] == expected_tags


@pytest.mark.usefixtures('patched_sentry')
class TestHttpContext(object):

    @pytest.fixture
    def config(self, config, web_config):
        config.update(web_config)
        return config

    def test_normal_http_entrypoint(
        self, container_factory, config, web_session
    ):
        class Service(object):
            name = "service"

            sentry = SentryReporter()

            @http('GET', '/resource')
            def resource(self, request):
                raise CustomException()

        container = container_factory(Service, config)
        container.start()

        with entrypoint_waiter(container, 'resource'):
            web_session.get('/resource')

        sentry = get_extension(container, SentryReporter)

        assert sentry.client.captureException.call_count == 1
        _, kwargs = sentry.client.captureException.call_args

        expected_http = {
            'url': ANY,
            'query_string': "",
            'method': 'GET',
            'data': {},
            'headers': ANY,
            'env': ANY
        }
        assert kwargs['data']['request'] == expected_http

    def test_unsupported_http_entrypoint(
        self, container_factory, config, web_session
    ):
        bogus = object()

        class CustomHttpEntrypoint(HttpRequestHandler):

            def get_entrypoint_parameters(self, request):
                args = (bogus, request)
                kwargs = request.path_values
                return args, kwargs

        custom_http = CustomHttpEntrypoint.decorator

        class Service(object):
            name = "service"

            sentry = SentryReporter()

            @custom_http('GET', '/resource')
            def resource(self, bogus_arg, request):
                raise CustomException()

        container = container_factory(Service, config)
        container.start()

        with entrypoint_waiter(container, 'resource'):
            web_session.get('/resource')

        sentry = get_extension(container, SentryReporter)

        assert sentry.client.captureException.call_count == 1
        _, kwargs = sentry.client.captureException.call_args

        expected_http = {}
        assert kwargs['data']['request'] == expected_http


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

    def test_end_to_end(
        self, container_factory, service_cls, config, sentry_dsn, sentry_stub,
        tracker
    ):
        config['SENTRY']['DSN'] = sentry_dsn

        container = container_factory(service_cls, config)
        container.start()

        with entrypoint_waiter(sentry_stub, 'report'):
            with entrypoint_hook(container, 'broken') as broken:
                with entrypoint_waiter(container, 'broken'):
                    with pytest.raises(CustomException):
                        broken()

        assert tracker.called
