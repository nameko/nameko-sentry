import json
import logging
import socket

import eventlet
import pytest
from eventlet.event import Event
from mock import ANY, Mock, patch, PropertyMock
from nameko.exceptions import RemoteError
from nameko.rpc import rpc
from nameko.standalone.rpc import ServiceRpcProxy
from nameko.testing.services import (
    entrypoint_hook, entrypoint_waiter, get_extension)
from nameko.web.handlers import HttpRequestHandler, http
from raven import breadcrumbs, Client
from raven.transport.eventlet import EventletHTTPTransport
from werkzeug.exceptions import ClientDisconnected

from nameko_sentry import SentryReporter
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
    with patch.object(Client, 'send'):
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

    assert sentry.client.send.call_count == 0


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

    assert sentry.client.send.call_count == 1

    # generate expected call args
    expected_logger = "service.broken"
    expected_message = "Unhandled exception in call {}: {} {!r}".format(
        'service.broken.1', exception_cls.__name__, str(raised.value)
    )

    _, kwargs = sentry.client.send.call_args
    assert kwargs['message'] == expected_message
    assert kwargs['logger'] == expected_logger
    assert kwargs['level'] == expected_level
    assert kwargs['extra'] == ANY
    assert kwargs['tags'] == ANY
    assert kwargs['user'] == {}


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

    assert sentry.client.send.call_count == expected_count


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

        assert sentry.client.send.call_count == 1

        _, kwargs = sentry.client.send.call_args
        assert kwargs['user'] == user_data

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

        assert sentry.client.send.call_count == 1

        _, kwargs = sentry.client.send.call_args
        assert kwargs['user'] == user_data


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

        assert sentry.client.send.call_count == 1

        expected_extra = {
            'call_id_stack': (
                repr(u"standalone_rpc_proxy.call.0"), repr(u"service.broken.1")
            ),
            'language': repr(u"en-gb"),
            'sys.argv': ANY
        }

        _, kwargs = sentry.client.send.call_args
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

        assert sentry.client.send.call_count == 1

        expected_tags = {
            'site': config['SENTRY']['CLIENT_CONFIG']['site'],
            'call_id': 'service.broken.1',
            'parent_call_id': 'standalone_rpc_proxy.call.0',
            'service_name': 'service',
            'method_name': 'broken'
        }

        _, kwargs = sentry.client.send.call_args
        assert expected_tags == kwargs['tags']

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

        assert sentry.client.send.call_count == 1

        expected_tags = {
            'site': config['SENTRY']['CLIENT_CONFIG']['site'],
            'call_id': 'service.broken.1',
            'parent_call_id': 'standalone_rpc_proxy.call.0',
            'service_name': 'service',
            'method_name': 'broken',
            'session_id': '1',  # extra
        }

        _, kwargs = sentry.client.send.call_args
        assert expected_tags == kwargs['tags']


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

        assert sentry.client.send.call_count == 1
        _, kwargs = sentry.client.send.call_args

        expected_http = {
            'url': ANY,
            'query_string': "",
            'method': 'GET',
            'data': {},
            'headers': ANY,
            'env': ANY
        }
        assert kwargs['request'] == expected_http

    def test_json_payload(
        self, container_factory, config, web_session
    ):
        class Service(object):
            name = "service"

            sentry = SentryReporter()

            @http('POST', '/resource')
            def resource(self, request):
                raise CustomException()

        container = container_factory(Service, config)
        container.start()

        submitted_data = {
            'foo': 'bar'
        }
        with entrypoint_waiter(container, 'resource'):
            rv = web_session.post('/resource', json=submitted_data)
            assert rv.status_code == 500
            assert "CustomException" in rv.text

        sentry = get_extension(container, SentryReporter)

        assert sentry.client.send.call_count == 1
        _, kwargs = sentry.client.send.call_args

        received_data = kwargs['request']['data']
        assert received_data == json.dumps(submitted_data).encode('utf-8')

    def test_form_submission(
        self, container_factory, config, web_session
    ):
        class Service(object):
            name = "service"

            sentry = SentryReporter()

            @http('POST', '/resource')
            def resource(self, request):
                raise CustomException()

        container = container_factory(Service, config)
        container.start()

        submitted_data = {
            'foo': 'bar'
        }
        with entrypoint_waiter(container, 'resource'):
            web_session.post('/resource', data=submitted_data)

        sentry = get_extension(container, SentryReporter)

        assert sentry.client.send.call_count == 1
        _, kwargs = sentry.client.send.call_args

        assert kwargs['request']['data'] == submitted_data

    def test_client_disconnect(
        self, container_factory, config, web_session
    ):
        class Service(object):
            name = "service"

            sentry = SentryReporter()

            @http('POST', '/resource')
            def resource(self, request):
                raise CustomException()

        container = container_factory(Service, config)
        container.start()

        request = Mock(
            method="GET",
            url="http://example.com",
            mimetype='application/json',
            environ={}
        )
        type(request).data = PropertyMock(side_effect=ClientDisconnected)

        with entrypoint_hook(container, 'resource') as hook:
            with pytest.raises(CustomException):
                hook(request)

        sentry = get_extension(container, SentryReporter)

        assert sentry.client.send.call_count == 1
        _, kwargs = sentry.client.send.call_args

        assert kwargs['request']['data'] == {}

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

        assert sentry.client.send.call_count == 1
        _, kwargs = sentry.client.send.call_args

        expected_http = {}
        assert kwargs['request'] == expected_http


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


@pytest.mark.usefixtures('patched_sentry')
class TestConcurrency(object):

    @pytest.fixture
    def config(self, config, web_config):
        config.update(web_config)
        return config

    def test_concurrent_workers(
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

        called = Mock()

        def called_twice(worker_ctx, res, exc_info):
            called()
            return called.call_count == 2

        with entrypoint_waiter(container, 'resource', callback=called_twice):
            eventlet.spawn(web_session.get, '/resource?q1')
            eventlet.spawn(web_session.get, '/resource?q2')

        sentry = get_extension(container, SentryReporter)

        assert sentry.client.send.call_count == 2
        query_strings = {
            kwargs['request']['query_string']
            for (_, kwargs) in sentry.client.send.call_args_list
        }
        assert query_strings == {"q1", "q2"}


@pytest.mark.usefixtures('patched_sentry')
class TestWorkerUsage(object):

    @pytest.fixture
    def service_cls(self):

        class Service(object):
            name = "service"

            sentry = SentryReporter()

            @rpc
            def broken(self, data):
                self.sentry.merge({
                    "arbitrary": data
                })
                raise CustomException("Error!")

        return Service

    def test_worker_usage(self, container_factory, service_cls, config):

        container = container_factory(service_cls, config)
        container.start()

        user_data = {
            'user': 'matt'
        }
        context_data = {
            'language': 'en-gb'
        }
        context_data.update(user_data)

        data = {'foo': 'bar'}

        with ServiceRpcProxy(
            'service', config, context_data=context_data
        ) as rpc_proxy:
            with pytest.raises(RemoteError):
                rpc_proxy.broken(data)

        sentry = get_extension(container, SentryReporter)

        assert sentry.client.send.call_count == 1

        _, kwargs = sentry.client.send.call_args
        assert kwargs['user'] == user_data
        assert kwargs['arbitrary'] == data


@pytest.mark.usefixtures('patched_sentry')
class TestBreadcrumbs(object):

    @pytest.fixture
    def config(self, config, web_config):
        config.update(web_config)
        return config

    @pytest.fixture
    def service_cls(self):

        class Service(object):
            name = "service"

            sentry = SentryReporter()

            @rpc
            def record_with_helper(self, data):
                breadcrumbs.record(
                    category="worker",
                    message='breadcrumb message',
                    level='warning',
                    data=data
                )
                raise CustomException("Error!")

            @rpc
            def record_directly(self, data):
                self.sentry.breadcrumbs.record(
                    category="worker",
                    message='breadcrumb message',
                    level='warning',
                    data=data
                )
                raise CustomException("Error!")

            @rpc
            def activate_deactivate(self, a1, a2, a3):
                breadcrumbs.record(category="worker", message=a1)
                self.sentry.deactivate()
                breadcrumbs.record(category="worker", message=a2)
                self.sentry.activate()
                breadcrumbs.record(category="worker", message=a3)
                raise CustomException("Error!")

        return Service

    @pytest.mark.parametrize(
        "method", ["record_directly", "record_with_helper"]
    )
    def test_breadcrumbs(self, method, container_factory, service_cls, config):

        container = container_factory(service_cls, config)
        container.start()

        data = {'foo': 'bar'}

        with ServiceRpcProxy('service', config) as rpc_proxy:
            with pytest.raises(RemoteError):
                getattr(rpc_proxy, method)(data)

        sentry = get_extension(container, SentryReporter)

        assert sentry.client.send.call_count == 1

        _, kwargs = sentry.client.send.call_args
        breadcrumbs = [
            crumb for crumb in kwargs['breadcrumbs']['values']
            if crumb['category'] == "worker"
        ]

        assert breadcrumbs == [{
            'category': 'worker',
            'data': data,
            'level': 'warning',
            'message': 'breadcrumb message',
            'timestamp': ANY,
            'type': 'default'
        }]

    def test_activate_deactivate(self, container_factory, service_cls, config):

        container = container_factory(service_cls, config)
        container.start()

        with ServiceRpcProxy('service', config) as rpc_proxy:
            with pytest.raises(RemoteError):
                rpc_proxy.activate_deactivate("a", "b", "c")

        sentry = get_extension(container, SentryReporter)

        assert sentry.client.send.call_count == 1

        _, kwargs = sentry.client.send.call_args
        breadcrumbs = [
            crumb for crumb in kwargs['breadcrumbs']['values']
            if crumb['category'] == "worker"
        ]

        assert breadcrumbs == [{
            'category': "worker",
            'data': None,
            'level': ANY,
            'message': 'a',
            'timestamp': ANY,
            'type': 'default'
        }, {
            'category': "worker",
            'data': None,
            'level': ANY,
            'message': 'c',
            'timestamp': ANY,
            'type': 'default'
        }]

    def test_concurrency(
        self, container_factory, config, web_session
    ):

        class Service(object):
            name = "service"

            sentry = SentryReporter()

            @http('GET', '/resource')
            def resource(self, request):
                breadcrumbs.record(message=request.query_string)
                raise CustomException()

        container = container_factory(Service, config)
        container.start()

        called = Mock()

        def called_twice(worker_ctx, res, exc_info):
            called()
            return called.call_count == 2

        with entrypoint_waiter(container, 'resource', callback=called_twice):
            eventlet.spawn(web_session.get, '/resource?q1')
            eventlet.spawn(web_session.get, '/resource?q2')

        sentry = get_extension(container, SentryReporter)

        assert sentry.client.send.call_count == 2

        breadcrumbs_map = {
            kwargs['request']['query_string']: kwargs['breadcrumbs']['values']
            for (_, kwargs) in sentry.client.send.call_args_list
        }

        expected_crumb_q1 = {
            'category': None,
            'data': None,
            'level': ANY,
            'message': 'q1'.encode('utf-8'),
            'timestamp': ANY,
            'type': 'default'
        }
        assert expected_crumb_q1 in breadcrumbs_map['q1']
        assert expected_crumb_q1 not in breadcrumbs_map['q2']

        expected_crumb_q2 = {
            'category': None,
            'data': None,
            'level': ANY,
            'message': 'q2'.encode('utf-8'),
            'timestamp': ANY,
            'type': 'default'
        }
        assert expected_crumb_q2 in breadcrumbs_map['q2']
        assert expected_crumb_q2 not in breadcrumbs_map['q1']


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
        return 'eventlet+http://user:pass@127.0.0.1:{}/1'.format(free_port)

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
