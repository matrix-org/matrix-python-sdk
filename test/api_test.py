import responses
import pytest
from matrix_client import client
from matrix_client.errors import MatrixRequestError


class TestTagsApi:
    cli = client.MatrixClient("http://example.com")
    user_id = "@user:matrix.org"
    room_id = "#foo:matrix.org"

    @responses.activate
    def test_get_user_tags(self):
        tags_url = "http://example.com" \
            "/_matrix/client/r0/user/@user:matrix.org/rooms/#foo:matrix.org/tags"
        responses.add(responses.GET, tags_url, body='{}')
        self.cli.api.get_user_tags(self.user_id, self.room_id)
        req = responses.calls[0].request
        assert req.url == tags_url
        assert req.method == 'GET'

    @responses.activate
    def test_add_user_tags(self):
        tags_url = "http://example.com" \
            "/_matrix/client/r0/user/@user:matrix.org/rooms/#foo:matrix.org/tags/foo"
        responses.add(responses.PUT, tags_url, body='{}')
        self.cli.api.add_user_tag(self.user_id, self.room_id, "foo", body={"order": "5"})
        req = responses.calls[0].request
        assert req.url == tags_url
        assert req.method == 'PUT'

    @responses.activate
    def test_remove_user_tags(self):
        tags_url = "http://example.com" \
            "/_matrix/client/r0/user/@user:matrix.org/rooms/#foo:matrix.org/tags/foo"
        responses.add(responses.DELETE, tags_url, body='{}')
        self.cli.api.remove_user_tag(self.user_id, self.room_id, "foo")
        req = responses.calls[0].request
        assert req.url == tags_url
        assert req.method == 'DELETE'


class TestAccountDataApi:
    cli = client.MatrixClient("http://example.com")
    user_id = "@user:matrix.org"
    room_id = "#foo:matrix.org"

    @responses.activate
    def test_set_account_data(self):
        account_data_url = "http://example.com" \
            "/_matrix/client/r0/user/@user:matrix.org/account_data/foo"
        responses.add(responses.PUT, account_data_url, body='{}')
        self.cli.api.set_account_data(self.user_id, 'foo', {'bar': 1})
        req = responses.calls[0].request
        assert req.url == account_data_url
        assert req.method == 'PUT'

    @responses.activate
    def test_set_room_account_data(self):
        account_data_url = "http://example.com/_matrix/client/r0/user" \
            "/@user:matrix.org/rooms/#foo:matrix.org/account_data/foo"
        responses.add(responses.PUT, account_data_url, body='{}')
        self.cli.api.set_room_account_data(self.user_id, self.room_id, 'foo', {'bar': 1})
        req = responses.calls[0].request
        assert req.url == account_data_url
        assert req.method == 'PUT'


class TestUnbanApi:
    cli = client.MatrixClient("http://example.com")
    user_id = "@user:matrix.org"
    room_id = "#foo:matrix.org"

    @responses.activate
    def test_unban(self):
        unban_url = "http://example.com" \
                    "/_matrix/client/r0/rooms/#foo:matrix.org/unban"
        body = '{"user_id": "' + self.user_id + '"}'
        responses.add(responses.POST, unban_url, body=body)
        self.cli.api.unban_user(self.room_id, self.user_id)
        req = responses.calls[0].request
        assert req.url == unban_url
        assert req.method == 'POST'


class TestDeviceApi:
    cli = client.MatrixClient("http://example.com")
    device_id = "QBUAZIFURK"
    display_name = "test_name"
    auth_body = {
        "auth": {
            "type": "example.type.foo",
            "session": "xxxxx",
            "example_credential": "verypoorsharedsecret"
        }
    }

    @responses.activate
    def test_get_devices(self):
        get_devices_url = "http://example.com/_matrix/client/r0/devices"
        responses.add(responses.GET, get_devices_url, body='{}')
        self.cli.api.get_devices()
        req = responses.calls[0].request
        assert req.url == get_devices_url
        assert req.method == 'GET'

    @responses.activate
    def test_get_device(self):
        get_device_url = "http://example.com/_matrix/client/r0/devices/QBUAZIFURK"
        responses.add(responses.GET, get_device_url, body='{}')
        self.cli.api.get_device(self.device_id)
        req = responses.calls[0].request
        assert req.url == get_device_url
        assert req.method == 'GET'

    @responses.activate
    def test_update_device_info(self):
        update_url = "http://example.com/_matrix/client/r0/devices/QBUAZIFURK"
        responses.add(responses.PUT, update_url, body='{}')
        self.cli.api.update_device_info(self.device_id, self.display_name)
        req = responses.calls[0].request
        assert req.url == update_url
        assert req.method == 'PUT'

    @responses.activate
    def test_delete_device(self):
        delete_device_url = "http://example.com/_matrix/client/r0/devices/QBUAZIFURK"
        responses.add(responses.DELETE, delete_device_url, body='{}')
        # Test for 401 status code of User-Interactive Auth API
        responses.add(responses.DELETE, delete_device_url, body='{}', status=401)
        self.cli.api.delete_device(self.auth_body, self.device_id)
        req = responses.calls[0].request
        assert req.url == delete_device_url
        assert req.method == 'DELETE'

        with pytest.raises(MatrixRequestError):
            self.cli.api.delete_device(self.auth_body, self.device_id)

    @responses.activate
    def test_delete_devices(self):
        delete_devices_url = "http://example.com/_matrix/client/r0/delete_devices"
        responses.add(responses.POST, delete_devices_url, body='{}')
        # Test for 401 status code of User-Interactive Auth API
        responses.add(responses.POST, delete_devices_url, body='{}', status=401)
        self.cli.api.delete_devices(self.auth_body, [self.device_id])
        req = responses.calls[0].request
        assert req.url == delete_devices_url
        assert req.method == 'POST'

        with pytest.raises(MatrixRequestError):
            self.cli.api.delete_devices(self.auth_body, [self.device_id])
