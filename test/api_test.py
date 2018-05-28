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
        responses.add(responses.POST, unban_url, body='{}')
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


class TestKeysApi:
    cli = client.MatrixClient("http://example.com")
    user_id = "@alice:matrix.org"
    device_id = "JLAFKJWSCS"
    one_time_keys = {"curve25519:AAAAAQ": "/qyvZvwjiTxGdGU0RCguDCLeR+nmsb3FfNG3/Ve4vU8"}
    device_keys = {
        "user_id": "@alice:example.com",
        "device_id": "JLAFKJWSCS",
        "algorithms": [
            "m.olm.curve25519-aes-sha256",
            "m.megolm.v1.aes-sha"
        ],
        "keys": {
            "curve25519:JLAFKJWSCS": "3C5BFWi2Y8MaVvjM8M22DBmh24PmgR0nPvJOIArzgyI",
            "ed25519:JLAFKJWSCS": "lEuiRJBit0IG6nUf5pUzWTUEsRVVe/HJkoKuEww9ULI"
        },
        "signatures": {
            "@alice:example.com": {
                "ed25519:JLAFKJWSCS": ("dSO80A01XiigH3uBiDVx/EjzaoycHcjq9lfQX0uWsqxl2gi"
                                       "MIiSPR8a4d291W1ihKJL/a+myXS367WT6NAIcBA")
            }
        }
    }

    @responses.activate
    @pytest.mark.parametrize("args", [
        {},
        {'device_keys': device_keys},
        {'one_time_keys': one_time_keys}
    ])
    def test_upload_keys(self, args):
        upload_keys_url = "http://example.com/_matrix/client/r0/keys/upload"
        responses.add(responses.POST, upload_keys_url, body='{}')
        self.cli.api.upload_keys(**args)
        req = responses.calls[0].request
        assert req.url == upload_keys_url
        assert req.method == 'POST'

    @responses.activate
    def test_query_keys(self):
        query_user_keys_url = "http://example.com/_matrix/client/r0/keys/query"
        responses.add(responses.POST, query_user_keys_url, body='{}')
        self.cli.api.query_keys({self.user_id: self.device_id}, timeout=10)
        req = responses.calls[0].request
        assert req.url == query_user_keys_url
        assert req.method == 'POST'

    @responses.activate
    def test_claim_keys(self):
        claim_keys_url = "http://example.com/_matrix/client/r0/keys/claim"
        responses.add(responses.POST, claim_keys_url, body='{}')
        self.cli.api.claim_keys({self.user_id: {self.device_id: "algo"}}, timeout=1000)
        req = responses.calls[0].request
        assert req.url == claim_keys_url
        assert req.method == 'POST'

    @responses.activate
    def test_key_changes(self):
        key_changes_url = "http://example.com/_matrix/client/r0/keys/changes"
        responses.add(responses.GET, key_changes_url, body='{}')
        self.cli.api.key_changes('s72594_4483_1934', 's75689_5632_2435')
        req = responses.calls[0].request
        assert req.url.split('?')[0] == key_changes_url
        assert req.method == 'GET'


class TestSendToDeviceApi:
    cli = client.MatrixClient("http://example.com")
    user_id = "@alice:matrix.org"
    device_id = "JLAFKJWSCS"

    @responses.activate
    def test_send_to_device(self):
        txn_id = self.cli.api._make_txn_id()
        send_to_device_url = \
            "http://example.com/_matrix/client/r0/sendToDevice/m.new_device/" + txn_id
        responses.add(responses.PUT, send_to_device_url, body='{}')
        payload = {self.user_id: {self.device_id: {"test": 1}}}
        self.cli.api.send_to_device("m.new_device", payload, txn_id)
        req = responses.calls[0].request
        assert req.url == send_to_device_url
        assert req.method == 'PUT'
