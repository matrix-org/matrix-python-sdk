import responses
from matrix_client import client, api
import json
import re
from future.moves.urllib.parse import quote


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
                "/_matrix/client/api/v1/rooms/#foo:matrix.org/unban"
        body = '{"user_id": "'+ self.user_id + '"}'
        responses.add(responses.POST, unban_url, body=body)
        self.cli.api.unban_user(self.room_id, self.user_id)
        req = responses.calls[0].request
        assert req.url == unban_url
        assert req.method == 'POST'


class TestASApi:
    user = "@user:example.com"
    url = "http://example.com"
    api = api.MatrixASHttpAPI(user, url, token="foobar")

    @responses.activate
    def test_register(self):
        register_url = self.url + "/_matrix/client/api/v1/register"
        req_body = {"username": "user",
                    "type": "m.login.application_service"}
        responses.add(responses.POST, register_url, body="{}",status=200)

        self.api.register()
        req = responses.calls[0].request
        assert req.url == register_url + "?access_token=foobar"
        assert req.method == "POST"
        assert json.loads(req.body) == req_body

    @responses.activate
    def test_send_message(self):
        room = "!123:example.com"
        quoted_room = quote(room)
        msg_url_re = re.compile(self.url + "/_matrix/client/api/v1/rooms/" +
                                quoted_room + "/send/m.room.message/[0-9]+")
        req_body = {"msgtype": "m.text", "body": "Hello!"}
        responses.add(responses.PUT, msg_url_re, body="{}", status=200)

        self.api.send_message(room, "Hello!")
        req = responses.calls[0].request
        # Multiple parameters with no way of knowing order
        main_req_url, params = req.url.split("?")
        params_dict = dict([p.split("=") for p in params.split("&")])
        assert msg_url_re.search(main_req_url)
        assert req.method == "PUT"
        assert json.loads(req.body) == req_body
        assert params_dict == {"access_token": "foobar", "user_id": quote(self.user)}
