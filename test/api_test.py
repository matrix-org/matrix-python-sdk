import responses
import json
try:
    from urllib import quote
except ImportError:
    from urllib.parse import quote

from matrix_client import client


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


class TestGroupsApi:
    cli = client.MatrixClient("http://example.com")
    user_id = "@user:matrix.org"
    room_id = "#foo:matrix.org"
    localpart = "testgroup"
    group_id = "+testgroup:matrix.org"

    @responses.activate
    def test_create_group(self):
        create_url = "http://example.com" \
            "/_matrix/client/r0/create_group"
        body = '{"group_id": "+' + self.localpart + ':matrix.org"}'
        responses.add(responses.POST, create_url, body=body)

        self.cli.api.create_group(self.localpart)

        req = responses.calls[0].request
        resp = responses.calls[0].response

        assert req.url == create_url
        assert req.method == 'POST'
        assert resp.json()['group_id'] == "+" + self.localpart + ":matrix.org"

    @responses.activate
    def test_invite_to_group(self):
        url = "http://example.com" \
            "/_matrix/client/r0/groups/" + quote(self.group_id) + \
            "/admin/users/invite/" + quote(self.user_id)
        body = '{"state": "invite"}'
        responses.add(responses.PUT, url, body=body)

        self.cli.api.invite_user_to_group(self.group_id, self.user_id)

        req = responses.calls[0].request

        assert req.url == url
        assert req.method == 'PUT'

    @responses.activate
    def test_kick_from_group(self):
        url = "http://example.com" \
            "/_matrix/client/r0/groups/" + quote(self.group_id) + \
            "/admin/users/remove/" + quote(self.user_id)
        body = '{}'
        responses.add(responses.PUT, url, body=body)

        self.cli.api.kick_user_from_group(self.group_id, self.user_id)

        req = responses.calls[0].request

        assert req.url == url
        assert req.method == 'PUT'

    @responses.activate
    def test_add_room_to_group(self):
        url = "http://example.com" \
            "/_matrix/client/r0/groups/" + quote(self.group_id) + \
            "/admin/rooms/" + quote(self.room_id)
        body = '{}'
        responses.add(responses.PUT, url, body=body)

        self.cli.api.add_room_to_group(self.group_id, self.room_id)

        req = responses.calls[0].request

        assert req.url == url
        assert req.method == 'PUT'

    @responses.activate
    def test_remove_room_from_group(self):
        url = "http://example.com" \
            "/_matrix/client/r0/groups/" + quote(self.group_id) + \
            "/admin/rooms/" + quote(self.room_id)
        body = '{}'
        responses.add(responses.DELETE, url, body=body)

        self.cli.api.remove_room_from_group(self.group_id, self.room_id)

        req = responses.calls[0].request

        assert req.url == url
        assert req.method == 'DELETE'

    @responses.activate
    def test_update_group_profile(self):
        url = "http://example.com" \
              "/_matrix/client/r0/groups/" + quote(self.group_id) + \
              "/profile"
        body = '{}'
        responses.add(responses.POST, url, body=body)

        profile_data = {"name": "New Name", "short_description": "Test Description"}
        self.cli.api.update_group_profile(self.group_id, profile_data)

        req = responses.calls[0].request

        assert req.url == url
        assert req.method == 'POST'

    @responses.activate
    def test_get_group_profile(self):
        url = "http://example.com" \
              "/_matrix/client/r0/groups/" + quote(self.group_id) + \
              "/profile"
        body = '''{
            "name": "Group Name",
            "avatar_url": "",
            "short_description": "A one line, relatively short, description of the group",
            "long_description": "A longer multi line description of the group"
        }'''
        responses.add(responses.GET, url, body=body)

        self.cli.api.get_group_profile(self.group_id)

        req = responses.calls[0].request

        assert req.url == url
        assert req.method == 'GET'

    @responses.activate
    def test_get_users_in_group(self):
        url = "http://example.com" \
              "/_matrix/client/r0/groups/" + quote(self.group_id) + \
              "/users"
        # FIXME This seems not to be stable yet! See the specs / specs proposal.
        body = '''{
           "chunk": [
                {"user_id": "@user:matrix.org"}
           ]
        }'''
        responses.add(responses.GET, url, body=body)

        self.cli.api.get_users_in_group(self.group_id)

        req = responses.calls[0].request

        assert req.url == url
        assert req.method == 'GET'

    @responses.activate
    def test_get_invited_users_in_group(self):
        url = "http://example.com" \
              "/_matrix/client/r0/groups/" + quote(self.group_id) + \
              "/invited_users"
        # FIXME This seems not to be stable yet! See the specs / specs proposal.
        body = '''{
           "chunk": [
                {"user_id": "@user:matrix.org"}
           ]
        }'''
        responses.add(responses.GET, url, body=body)

        self.cli.api.get_invited_users_in_group(self.group_id)

        req = responses.calls[0].request

        assert req.url == url
        assert req.method == 'GET'

    @responses.activate
    def test_get_rooms_in_group(self):
        url = "http://example.com" \
              "/_matrix/client/r0/groups/" + quote(self.group_id) + \
              "/rooms"
        body = '''{
           "chunk": [
                {"room_id": "#foo:matrix.org"}
           ]
        }'''
        responses.add(responses.GET, url, body=body)

        self.cli.api.get_rooms_in_group(self.group_id)

        req = responses.calls[0].request

        assert req.url == url
        assert req.method == 'GET'

    @responses.activate
    def test_accept_group_invitation(self):
        url = "http://example.com" \
              "/_matrix/client/r0/groups/" + quote(self.group_id) + \
              "/self/accept_invite"
        body = '{}'
        responses.add(responses.PUT, url, body=body)

        self.cli.api.accept_group_invitation(self.group_id)

        req = responses.calls[0].request

        assert req.url == url
        assert req.method == 'PUT'

    @responses.activate
    def test_leave_group(self):
        url = "http://example.com" \
              "/_matrix/client/r0/groups/" + quote(self.group_id) + \
              "/self/leave"
        body = '{}'
        responses.add(responses.PUT, url, body=body)

        self.cli.api.leave_group(self.group_id)

        req = responses.calls[0].request

        assert req.url == url
        assert req.method == 'PUT'

    @responses.activate
    def test_publicise_group(self):
        url = "http://example.com" \
              "/_matrix/client/r0/groups/" + quote(self.group_id) + \
              "/self/update_publicity"
        body = '{}'
        responses.add(responses.PUT, url, body=body)

        self.cli.api.publicise_group(self.group_id, True)

        req = responses.calls[0].request

        assert req.url == url
        assert req.method == 'PUT'
        assert json.loads(req.body)['publicise']

    @responses.activate
    def test_get_joined_groups(self):
        url = "http://example.com" \
              "/_matrix/client/r0/joined_groups"
        body = '{}'
        responses.add(responses.GET, url, body=body)

        self.cli.api.get_joined_groups()

        req = responses.calls[0].request

        assert req.url == url
        assert req.method == 'GET'
