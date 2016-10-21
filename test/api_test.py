import responses
from matrix_client import client


class TestTagsApi:
    cli = client.MatrixClient("https://example.com")
    user_id = "@user:matrix.org"
    room_id = "#foo:matrix.org"

    @responses.activate
    def test_get_user_tags(self):

        tags_url = "https://example.com" \
            "/_matrix/client/r0/user/@user:matrix.org/rooms/#foo:matrix.org/tags"
        responses.add(responses.GET, tags_url, body='{}')
        self.cli.api.get_user_tags(self.user_id, self.room_id)
        req = responses.calls[0].request
        assert req.url == tags_url
        assert req.method == 'GET'

    @responses.activate
    def test_add_user_tags(self):
        tags_url = "https://example.com" \
            "/_matrix/client/r0/user/@user:matrix.org/rooms/#foo:matrix.org/tags/foo"
        responses.add(responses.PUT, tags_url, body='{}')
        self.cli.api.add_user_tag(self.user_id, self.room_id, "foo", body={"order": "5"})
        req = responses.calls[0].request
        assert req.url == tags_url
        assert req.method == 'PUT'

    @responses.activate
    def test_remove_user_tags(self):
        tags_url = "https://example.com" \
            "/_matrix/client/r0/user/@user:matrix.org/rooms/#foo:matrix.org/tags/foo"
        responses.add(responses.DELETE, tags_url, body='{}')
        self.cli.api.remove_user_tag(self.user_id, self.room_id, "foo")
        req = responses.calls[0].request
        assert req.url == tags_url
        assert req.method == 'DELETE'
