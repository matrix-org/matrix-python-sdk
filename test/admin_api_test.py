import responses
import json
from matrix_client.admin_api import MatrixHttpAdminApi


class TestAdminApi:
    admin_api = MatrixHttpAdminApi("http://example.com")
    user_id = "@alice:matrix.org"
    room_id = "!gveUzqBzXPqmwvDaCZ:example.org"
    event_id = "$153119074937XoqNn::example.org"
    up_to_ts = 1531190749090
    purge_id = "dLVEjckmfggyQduS"

    @responses.activate
    def test_purge_history_eventid(self):
        purge_history_url = \
            "http://example.com/_matrix/client/r0/" \
            "admin/purge_history/%s" % self.room_id
        responses.add(
            responses.POST,
            purge_history_url,
            body='{"purge_id": "%s"}' % self.purge_id
        )
        self.admin_api.purge_history(self.room_id, self.event_id)
        req = responses.calls[0].request
        assert req.url == purge_history_url
        assert req.method == 'POST'
        j = json.loads(req.body)
        assert j["delete_local_events"]
        assert j["purge_up_to_event_id"] == self.event_id

    @responses.activate
    def test_purge_history_up_to_ts(self):
        purge_history_url = \
            "http://example.com/_matrix/client/r0/" \
            "admin/purge_history/%s" % self.room_id
        responses.add(
            responses.POST,
            purge_history_url,
            body='{"purge_id": "%s"}' % self.purge_id
        )
        self.admin_api.purge_history(self.room_id, self.up_to_ts)
        req = responses.calls[0].request
        j = json.loads(req.body)
        assert j["delete_local_events"]
        assert j["purge_up_to_ts"] == self.up_to_ts

    @responses.activate
    def test_purge_history_status(self):
        purge_history_status_url = \
            "http://example.com/_matrix/client/r0/" \
            "admin/purge_history_status/%s" % self.purge_id
        responses.add(
            responses.GET,
            purge_history_status_url,
            body='{"status": "complete"}'
        )
        self.admin_api.purge_history_status(self.purge_id)
        req = responses.calls[0].request
        assert req.url == purge_history_status_url

    @responses.activate
    def test_media_in_room(self):
        media_url = \
            "http://example.com/_matrix/client/r0/" \
            "admin/room/%s/media" % self.room_id
        responses.add(
            responses.GET,
            media_url,
            body='{"local": ["mxc://example.com/xwvutsrqponmlkjihgfedcba"],'
            ' "remote": ["mxc://matrix.org/xwtttsrqponmlkjihgfedcba"]}'
        )
        resp = self.admin_api.media_in_room(self.room_id)
        req = responses.calls[0].request
        assert req.url == media_url
        assert req.method == 'GET'
        assert "local" in resp
        assert "remote" in resp

    @responses.activate
    def test_whois(self):
        whois_url = \
            "http://example.com/_matrix/client/r0/" \
            "admin/whois/%s" % self.user_id
        responses.add(
            responses.GET,
            whois_url,
            body='{"user_id": "%s", "devices": {}}' % self.user_id
        )
        self.admin_api.whois(self.user_id)
        req = responses.calls[0].request
        assert req.url == whois_url
        assert req.method == 'GET'

    @responses.activate
    def test_deactivate_no_erase(self):
        erase_url = \
            "http://example.com/_matrix/client/r0/" \
            "admin/deactivate/%s" % self.user_id
        responses.add(responses.POST, erase_url, body='{}')
        self.admin_api.deactivate(self.user_id)
        req = responses.calls[0].request
        assert req.url == erase_url
        assert req.method == 'POST'

    @responses.activate
    def test_deactivate(self):
        erase_url = \
            "http://example.com/_matrix/client/r0/" \
            "admin/deactivate/%s" % self.user_id
        responses.add(responses.POST, erase_url, body='{}')
        self.admin_api.deactivate(self.user_id, erase=True)
        req = responses.calls[0].request
        assert req.url == erase_url
        assert req.method == 'POST'
        j = json.loads(req.body)
        assert j["erase"]

    @responses.activate
    def test_reset_password(self):
        reset_url = \
            "http://example.com/_matrix/client/r0/" \
            "admin/reset_password/%s" % self.user_id
        responses.add(responses.POST, reset_url, body='{}')
        self.admin_api.reset_password(self.user_id, 'secret')
        req = responses.calls[0].request
        assert req.url == reset_url
        assert req.method == 'POST'
        j = json.loads(req.body)
        assert j["new_password"] == 'secret'

    @responses.activate
    def test_quarantine_media(self):
        quarantine_media_url = \
            "http://example.com/_matrix/client/r0/" \
            "admin/quarantine_media/%s" % self.room_id
        responses.add(
            responses.POST,
            quarantine_media_url,
            body='{"num_quarantined": 1}'
        )
        self.admin_api.quarantine_media(self.room_id)
        req = responses.calls[0].request
        assert req.url == quarantine_media_url
        assert req.method == 'POST'

    @responses.activate
    def test_shutdown_room(self):
        shutdown_room_url = \
            "http://example.com/_matrix/client/r0/" \
            "admin/shutdown_room/%s" % self.room_id
        responses.add(
            responses.POST,
            shutdown_room_url,
            body='{"kicked_users": 2, '
            '"local_aliases": [], '
            '"new_room_id": "!hepuyalbwtkjapqdhq:example.org"}'
        )
        self.admin_api.shutdown_room(
            self.room_id,
            self.user_id,
            room_name="New room",
            message="Old room closed by admin"
        )
        req = responses.calls[0].request
        assert req.url == shutdown_room_url
        assert req.method == 'POST'
        j = json.loads(req.body)
        assert j["new_room_user_id"] == self.user_id
