# flake8: noqa E501
import json
from asyncio import Future
from functools import partial
from urllib.parse import quote
from unittest.mock import MagicMock, Mock, call

import pytest
import matrix_client.errors

from matrix_client.api_asyncio import AsyncHTTPAPI

HEADERS = {'Authorization': 'Bearer 1234', 'Content-Type': 'application/json', 'User-Agent': 'matrix-python-sdk/0.4.0-dev'}


def client_session(json, status=200):
    client_session = MagicMock()

    class MockResponse(MagicMock):
        called = 0

        async def __aenter__(self):
            response = MagicMock()
            f = Future()
            f.set_result(json)
            response.json = Mock(return_value=f)
            response.status = self.status()
            f = Future()
            f.set_result("hello")
            response.text = Mock(return_value=f)
            return response

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

        def status(self):
            if status == 429 and self.called > 0:
                return 200
            else:
                self.called += 1
                return status

    client_session.request = MockResponse()

    return client_session


@pytest.fixture
def api():
    return partial(AsyncHTTPAPI, base_url="http://base_url", token="1234")


@pytest.mark.asyncio
async def test_send(api):
    api = api(client_session=client_session({}))

    await api._send("GET", "/createRoom")
    api.client_session.request.assert_called_once_with("GET",
                                                       "http://base_url/_matrix/client/r0/createRoom",
                                                       data="{}",
                                                       headers=HEADERS,
                                                       params={})


@pytest.mark.asyncio
async def test_send_429(api):
    api = api(client_session=client_session({}, status=429))

    await api._send("GET", "/createRoom")
    call429 = call("GET",
                   "http://base_url/_matrix/client/r0/createRoom",
                   data="{}",
                   headers=HEADERS,
                   params={})

    # If we 429 we should call request twice with the same parameters
    api.client_session.request.assert_has_calls([call429, call429])


@pytest.mark.parametrize("json", [{"error": '{"retry_after_ms": 10}'},
                                  {"error": {"retry_after_ms": 10}},
                                  {"retry_after_ms": 10}])
@pytest.mark.asyncio
async def test_send_429_timeout(api, json):
    api = api(client_session=client_session(json, status=429))

    await api._send("GET", "/createRoom")

    call429 = call("GET",
                   "http://base_url/_matrix/client/r0/createRoom",
                   data="{}",
                   headers=HEADERS,
                   params={})

    # If we 429 we should call request twice with the same parameters
    api.client_session.request.assert_has_calls([call429, call429])


@pytest.mark.asyncio
async def test_send_404(api):
    api = api(client_session=client_session({}, status=404))

    with pytest.raises(matrix_client.errors.MatrixRequestError) as exc:
        await api._send("GET", "/createRoom")
        assert exc.status == 404
        assert exc.content == "hello"


@pytest.mark.asyncio
async def test_get_displayname(api):
    api = api(client_session=client_session({"displayname": "African swallow"}))
    mxid = "@user:test"
    displayname = await api.get_display_name(mxid)
    assert displayname == "African swallow"

    api.client_session.request.assert_called_once_with("GET",
                                                       f"http://base_url/_matrix/client/r0/profile/{mxid}/displayname",
                                                       data="{}",
                                                       headers=HEADERS,
                                                       params={})


@pytest.mark.asyncio
async def test_set_displayname(api):
    api = api(client_session=client_session({}))
    mxid = "@user:test"
    await api.set_display_name(mxid, "African swallow")

    api.client_session.request.assert_called_once_with("PUT",
                                                       f"http://base_url/_matrix/client/r0/profile/{mxid}/displayname",
                                                       data='{"displayname": "African swallow"}',
                                                       headers=HEADERS,
                                                       params={})


@pytest.mark.asyncio
async def test_get_avatar_url(api):
    api = api(client_session=client_session({"avatar_url": "mxc://hello"}))
    mxid = "@user:test"
    url = await api.get_avatar_url(mxid)
    assert url == "mxc://hello"

    api.client_session.request.assert_called_once_with("GET",
                                                       f"http://base_url/_matrix/client/r0/profile/{mxid}/avatar_url",
                                                       data="{}",
                                                       headers=HEADERS,
                                                       params={})


@pytest.mark.asyncio
async def test_get_room_id(api):
    api = api(client_session=client_session({"room_id": "aroomid"}))
    room_alias = "#test:test"
    aid = await api.get_room_id(room_alias)
    assert aid == "aroomid"

    api.client_session.request.assert_called_once_with("GET",
                                                       f"http://base_url/_matrix/client/r0/directory/room/{quote(room_alias)}",
                                                       data="{}",
                                                       headers=HEADERS,
                                                       params={})


@pytest.mark.asyncio
async def test_get_room_displayname(api):
    mxid = "@user:test"
    api = api(client_session=client_session({"chunk":
                                             [{"sender": mxid, "content": {"displayname": "African swallow"}}]}))
    displayname = await api.get_room_displayname("arromid", mxid)
    assert displayname == "African swallow"

    api.client_session.request.assert_called_once_with("GET",
                                                       f"http://base_url/_matrix/client/r0/rooms/arromid/members",
                                                       data="{}",
                                                       headers=HEADERS,
                                                       params={})


# Test the wrapping of a sync method
@pytest.mark.asyncio
async def test_sync_wrap(api):
    api = api(client_session=client_session({}))
    roomid = "!ldjaslkdja:test"
    eventid = "$alskdjsalkdjal:test"
    await api.get_event_in_room(roomid, eventid)

    api.client_session.request.assert_called_once_with("GET",
                                                       f"http://base_url/_matrix/client/r0/rooms/{roomid}/event/{eventid}",
                                                       data="{}",
                                                       headers=HEADERS,
                                                       params={})


# Test no access token
@pytest.mark.asyncio
async def test_login(api):
    api = AsyncHTTPAPI(base_url="http://base_url", client_session=client_session({}))
    await api.login("bob")

    api.client_session.request.assert_called_once_with("POST",
                                                       f"http://base_url/_matrix/client/r0/login",
                                                       data=json.dumps({"type": "bob"}),
                                                       headers={'User-Agent': 'matrix-python-sdk/0.4.0-dev', "Content-Type": "application/json"},
                                                       params={})
