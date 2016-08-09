from matrix_client.client import MatrixClient, Room, User
import pytest


def test_create_client():
    MatrixClient("http://example.com")


def test_sync_token():
    client = MatrixClient("http://example.com")
    assert client.get_sync_token() is None
    client.set_sync_token("FAKE_TOKEN")
    assert client.get_sync_token() is "FAKE_TOKEN"


def test__mkroom():
    client = MatrixClient("http://example.com")

    roomId = "!UcYsUzyxTGDxLBEvLz:matrix.org"
    goodRoom = client._mkroom(roomId)

    assert isinstance(goodRoom, Room)
    assert goodRoom.room_id is roomId

    with pytest.raises(ValueError):
        client._mkroom("BAD_ROOM:matrix.org")
        client._mkroom("!BAD_ROOMmatrix.org")
        client._mkroom("!BAD_ROOM::matrix.org")


def test_get_rooms():
    client = MatrixClient("http://example.com")
    rooms = client.get_rooms()
    assert isinstance(rooms, dict)
    assert len(rooms) == 0

    client = MatrixClient("http://example.com")

    client._mkroom("!abc:matrix.org")
    client._mkroom("!def:matrix.org")
    client._mkroom("!ghi:matrix.org")

    rooms = client.get_rooms()
    assert isinstance(rooms, dict)
    assert len(rooms) == 3


def test_bad_state_events():
    client = MatrixClient("http://example.com")
    room = client._mkroom("!abc:matrix.org")

    ev = {
        "tomato": False
    }

    client._process_state_event(ev, room)


def test_state_event():
    client = MatrixClient("http://example.com")
    room = client._mkroom("!abc:matrix.org")

    room.name = False
    room.topic = False
    room.aliases = False

    ev = {
        "type": "m.room.name",
        "content": {}
    }

    client._process_state_event(ev, room)
    assert room.name is None

    ev["content"]["name"] = "TestName"
    client._process_state_event(ev, room)
    assert room.name is "TestName"

    ev["type"] = "m.room.topic"
    client._process_state_event(ev, room)
    assert room.topic is None

    ev["content"]["topic"] = "TestTopic"
    client._process_state_event(ev, room)
    assert room.topic is "TestTopic"

    ev["type"] = "m.room.aliases"
    client._process_state_event(ev, room)
    assert room.aliases is None

    aliases = ["#foo:matrix.org", "#bar:matrix.org"]
    ev["content"]["aliases"] = aliases
    client._process_state_event(ev, room)
    assert room.aliases is aliases


def test_get_user():
    client = MatrixClient("http://example.com")

    assert isinstance(client.get_user("@foobar:matrix.org"), User)

    with pytest.raises(ValueError):
        client.get_user("badfoobar:matrix.org")
        client.get_user("@badfoobarmatrix.org")
        client.get_user("@badfoobar:::matrix.org")


def test_get_download_url():
    client = MatrixClient("http://example.com")
    real_url = "http://example.com/_matrix/media/r0/download/foobar"
    assert client.api.get_download_url("mxc://foobar") == real_url

    with pytest.raises(ValueError):
        client.api.get_download_url("http://foobar")
