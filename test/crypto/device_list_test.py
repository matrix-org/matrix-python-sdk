import pytest
pytest.importorskip("olm")  # noqa

import json
from copy import deepcopy
from threading import Event, Condition

import responses

from matrix_client.api import MATRIX_V2_API_PATH
from matrix_client.client import MatrixClient
from matrix_client.room import User
from matrix_client.errors import MatrixRequestError
from matrix_client.crypto.olm_device import OlmDevice
from matrix_client.crypto.device_list import (_OutdatedUsersSet as OutdatedUsersSet,
                                              _UpdateDeviceList as UpdateDeviceList)
from test.response_examples import example_key_query_response

HOSTNAME = 'http://example.com'


class TestDeviceList:
    cli = MatrixClient(HOSTNAME)
    user_id = '@test:example.com'
    alice = '@alice:example.com'
    room_id = '!test:example.com'
    device_id = 'AUIETSRN'
    device = OlmDevice(cli.api, user_id, device_id)
    device_list = device.device_list
    signing_key = device.olm_account.identity_keys['ed25519']
    query_url = HOSTNAME + MATRIX_V2_API_PATH + '/keys/query'

    @responses.activate
    def test_download_device_keys(self):
        # The method we want to test
        download_device_keys = self.device_list._download_device_keys
        bob = '@bob:example.com'
        eve = '@eve:example.com'
        user_devices = {self.alice: [], bob: [], self.user_id: []}

        # This response is correct for Alice's keys, but lacks Bob's
        # There are no failures
        resp = example_key_query_response
        responses.add(responses.POST, self.query_url, json=resp)

        # Still correct, but Alice's identity key has changed
        resp = deepcopy(example_key_query_response)
        new_id_key = 'ijxGZqwB/UvMtKABdaCdrI0OtQI6NhHBYiknoCkdWng'
        payload = resp['device_keys'][self.alice]['JLAFKJWSCS']
        payload['keys']['curve25519:JLAFKJWSCS'] = new_id_key
        payload['signatures'][self.alice]['ed25519:JLAFKJWSCS'] = \
            ('D9oLtYefMIr4StiHTIzn3+bhtPCfrZNDU9jsUbMu3MicfZLl4d8WlYn3TPmbwDi8XMGcT'
             'nNnqfdi/tYUPvKfCA')
        responses.add(responses.POST, self.query_url, json=resp)

        # Still correct, but Alice's signing key has changed
        alice_device = OlmDevice(self.cli.api, self.alice, 'JLAFKJWSCS')
        resp = deepcopy(example_key_query_response)
        resp['device_keys'][self.alice]['JLAFKJWSCS']['keys']['ed25519:JLAFKJWSCS'] = \
            alice_device.identity_keys['ed25519']
        resp['device_keys'][self.alice]['JLAFKJWSCS'] = \
            alice_device.sign_json(resp['device_keys'][self.alice]['JLAFKJWSCS'])
        responses.add(responses.POST, self.query_url, json=resp)

        # Response containing an unknown user
        resp = deepcopy(example_key_query_response)
        user_device = resp['device_keys'].pop(self.alice)
        resp['device_keys'][eve] = user_device
        responses.add(responses.POST, self.query_url, json=resp)

        # Response with an invalid signature
        resp = deepcopy(example_key_query_response)
        resp['device_keys'][self.alice]['JLAFKJWSCS']['test'] = 1
        responses.add(responses.POST, self.query_url, json=resp)

        # Response with a requested user and valid signature, but with a mismatch
        resp = deepcopy(example_key_query_response)
        user_device = resp['device_keys'].pop(self.alice)
        resp['device_keys'][bob] = user_device
        responses.add(responses.POST, self.query_url, json=resp)

        # Response with an invalid keys field
        resp = deepcopy(example_key_query_response)
        keys_field = resp['device_keys'][self.alice]['JLAFKJWSCS']['keys']
        key = keys_field.pop("ed25519:JLAFKJWSCS")
        keys_field["ed25519:wrong"] = key
        # Cover a missing branch by adding failures
        resp["failures"]["other.com"] = {}
        # And one more by adding ourself
        resp['device_keys'][self.user_id] = {self.device_id: 'dummy'}
        responses.add(responses.POST, self.query_url, json=resp)

        self.device.device_keys.clear()
        assert download_device_keys(user_devices)
        req = json.loads(responses.calls[0].request.body)
        assert req['device_keys'] == {self.alice: [], bob: [], self.user_id: []}
        expected_device_keys = {
            self.alice: {
                'JLAFKJWSCS': {
                    'curve25519': '3C5BFWi2Y8MaVvjM8M22DBmh24PmgR0nPvJOIArzgyI',
                    'ed25519': 'VzJIYXQ85u19z2ZpEeLLVu8hUKTCE0VXYUn4IY4iFcA'
                }
            }
        }
        assert self.device.device_keys == expected_device_keys

        # Different curve25519, key should get updated
        assert download_device_keys(user_devices)
        expected_device_keys[self.alice]['JLAFKJWSCS']['curve25519'] = new_id_key
        assert self.device.device_keys == expected_device_keys

        # Different ed25519, key should not get updated
        assert not download_device_keys(user_devices)
        assert self.device.device_keys == expected_device_keys

        self.device.device_keys.clear()
        # All the remaining responses are wrong and we should not add the key
        for _ in range(4):
            assert not download_device_keys(user_devices)
            assert self.device.device_keys == {}

        assert len(responses.calls) == 7

    @responses.activate
    def test_update_thread(self):
        # Normal run
        event = Event()
        outdated_users = OutdatedUsersSet({self.user_id})
        outdated_users.events.add(event)

        def dummy_download(user_devices, since_token=None):
            assert user_devices == {self.user_id: []}
            return
        thread = UpdateDeviceList(Condition(), outdated_users, dummy_download, set())

        thread.start()
        event.wait()
        assert not thread.outdated_user_ids
        assert thread.event.is_set()
        assert thread.tracked_user_ids == {self.user_id}
        thread.join()
        assert not thread.is_alive()

        # Error run
        outdated_users = OutdatedUsersSet({self.user_id})

        def error_on_first_download(user_devices, since_token=None):
            error_on_first_download.c += 1
            if error_on_first_download.c == 1:
                raise MatrixRequestError
            return
        error_on_first_download.c = 0
        thread = UpdateDeviceList(
            Condition(), outdated_users, error_on_first_download, set())
        thread.start()
        thread.event.wait()
        assert error_on_first_download.c == 2
        assert not thread.outdated_user_ids
        thread.join()

        # Cover a missing branch
        thread = UpdateDeviceList(
            Condition(), outdated_users, error_on_first_download, set())
        thread._should_terminate.set()
        thread.start()
        thread.join()
        assert not thread.is_alive()

    @responses.activate
    def test_get_room_device_keys(self):
        self.device_list.tracked_user_ids.clear()
        room = self.cli._mkroom(self.room_id)
        room._members[self.alice] = User(self.cli.api, self.alice)

        responses.add(responses.POST, self.query_url, json=example_key_query_response)

        # Blocking
        self.device_list.get_room_device_keys(room)
        assert self.device_list.tracked_user_ids == {self.alice}
        assert self.device_list.device_keys[self.alice]['JLAFKJWSCS']

        # Same, but we already track the user
        self.device_list.get_room_device_keys(room)

        # Non-blocking
        self.device_list.tracked_user_ids.clear()
        # We have to block for testing purposes, though
        self.device_list.update_thread.event.clear()
        self.device_list.get_room_device_keys(room, blocking=False)
        self.device_list.update_thread.event.wait()

        # Same, but we already track the user
        self.device_list.get_room_device_keys(room, blocking=False)

    @responses.activate
    def test_track_users(self):
        self.device_list.tracked_user_ids.clear()
        responses.add(responses.POST, self.query_url, json=example_key_query_response)

        self.device_list.update_thread.event.clear()
        self.device_list.track_users({self.alice})
        self.device_list.update_thread.event.wait()
        assert self.device_list.tracked_user_ids == {self.alice}
        assert len(responses.calls) == 1

        # Same, but we are already tracking Alice
        self.device_list.track_users({self.alice})
        assert len(responses.calls) == 1

    def test_stop_tracking_users(self):
        self.device_list.tracked_user_ids.clear()
        self.device_list.tracked_user_ids.add(self.alice)
        self.device_list.outdated_user_ids.clear()
        self.device_list.outdated_user_ids.add(self.alice)

        self.device_list.stop_tracking_users({self.alice})

        assert not self.device_list.tracked_user_ids
        assert not self.device_list.outdated_user_ids

    def test_pending_users(self):
        # Say Alice is already tracked to avoid triggering dowload process
        self.device_list.tracked_user_ids.add(self.alice)

        self.device_list.track_user_no_download(self.alice)
        assert self.alice in self.device_list.pending_outdated_user_ids

        self.device_list.track_pending_users()
        assert self.alice not in self.device_list.pending_outdated_user_ids

    @responses.activate
    def test_update_user_device_keys(self):
        self.device_list.tracked_user_ids.clear()
        responses.add(responses.POST, self.query_url, json=example_key_query_response)

        self.device_list.update_user_device_keys({self.alice})
        assert len(responses.calls) == 0

        self.device_list.tracked_user_ids.add(self.alice)

        self.device_list.update_thread.event.clear()
        self.device_list.update_user_device_keys({self.alice}, since_token='dummy')
        self.device_list.update_thread.event.wait()
        assert len(responses.calls) == 1


def test_outdated_users_set():
    s = OutdatedUsersSet()
    assert not s

    s = OutdatedUsersSet({1})
    event = Event()
    s.events.add(event)
    assert s == {1}

    # Make a manual copy of s
    t = OutdatedUsersSet()
    t.add(1)
    t.events.add(event)
    assert t == s and t.events == s.events

    u = s.copy()
    event2 = Event()
    u.add(2)
    u.events.add(event2)
    # Check that modifying u didn't change s
    assert t == s and t.events == s.events

    s.update(u)
    assert s == {1, 2} and s.events == {event, event2}

    s.mark_as_processed()
    assert event.is_set()

    new = 's72594_4483_1935'
    s.sync_token = new
    old = 's72594_4483_1934'
    s.sync_token = old
    assert s.sync_token == new

    s.clear()
    assert not s and not s.events
