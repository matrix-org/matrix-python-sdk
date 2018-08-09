import pytest
olm = pytest.importorskip("olm")  # noqa

from copy import deepcopy

import responses

from matrix_client.api import MATRIX_V2_API_PATH
from matrix_client.client import MatrixClient
from matrix_client.crypto.key_sharing import KeySharingManager
from matrix_client.device import Device
from test.crypto.dummy_olm_device import OlmDevice, DummyStore
from test.response_examples import (example_forwarded_room_key_event,
                                    example_room_key_request_event,
                                    example_room_key_cancel_event)

HOSTNAME = 'http://example.com'


class TestKeySharing:
    cli = MatrixClient(HOSTNAME)
    user_id = '@user:matrix.org'
    room_id = '!test:example.com'
    device_id = 'QBUAZIFURK'
    other_device_id = 'JLAFKJWSCS'
    other_curve_key = 'mmFRSHuJVq3aTudx3KB3w5ZvSFQhgEcy8d+m+vkEfUQ'
    other_device = Device(None, user_id, other_device_id, curve25519_key=other_curve_key)
    request_url = HOSTNAME + MATRIX_V2_API_PATH + '/sendToDevice/m.room_key_request/1'
    forward_url = HOSTNAME + MATRIX_V2_API_PATH + '/sendToDevice/m.room.encrypted/1'

    @pytest.fixture()
    def olm_device(self):
        device = OlmDevice(self.cli.api, self.user_id, self.device_id)
        device.api._make_txn_id = lambda: 1
        return device

    @pytest.fixture()
    def manager(self, olm_device):
        return KeySharingManager(self.cli.api, DummyStore(), self.user_id, self.device_id,
                                 olm_device)

    @pytest.fixture()
    def olm_session_with_other_device(self, olm_device):
        session = olm.OutboundSession(olm_device.olm_account, self.other_curve_key,
                                      self.other_curve_key)
        olm_device.device_keys[self.user_id][self.other_device_id] = self.other_device
        olm_device.olm_sessions[self.other_curve_key] = [session]

    @responses.activate
    def test_handle_forwarded_room_key(self, olm_device, manager):
        responses.add(responses.PUT, self.request_url, json={})
        content = example_forwarded_room_key_event['content']
        sender_key = 'test'
        room_id = content['room_id']
        session_sender_key = content['sender_key']
        session_id = content['session_id']

        # Not requested
        manager.handle_forwarded_room_key_event(example_forwarded_room_key_event,
                                                self.user_id, sender_key)
        assert not olm_device.megolm_inbound_sessions

        manager.outgoing_key_requests.add(session_id)
        manager.handle_forwarded_room_key_event(example_forwarded_room_key_event,
                                                self.user_id, sender_key)
        sessions = olm_device.megolm_inbound_sessions[room_id][session_sender_key]
        assert sessions[session_id].id == session_id
        assert not manager.outgoing_key_requests

        manager.outgoing_key_requests.add(session_id)
        # With callback

        def callback(arg_session_id):
            assert arg_session_id == session_id

        manager.key_forward_callback = callback
        manager.handle_forwarded_room_key_event(example_forwarded_room_key_event,
                                                self.user_id, sender_key)
        assert sessions[session_id].id == session_id
        assert not manager.outgoing_key_requests

        manager.outgoing_key_requests.add(session_id)
        olm_device.megolm_inbound_sessions.clear()
        # Wrong payload
        event = deepcopy(example_forwarded_room_key_event)
        event['content']['session_key'] = 'wrong'
        manager.handle_forwarded_room_key_event(event, self.user_id, sender_key)
        sessions = olm_device.megolm_inbound_sessions[room_id][session_sender_key]
        assert not sessions
        assert manager.outgoing_key_requests

        # Wrong algorithm
        event = deepcopy(example_forwarded_room_key_event)
        event['content']['algorithm'] = 'wrong'
        manager.handle_forwarded_room_key_event(event, self.user_id, sender_key)
        assert not sessions
        assert manager.outgoing_key_requests

        # Wrong sender
        manager.handle_forwarded_room_key_event(example_forwarded_room_key_event,
                                                'wrong', sender_key)
        assert not sessions
        assert manager.outgoing_key_requests

    def test_handle_key_request(self, manager, olm_device):
        event = deepcopy(example_room_key_request_event)
        content = event['content']
        device_id = content['requesting_device_id']
        request_id = content['request_id']

        # Request from another user
        event['sender'] = 'wrong'
        manager.handle_key_request(event)
        assert not manager.queued_key_requests

        # Useless request from us
        event['sender'] = self.user_id
        content['requesting_device_id'] = self.device_id
        manager.handle_key_request(event)
        assert not manager.queued_key_requests

        # Request from unknown device
        content['requesting_device_id'] = 'unknown'
        manager.handle_key_request(event)
        assert not manager.queued_key_requests

        # Valid request
        olm_device.device_keys[self.user_id][device_id] = None
        content['requesting_device_id'] = device_id
        valid_event = deepcopy(event)
        manager.handle_key_request(valid_event)
        assert request_id in manager.queued_key_requests[device_id]

        # Duplicate request
        manager.handle_key_request(event)

        # Cancel request
        cancel_event = deepcopy(example_room_key_cancel_event)
        cancel_event['sender'] = self.user_id
        manager.handle_key_request(cancel_event)
        assert not manager.queued_key_requests[device_id][request_id]

        # Request after cancelation
        manager.handle_key_request(event)
        assert not manager.queued_key_requests[device_id][request_id]

        # Unknown algorithm
        content['body']['algorithm'] = 'unknown'
        manager.handle_key_request(event)
        assert not manager.queued_key_requests[device_id][request_id]

        # Unknown action
        content['action'] = 'unknown'
        manager.handle_key_request(event)
        assert not manager.queued_key_requests[device_id][request_id]

    def test_trigger_key_requests_callback(self, manager, olm_device):
        # No callback
        manager.trigger_key_requests_callback()

        def callback(devices, method):
            assert devices[device_id] == device
            assert method == manager.process_key_requests

        manager.key_request_callback = callback

        # No requests
        manager.trigger_key_requests_callback()

        # Request
        device_id = 'test'
        device = Device(None, self.user_id, self.device_id)
        olm_device.device_keys[self.user_id][device_id] = device

        manager.queued_key_requests[device_id] = None
        manager.trigger_key_requests_callback()

    @responses.activate
    @pytest.mark.usefixtures('olm_session_with_other_device')
    def test_process_key_requests(self, manager, olm_device):
        device_ids = [self.other_device_id]

        # No requests
        manager.process_key_requests(device_ids)

        # No session
        event = deepcopy(example_room_key_request_event)
        content = event['content']
        body = content['body']
        request_id = content['request_id']
        manager.queued_key_requests[self.other_device_id][request_id] = body
        manager.process_key_requests(device_ids)

        responses.add(responses.PUT, self.forward_url, json={})
        room_id = body['room_id']
        sender_key = body['sender_key']
        session_id = body['session_id']
        olm_device.megolm_add_inbound_session(
            room_id, sender_key, 'ed25519', session_id,
            example_forwarded_room_key_event['content']['session_key'],
            export_format=True
        )
        manager.queued_key_requests[self.other_device_id][request_id] = body
        manager.process_key_requests(device_ids)

        manager.queued_key_requests[self.other_device_id][request_id] = body
        # Retrieved from db
        session = olm_device.megolm_inbound_sessions[room_id][sender_key][session_id]
        olm_device.megolm_inbound_sessions.clear()

        class DB(DummyStore):

            def __getattribute__(self, name):
                if name == 'get_inbound_session':
                    return lambda *x: session
                return super(DB, self).__getattribute__(name)

        olm_device.db = DB()
        manager.process_key_requests(device_ids)

    @responses.activate
    def test_request_missing_key(self, manager):
        responses.add(responses.PUT, self.request_url, json={})
        encrypted_event = {
            'room_id': 'test',
            'content': {
                'session_id': 'test',
                'algorithm': 'test',
                'sender_key': 'test'
            }
        }
        # No callback
        manager.request_missing_key(encrypted_event)
        assert not responses.calls

        manager.key_forward_callback = lambda: None
        # Good
        manager.request_missing_key(encrypted_event)
        assert len(responses.calls) == 1

        # Already requested
        manager.request_missing_key(encrypted_event)
        assert len(responses.calls) == 1
