import pytest
olm = pytest.importorskip("olm")  # noqa

import json
import logging
from copy import deepcopy
from datetime import timedelta, datetime
try:
    from urllib import quote
except ImportError:
    from urllib.parse import quote

import responses

from matrix_client.crypto import olm_device
from matrix_client.crypto.verified_event import VerifiedEvent
from matrix_client.api import MATRIX_V2_API_PATH
from matrix_client.client import MatrixClient
from matrix_client.user import User
from matrix_client.device import Device
from matrix_client.errors import E2EUnknownDevices, UnableToDecryptError
from test.crypto.dummy_olm_device import OlmDevice, DummyStore
from matrix_client.crypto.sessions import MegolmOutboundSession, MegolmInboundSession
from test.response_examples import (example_key_upload_response,
                                    example_claim_keys_response,
                                    example_room_key_event)

HOSTNAME = 'http://example.com'


class TestOlmDevice:
    cli = MatrixClient(HOSTNAME)
    user_id = '@user:matrix.org'
    room_id = '!test:example.com'
    device_id = 'QBUAZIFURK'
    alice = '@alice:example.com'
    alice_device_id = 'JLAFKJWSCS'
    alice_curve_key = 'mmFRSHuJVq3aTudx3KB3w5ZvSFQhgEcy8d+m+vkEfUQ'
    alice_ed_key = '4VjV3OhFUxWFAcO5YOaQVmTIn29JdRmtNh9iAxoyhkc'
    alice_device = Device(cli.api, alice, alice_device_id, database=DummyStore(),
                          curve25519_key=alice_curve_key, ed25519_key=alice_ed_key)
    room = cli._mkroom(room_id)
    room._members[alice] = User(cli.api, alice)

    upload_url = HOSTNAME + MATRIX_V2_API_PATH + '/keys/upload'
    claim_url = HOSTNAME + MATRIX_V2_API_PATH + '/keys/claim'
    to_device_url = HOSTNAME + MATRIX_V2_API_PATH + '/sendToDevice/m.room.encrypted/1'

    @pytest.fixture()
    def device(self):
        device = OlmDevice(self.cli.api, self.user_id, self.device_id)
        # allow to_device api call to work well with responses
        device.api._make_txn_id = lambda: 1
        return device

    @pytest.fixture()
    def signing_key(self, device):
        return device.olm_account.identity_keys['ed25519']

    @pytest.fixture()
    def olm_session_with_alice(self, device):
        session = olm.OutboundSession(device.olm_account, self.alice_curve_key,
                                      self.alice_curve_key)
        device.device_keys[self.alice][self.alice_device_id] = self.alice_device
        device.olm_sessions[self.alice_curve_key] = [session]

    @pytest.fixture()
    def alice_olm_device(self, device):
        """Establish an Olm session from Alice to us, and return Alice's Olm device."""
        alice_device = OlmDevice(device.api, self.alice, self.alice_device_id)
        alice_device.device_keys[self.user_id][self.device_id] = device
        device.device_keys[self.alice][self.alice_device_id] = alice_device

        device.olm_account.generate_one_time_keys(1)
        otk = next(iter(device.olm_account.one_time_keys['curve25519'].values()))
        device.olm_account.mark_keys_as_published()
        sender_key = device.curve25519
        session = olm.OutboundSession(alice_device.olm_account, sender_key, otk)
        alice_device.olm_sessions[sender_key] = [session]
        return alice_device

    def test_sign_json(self, device):
        example_payload = {
            "name": "example.org",
            "unsigned": {
                "age_ts": 922834800000
            }
        }
        saved_payload = deepcopy(example_payload)

        signed_payload = device.sign_json(example_payload)
        signature = signed_payload.pop('signatures')
        # We should not have modified the payload besides the signatures key
        assert example_payload == saved_payload
        key_id = 'ed25519:' + device.device_id
        assert signature[self.user_id][key_id]

    def test_verify_json(self, device):
        example_payload = {
            "test": "test",
            "unsigned": {
                "age_ts": 922834800000
            },
            "signatures": {
                "@user:matrix.org": {
                    "ed25519:QBUAZIFURK": ("WI7TgwqTp4YVn1dFWmDu7xrJvEikEzAbmoqyM5JY5t0P"
                                           "6fVaiMFAirmwb13GzIyYDLR+nQfoksNBcrp7xSaMCA")
                }
            }
        }
        saved_payload = deepcopy(example_payload)
        signing_key = "WQF5z9b4DV1DANI5HUMJfhTIDvJs1jkoGTLY6AQdjF0"

        assert device.verify_json(example_payload, signing_key, self.user_id,
                                  device.device_id)

        # We should not have modified the payload
        assert example_payload == saved_payload

        # Try to verify an object that has been tampered with
        example_payload['test'] = 'test1'
        assert not device.verify_json(example_payload, signing_key, self.user_id,
                                      device.device_id)

        # Try to verify invalid payloads
        example_payload['signatures'].pop(self.user_id)
        assert not device.verify_json(example_payload, signing_key, self.user_id,
                                      device.device_id)
        example_payload.pop('signatures')
        assert not device.verify_json(example_payload, signing_key, self.user_id,
                                      device.device_id)

    def test_sign_verify(self, device, signing_key):
        example_payload = {
            "name": "example.org",
        }

        signed_payload = device.sign_json(example_payload)
        assert device.verify_json(signed_payload, signing_key, self.user_id,
                                  device.device_id)

    @responses.activate
    def test_upload_identity_keys(self, device, signing_key):
        device.one_time_keys_manager.server_counts = {}
        resp = deepcopy(example_key_upload_response)

        responses.add(responses.POST, self.upload_url, json=resp)

        assert device.upload_identity_keys() is None
        assert device.one_time_keys_manager.server_counts == \
            resp['one_time_key_counts']

        req_device_keys = json.loads(responses.calls[0].request.body)['device_keys']
        assert req_device_keys['user_id'] == self.user_id
        assert req_device_keys['device_id'] == self.device_id
        assert req_device_keys['algorithms'] == device._algorithms
        assert 'keys' in req_device_keys
        assert 'signatures' in req_device_keys
        assert device.verify_json(req_device_keys, signing_key, self.user_id,
                                  self.device_id)

    @pytest.mark.parametrize('proportion', [-1, 2])
    def test_upload_identity_keys_invalid(self, proportion):
        with pytest.raises(ValueError):
            OlmDevice(self.cli.api,
                      self.user_id,
                      self.device_id,
                      signed_keys_proportion=proportion)

    @responses.activate
    @pytest.mark.parametrize('proportion', [0, 1, 0.5, 0.33])
    def test_upload_one_time_keys(self, proportion):
        resp = deepcopy(example_key_upload_response)
        counts = resp['one_time_key_counts']
        counts['curve25519'] = counts['signed_curve25519'] = 10
        responses.add(responses.POST, self.upload_url, json=resp)

        device = OlmDevice(
            self.cli.api, self.user_id, self.device_id, signed_keys_proportion=proportion)
        assert not device.one_time_keys_manager.server_counts

        max_keys = device.olm_account.max_one_time_keys // 2
        signed_keys_to_upload = \
            max(round(max_keys * proportion) - counts['signed_curve25519'], 0)
        unsigned_keys_to_upload = \
            max(round(max_keys * (1 - proportion)) - counts['curve25519'], 0)
        expected_return = {}
        if signed_keys_to_upload:
            expected_return['signed_curve25519'] = signed_keys_to_upload
        if unsigned_keys_to_upload:
            expected_return['curve25519'] = unsigned_keys_to_upload

        assert device.upload_one_time_keys() == expected_return
        assert len(responses.calls) == 2
        assert device.one_time_keys_manager.server_counts == resp['one_time_key_counts']

        req_otk = json.loads(responses.calls[1].request.body)['one_time_keys']
        assert len(req_otk) == unsigned_keys_to_upload + signed_keys_to_upload
        assert len([key for key in req_otk if not key.startswith('signed')]) == \
            unsigned_keys_to_upload
        assert len([key for key in req_otk if key.startswith('signed')]) == \
            signed_keys_to_upload
        for k in req_otk:
            if k == 'signed_curve25519':
                device.verify_json(req_otk[k], device.signing_key, device.user_id,
                                   device.device_id)

    @responses.activate
    def test_upload_one_time_keys_enough(self, device):
        device.one_time_keys_manager.server_counts = {}
        limit = device.olm_account.max_one_time_keys // 2
        resp = {'one_time_key_counts': {'signed_curve25519': limit}}
        responses.add(responses.POST, self.upload_url, json=resp)

        assert not device.upload_one_time_keys()

    @responses.activate
    def test_upload_one_time_keys_force_update(self, device):
        device.one_time_keys_manager.server_counts = {'curve25519': 10}
        resp = deepcopy(example_key_upload_response)
        responses.add(responses.POST, self.upload_url, json=resp)

        device.upload_one_time_keys()
        assert len(responses.calls) == 1

        device.upload_one_time_keys(force_update=True)
        assert len(responses.calls) == 3

    @responses.activate
    @pytest.mark.parametrize('count,should_upload', [(0, True), (25, False), (4, True)])
    def test_update_one_time_key_counts(self, device, count, should_upload):
        responses.add(responses.POST, self.upload_url, json={'one_time_key_counts': {}})
        device.one_time_keys_manager.target_counts['signed_curve25519'] = 50

        count_dict = {}
        if count:
            count_dict['signed_curve25519'] = count

        device.update_one_time_key_counts(count_dict)

        if should_upload:
            if count:
                req_otk = json.loads(responses.calls[0].request.body)['one_time_keys']
                assert len(responses.calls) == 1
            else:
                req_otk = json.loads(responses.calls[1].request.body)['one_time_keys']
                assert len(responses.calls) == 2
            assert len(req_otk) == 50 - count
        else:
            assert not len(responses.calls)

    @pytest.mark.parametrize('threshold', [-1, 2])
    def test_invalid_keys_threshold(self, threshold):
        with pytest.raises(ValueError):
            OlmDevice(self.cli.api,
                      self.user_id,
                      self.device_id,
                      keys_threshold=threshold)

    @responses.activate
    def test_olm_start_sessions(self, device):
        responses.add(responses.POST, self.claim_url, json=example_claim_keys_response)

        user_devices = {self.alice: {self.alice_device_id}}

        # We don't have alice's keys
        device.olm_start_sessions(user_devices)
        assert not device.olm_sessions[self.alice_curve_key]

        # Cover logging part
        olm_device.logger.setLevel(logging.WARNING)
        # Now should be good
        device.device_keys[self.alice][self.alice_device_id] = self.alice_device
        device.olm_start_sessions(user_devices)
        assert device.olm_sessions[self.alice_curve_key]

        # With failures and wrong signature
        device.olm_sessions.clear()
        payload = deepcopy(example_claim_keys_response)
        payload['failures'] = {'dummy': 1}
        key = payload['one_time_keys'][self.alice][self.alice_device_id]
        key['signed_curve25519:AAAAAQ']['test'] = 1
        responses.replace(responses.POST, self.claim_url, json=payload)

        device.olm_start_sessions(user_devices)
        assert not device.olm_sessions[self.alice_curve_key]

        # Missing requested user and devices
        user_devices[self.alice].add('test')
        user_devices['test'] = 'test'

        device.olm_start_sessions(user_devices)

    @responses.activate
    def test_olm_build_encrypted_event(self, device):
        event_content = {'dummy': 'example'}

        # We don't have Alice's keys
        with pytest.raises(RuntimeError):
            device.olm_build_encrypted_event(
                'm.text', event_content, self.alice, self.alice_device_id)

        # We don't have a session with Alice
        device.device_keys[self.alice][self.alice_device_id] = self.alice_device
        with pytest.raises(RuntimeError):
            device.olm_build_encrypted_event(
                'm.text', event_content, self.alice, self.alice_device_id)

        responses.add(responses.POST, self.claim_url, json=example_claim_keys_response)
        user_devices = {self.alice: {self.alice_device_id}}
        device.olm_start_sessions(user_devices)
        assert device.olm_build_encrypted_event(
            'm.text', event_content, self.alice, self.alice_device_id)

    def test_olm_decrypt(self, device):
        # Since this method doesn't care about high-level event formatting, we will
        # generate things at low level
        our_account = device.olm_account
        # Alice needs to start a session with us
        alice = olm.Account()
        sender_key = alice.identity_keys['curve25519']
        our_account.generate_one_time_keys(1)
        otk = next(iter(our_account.one_time_keys['curve25519'].values()))
        device.olm_account.mark_keys_as_published()
        session = olm.OutboundSession(alice, our_account.identity_keys['curve25519'], otk)

        plaintext = {"test": "test"}
        message = session.encrypt(json.dumps(plaintext))
        assert device._olm_decrypt(message, sender_key) == plaintext

        # New pre-key message, but the session exists this time
        message = session.encrypt(json.dumps(plaintext))
        assert device._olm_decrypt(message, sender_key) == plaintext

        # Try to decrypt the same message twice
        with pytest.raises(RuntimeError):
            device._olm_decrypt(message, sender_key)

        # Answer Alice in order to have a type 1 message
        message = device.olm_sessions[sender_key][0].encrypt(json.dumps(plaintext))
        session.decrypt(message)
        message = session.encrypt(json.dumps(plaintext))
        assert device._olm_decrypt(message, sender_key) == plaintext

        # Try to decrypt the same message type 1 twice
        with pytest.raises(RuntimeError):
            device._olm_decrypt(message, sender_key)

        # Try to decrypt a message from a session that reused a one-time key
        otk_reused_session = olm.OutboundSession(
            alice, our_account.identity_keys['curve25519'], otk)
        message = otk_reused_session.encrypt(json.dumps(plaintext))
        with pytest.raises(RuntimeError):
            device._olm_decrypt(message, sender_key)

        # Try to decrypt an invalid type 0 message
        our_account.generate_one_time_keys(1)
        otk = next(iter(our_account.one_time_keys['curve25519'].values()))
        wrong_session = olm.OutboundSession(alice, sender_key, otk)
        message = wrong_session.encrypt(json.dumps(plaintext))
        with pytest.raises(RuntimeError):
            device._olm_decrypt(message, sender_key)

        # Try to decrypt a type 1 message for which we have no sessions
        message = session.encrypt(json.dumps(plaintext))
        device.olm_sessions.clear()
        with pytest.raises(RuntimeError):
            device._olm_decrypt(message, sender_key)

    def test_olm_decrypt_event(self, device, alice_olm_device):
        encrypted_event = alice_olm_device.olm_build_encrypted_event(
            'example_type', {'content': 'test'}, self.user_id, self.device_id)

        # Now we can test
        device.olm_decrypt_event(encrypted_event, self.alice)

        # Device verification
        alice_olm_device.verified = True
        encrypted_event = alice_olm_device.olm_build_encrypted_event(
            'example_type', {'content': 'test'}, self.user_id, self.device_id)
        device.olm_decrypt_event(encrypted_event, self.alice)

        # The signing_key is wrong
        encrypted_event = alice_olm_device.olm_build_encrypted_event(
            'example_type', {'content': 'test'}, self.user_id, self.device_id)
        device.device_keys[self.alice][self.alice_device_id]._ed25519 = 'wrong'
        with pytest.raises(RuntimeError):
            device.olm_decrypt_event(encrypted_event, self.alice)

        # We do not have the keys
        encrypted_event = alice_olm_device.olm_build_encrypted_event(
            'example_type', {'content': 'test'}, self.user_id, self.device_id)
        device.device_keys[self.alice].clear()
        device.olm_decrypt_event(encrypted_event, self.alice)
        device.device_keys[self.alice][self.alice_device_id] = alice_olm_device
        alice_olm_device.verified = False

        # Type 1 Olm payload
        alice_olm_device.olm_decrypt_event(
            device.olm_build_encrypted_event(
                'example_type', {'content': 'test'}, self.alice, self.alice_device_id
            ),
            self.user_id)
        encrypted_event = alice_olm_device.olm_build_encrypted_event(
            'example_type', {'content': 'test'}, self.user_id, self.device_id)
        device.olm_decrypt_event(encrypted_event, self.alice)

        encrypted_event = alice_olm_device.olm_build_encrypted_event(
            'example_type', {'content': 'test'}, self.user_id, self.device_id)
        with pytest.raises(RuntimeError):
            device.olm_decrypt_event(encrypted_event, 'wrong')

        wrong_event = deepcopy(encrypted_event)
        wrong_event['algorithm'] = 'wrong'
        with pytest.raises(RuntimeError):
            device.olm_decrypt_event(wrong_event, self.alice)

        wrong_event = deepcopy(encrypted_event)
        wrong_event['ciphertext'] = {}
        with pytest.raises(RuntimeError):
            device.olm_decrypt_event(wrong_event, self.alice)

        encrypted_event = alice_olm_device.olm_build_encrypted_event(
            'example_type', {'content': 'test'}, self.user_id, self.device_id)
        device.user_id = 'wrong'
        with pytest.raises(RuntimeError):
            device.olm_decrypt_event(encrypted_event, self.alice)
        device.user_id = self.user_id

        encrypted_event = alice_olm_device.olm_build_encrypted_event(
            'example_type', {'content': 'test'}, self.user_id, self.device_id)
        device._ed25519 = 'wrong'
        with pytest.raises(RuntimeError):
            device.olm_decrypt_event(encrypted_event, self.alice)

    @responses.activate
    def test_olm_ensure_sessions(self, device):
        responses.add(responses.POST, self.claim_url, json=example_claim_keys_response)
        device.device_keys[self.alice][self.alice_device_id] = self.alice_device
        user_devices = {self.alice: [self.alice_device_id]}

        device.olm_ensure_sessions(user_devices)
        assert device.olm_sessions[self.alice_curve_key]
        assert len(responses.calls) == 1

        device.olm_ensure_sessions(user_devices)
        assert len(responses.calls) == 1

    @responses.activate
    def test_megolm_share_session(self, device):
        responses.add(responses.POST, self.claim_url, json=example_claim_keys_response)
        responses.add(responses.PUT, self.to_device_url, json={})
        device.device_keys[self.alice][self.alice_device_id] = self.alice_device
        device.device_keys['dummy']['dummy'] = \
            Device(self.cli.api, 'dummy', 'dummy', curve25519_key='a', ed25519_key='a')
        user_devices = {self.alice: [self.alice_device_id], 'dummy': ['dummy']}
        session = MegolmOutboundSession()

        # Sharing with Alice should succeed, but dummy will fail
        device.megolm_share_session(self.room_id, user_devices, session)
        assert session.devices == {self.alice_device_id, 'dummy'}

        req = json.loads(responses.calls[1].request.body)['messages']
        assert self.alice in req
        assert 'dummy' not in req

    @responses.activate
    @pytest.mark.usefixtures('olm_session_with_alice')
    def test_megolm_start_session(self, device):
        responses.add(responses.PUT, self.to_device_url, json={})
        device.device_list.tracked_user_ids.add(self.alice)
        user_devices = {self.alice: [self.alice_device_id]}

        device.megolm_start_session(self.room, user_devices)
        session = device.megolm_outbound_sessions[self.room_id]
        assert self.alice_device_id in session.devices

        # Check that we can decrypt our own messages
        plaintext = {
            'type': 'test',
            'content': {'test': 'test'},
        }
        encrypted_event = device.megolm_build_encrypted_event(self.room, plaintext)
        event = {
            'sender': self.alice,
            'room_id': self.room_id,
            'content': encrypted_event,
            'type': 'm.room.encrypted',
            'origin_server_ts': 1,
            'event_id': 1
        }
        device.megolm_decrypt_event(event)
        assert event['content'] == plaintext['content']

    @responses.activate
    @pytest.mark.usefixtures('olm_session_with_alice')
    def test_megolm_share_session_with_new_devices(self, device):
        responses.add(responses.PUT, self.to_device_url, json={})
        session = MegolmOutboundSession()
        device.megolm_outbound_sessions[self.room_id] = session
        user_devices = {self.alice: [self.alice_device_id]}

        device.megolm_share_session_with_new_devices(self.room, user_devices, session)
        assert self.alice_device_id in session.devices
        assert len(responses.calls) == 1

        device.megolm_share_session_with_new_devices(self.room, user_devices, session)
        assert len(responses.calls) == 1

    def test_megolm_get_recipients(self, device):
        device.device_keys[self.alice][self.alice_device_id] = self.alice_device

        user_devices, _ = device.megolm_get_recipients(self.room)
        assert user_devices == {self.alice: [self.alice_device_id]}

        session = MegolmOutboundSession()
        device.megolm_outbound_sessions[self.room_id] = session

        user_devices, removed = device.megolm_get_recipients(self.room, session)
        assert user_devices == {self.alice: [self.alice_device_id]} and not removed

        self.alice_device.blacklisted = True
        _, removed = device.megolm_get_recipients(self.room, session)
        assert not removed
        session.add_device(self.alice_device_id)
        _, removed = device.megolm_get_recipients(self.room, session)
        assert removed and self.room_id not in device.megolm_outbound_sessions
        self.alice_device.blacklisted = False

        self.room.verify_devices = True
        with pytest.raises(E2EUnknownDevices) as e:
            device.megolm_get_recipients(self.room)
        assert e.value.user_devices == {self.alice: [self.alice_device]}
        self.room.verify_devices = False

    @responses.activate
    @pytest.mark.usefixtures('olm_session_with_alice')
    def test_megolm_build_encrypted_event(self, device):
        responses.add(responses.PUT, self.to_device_url, json={})
        device.device_list.tracked_user_ids.add(self.alice)
        event = {'type': 'm.room.message', 'content': {'body': 'test'}}

        self.room.rotation_period_msgs = 1
        device.megolm_build_encrypted_event(self.room, event)

        device.megolm_build_encrypted_event(self.room, event)

        session = device.megolm_outbound_sessions[self.room_id]
        session.encrypt('test')
        device.megolm_build_encrypted_event(self.room, event)
        assert device.megolm_outbound_sessions[self.room_id].id != session.id

    def test_megolm_remove_outbound_session(self, device):
        session = MegolmOutboundSession()
        device.megolm_outbound_sessions[self.room_id] = session
        device.megolm_remove_outbound_session(self.room_id)
        device.megolm_remove_outbound_session(self.room_id)

    @responses.activate
    @pytest.mark.usefixtures('olm_session_with_alice')
    def test_send_encrypted_message(self, device):
        message_url = HOSTNAME + MATRIX_V2_API_PATH + \
            '/rooms/{}/send/m.room.encrypted/1'.format(quote(self.room.room_id))
        responses.add(responses.PUT, message_url, json={})
        session = MegolmOutboundSession()
        session.add_device(self.alice_device_id)
        device.megolm_outbound_sessions[self.room_id] = session

        device.send_encrypted_message(self.room, {'test': 'test'})

    def test_megolm_add_inbound_session(self, device):
        session = MegolmOutboundSession()

        with pytest.raises(ValueError):
            device.megolm_add_inbound_session(
                self.room_id, self.alice_curve_key, self.alice_ed_key, session.id,
                'wrong'
            )
        assert device.megolm_add_inbound_session(
            self.room_id, self.alice_curve_key, self.alice_ed_key, session.id,
            session.session_key
        )
        assert session.id in \
            device.megolm_inbound_sessions[self.room_id][self.alice_curve_key]
        assert not device.megolm_add_inbound_session(
            self.room_id, self.alice_curve_key, self.alice_ed_key, session.id,
            session.session_key
        )
        with pytest.raises(ValueError):
            device.megolm_add_inbound_session(
                self.room_id, self.alice_curve_key, self.alice_ed_key, 'wrong',
                session.session_key
            )

    def test_handle_room_key_event(self, device):
        device.handle_room_key_event(example_room_key_event, self.alice_curve_key)
        assert self.room_id in device.megolm_inbound_sessions

        device.handle_room_key_event(example_room_key_event, self.alice_curve_key)

        event = deepcopy(example_room_key_event)
        event['content']['algorithm'] = 'wrong'
        device.handle_room_key_event(event, self.alice_curve_key)

        event = deepcopy(example_room_key_event)
        event['content']['session_id'] = 'wrong'
        device.handle_room_key_event(event, self.alice_curve_key)

    def test_olm_handle_encrypted_event(self, device, alice_olm_device):
        content = example_room_key_event['content']
        encrypted_event = alice_olm_device.olm_build_encrypted_event(
            'm.room_key', content, self.user_id, self.device_id)
        event = {
            'type': 'm.room.encrypted',
            'content': encrypted_event,
            'sender': self.alice
        }

        device.olm_handle_encrypted_event(event)

        # Decrypting the same event twice will trigger an error
        device.olm_handle_encrypted_event(event)

        # Forwarded key event
        encrypted_event = alice_olm_device.olm_build_encrypted_event(
            'm.forwarded_room_key', content, self.user_id, self.device_id)
        event = {
            'type': 'm.room.encrypted',
            'content': encrypted_event,
            'sender': self.alice
        }
        device.olm_handle_encrypted_event(event)

        # Unhandled event
        encrypted_event = alice_olm_device.olm_build_encrypted_event(
            'm.other', content, self.user_id, self.device_id)
        event = {
            'type': 'm.room.encrypted',
            'content': encrypted_event,
            'sender': self.alice
        }
        device.olm_handle_encrypted_event(event)

        # Simulate redacted event
        event['content'].pop('algorithm')
        device.olm_handle_encrypted_event(event)

    def test_megolm_decrypt_event(self, device):
        out_session = MegolmOutboundSession()

        plaintext = {
            'content': {"test": "test"},
            'type': 'm.text',
        }
        ciphertext = out_session.encrypt(json.dumps(plaintext))

        content = {
            'ciphertext': ciphertext,
            'session_id': out_session.id,
            'sender_key': self.alice_curve_key,
            'algorithm': 'm.megolm.v1.aes-sha2',
            'device_id': self.alice_device_id,
        }

        event = {
            'sender': self.alice,
            'room_id': self.room_id,
            'content': content,
            'type': 'm.room.encrypted',
            'origin_server_ts': 1,
            'event_id': 1
        }

        with pytest.raises(UnableToDecryptError):
            device.megolm_decrypt_event(event)

        session_key = out_session.session_key
        in_session = MegolmInboundSession(session_key, self.alice_ed_key)
        sessions = device.megolm_inbound_sessions[self.room_id]
        sessions[self.alice_curve_key][in_session.id] = in_session

        # Unknown message index
        with pytest.raises(RuntimeError):
            device.megolm_decrypt_event(event)

        ciphertext = out_session.encrypt(json.dumps(plaintext))
        event['content']['ciphertext'] = ciphertext
        device.megolm_decrypt_event(event)
        assert event['content'] == plaintext['content']

        # No replay attack
        event['content'] = content
        device.megolm_decrypt_event(event)
        assert event['content'] == plaintext['content']

        # Replay attack
        event['content'] = content
        event['event_id'] = 2
        with pytest.raises(RuntimeError):
            device.megolm_decrypt_event(event)
        event['event_id'] = 1

        # Device verification
        device.device_keys[self.alice][self.alice_device_id] = self.alice_device
        event['content'] = content
        # Unverified
        device.megolm_decrypt_event(event)
        assert event['content'] == plaintext['content']
        assert isinstance(event, dict)

        event['content'] = content
        # Verified
        self.alice_device.verified = True
        decrypted_event = device.megolm_decrypt_event(event)
        assert decrypted_event['content'] == plaintext['content']
        assert isinstance(decrypted_event, VerifiedEvent)

        in_session = MegolmInboundSession(session_key, self.alice_curve_key)
        sessions = device.megolm_inbound_sessions[self.room_id]
        sessions[self.alice_curve_key][in_session.id] = in_session
        # Wrong signing key
        with pytest.raises(RuntimeError):
            device.megolm_decrypt_event(event)
        self.alice_device.verified = False

        event['content']['algorithm'] = 'wrong'
        with pytest.raises(RuntimeError):
            device.megolm_decrypt_event(event)

        event['content'].pop('algorithm')
        event['type'] = 'encrypted'
        device.megolm_decrypt_event(event)
        assert event['type'] == 'encrypted'


def test_megolm_outbound_session():
    session = MegolmOutboundSession()
    assert session.max_messages == 100
    assert session.max_age == timedelta(days=7)

    session = MegolmOutboundSession(max_messages=1, max_age=100000)
    assert session.max_messages == 1
    assert session.max_age == timedelta(milliseconds=100000)

    assert not session.devices

    session.add_device('test')
    assert 'test' in session.devices

    session.add_devices({'test2', 'test3'})
    assert 'test2' in session.devices and 'test3' in session.devices

    assert not session.should_rotate()

    session.encrypt('message')
    assert session.should_rotate()

    session.max_messages = 2
    assert not session.should_rotate()
    session.creation_time = datetime.now() - timedelta(milliseconds=100000)
    assert session.should_rotate()
