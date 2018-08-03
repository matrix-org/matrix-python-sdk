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
from matrix_client.errors import E2EUnknownDevices
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
    device = OlmDevice(cli.api, user_id, device_id)
    signing_key = device.olm_account.identity_keys['ed25519']
    alice = '@alice:example.com'
    alice_device_id = 'JLAFKJWSCS'
    alice_curve_key = 'mmFRSHuJVq3aTudx3KB3w5ZvSFQhgEcy8d+m+vkEfUQ'
    alice_ed_key = '4VjV3OhFUxWFAcO5YOaQVmTIn29JdRmtNh9iAxoyhkc'
    alice_device = Device(cli.api, alice, alice_device_id, database=DummyStore(),
                          curve25519_key=alice_curve_key, ed25519_key=alice_ed_key)
    alice_olm_session = olm.OutboundSession(
        device.olm_account, alice_curve_key, alice_curve_key)
    room = cli._mkroom(room_id)
    room._members[alice] = User(cli.api, alice)
    # allow to_device api call to work well with responses
    device.api._make_txn_id = lambda: 1

    def test_sign_json(self):
        example_payload = {
            "name": "example.org",
            "unsigned": {
                "age_ts": 922834800000
            }
        }
        saved_payload = deepcopy(example_payload)

        signed_payload = self.device.sign_json(example_payload)
        signature = signed_payload.pop('signatures')
        # We should not have modified the payload besides the signatures key
        assert example_payload == saved_payload
        key_id = 'ed25519:' + self.device_id
        assert signature[self.user_id][key_id]

    def test_verify_json(self):
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

        assert self.device.verify_json(example_payload, signing_key, self.user_id,
                                       self.device_id)

        # We should not have modified the payload
        assert example_payload == saved_payload

        # Try to verify an object that has been tampered with
        example_payload['test'] = 'test1'
        assert not self.device.verify_json(example_payload, signing_key, self.user_id,
                                           self.device_id)

        # Try to verify invalid payloads
        example_payload['signatures'].pop(self.user_id)
        assert not self.device.verify_json(example_payload, signing_key, self.user_id,
                                           self.device_id)
        example_payload.pop('signatures')
        assert not self.device.verify_json(example_payload, signing_key, self.user_id,
                                           self.device_id)

    def test_sign_verify(self):
        example_payload = {
            "name": "example.org",
        }

        signed_payload = self.device.sign_json(example_payload)
        assert self.device.verify_json(signed_payload, self.signing_key, self.user_id,
                                       self.device_id)

    @responses.activate
    def test_upload_identity_keys(self):
        upload_url = HOSTNAME + MATRIX_V2_API_PATH + '/keys/upload'
        self.device.one_time_keys_manager.server_counts = {}
        resp = deepcopy(example_key_upload_response)

        responses.add(responses.POST, upload_url, json=resp)

        assert self.device.upload_identity_keys() is None
        assert self.device.one_time_keys_manager.server_counts == \
            resp['one_time_key_counts']

        req_device_keys = json.loads(responses.calls[0].request.body)['device_keys']
        assert req_device_keys['user_id'] == self.user_id
        assert req_device_keys['device_id'] == self.device_id
        assert req_device_keys['algorithms'] == self.device._algorithms
        assert 'keys' in req_device_keys
        assert 'signatures' in req_device_keys
        assert self.device.verify_json(req_device_keys, self.signing_key, self.user_id,
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
        upload_url = HOSTNAME + MATRIX_V2_API_PATH + '/keys/upload'
        resp = deepcopy(example_key_upload_response)
        counts = resp['one_time_key_counts']
        counts['curve25519'] = counts['signed_curve25519'] = 10
        responses.add(responses.POST, upload_url, json=resp)

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
    def test_upload_one_time_keys_enough(self):
        upload_url = HOSTNAME + MATRIX_V2_API_PATH + '/keys/upload'
        self.device.one_time_keys_manager.server_counts = {}
        limit = self.device.olm_account.max_one_time_keys // 2
        resp = {'one_time_key_counts': {'signed_curve25519': limit}}
        responses.add(responses.POST, upload_url, json=resp)

        assert not self.device.upload_one_time_keys()

    @responses.activate
    def test_upload_one_time_keys_force_update(self):
        upload_url = HOSTNAME + MATRIX_V2_API_PATH + '/keys/upload'
        self.device.one_time_keys_manager.server_counts = {'curve25519': 10}
        resp = deepcopy(example_key_upload_response)
        responses.add(responses.POST, upload_url, json=resp)

        self.device.upload_one_time_keys()
        assert len(responses.calls) == 1

        self.device.upload_one_time_keys(force_update=True)
        assert len(responses.calls) == 3

    @responses.activate
    @pytest.mark.parametrize('count,should_upload', [(0, True), (25, False), (4, True)])
    def test_update_one_time_key_counts(self, count, should_upload):
        upload_url = HOSTNAME + MATRIX_V2_API_PATH + '/keys/upload'
        responses.add(responses.POST, upload_url, json={'one_time_key_counts': {}})
        self.device.one_time_keys_manager.target_counts['signed_curve25519'] = 50
        self.device.one_time_keys_manager.server_counts.clear()

        count_dict = {}
        if count:
            count_dict['signed_curve25519'] = count

        self.device.update_one_time_key_counts(count_dict)

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
    def test_olm_start_sessions(self):
        claim_url = HOSTNAME + MATRIX_V2_API_PATH + '/keys/claim'
        responses.add(responses.POST, claim_url, json=example_claim_keys_response)
        self.device.olm_sessions.clear()
        self.device.device_keys.clear()

        user_devices = {self.alice: {self.alice_device_id}}

        # We don't have alice's keys
        self.device.olm_start_sessions(user_devices)
        assert not self.device.olm_sessions[self.alice_curve_key]

        # Cover logging part
        olm_device.logger.setLevel(logging.WARNING)
        # Now should be good
        self.device.device_keys[self.alice][self.alice_device_id] = self.alice_device
        self.device.olm_start_sessions(user_devices)
        assert self.device.olm_sessions[self.alice_curve_key]

        # With failures and wrong signature
        self.device.olm_sessions.clear()
        payload = deepcopy(example_claim_keys_response)
        payload['failures'] = {'dummy': 1}
        key = payload['one_time_keys'][self.alice][self.alice_device_id]
        key['signed_curve25519:AAAAAQ']['test'] = 1
        responses.replace(responses.POST, claim_url, json=payload)

        self.device.olm_start_sessions(user_devices)
        assert not self.device.olm_sessions[self.alice_curve_key]

        # Missing requested user and devices
        user_devices[self.alice].add('test')
        user_devices['test'] = 'test'

        self.device.olm_start_sessions(user_devices)

    @responses.activate
    def test_olm_build_encrypted_event(self):
        self.device.device_keys.clear()
        self.device.olm_sessions.clear()
        event_content = {'dummy': 'example'}

        # We don't have Alice's keys
        with pytest.raises(RuntimeError):
            self.device.olm_build_encrypted_event(
                'm.text', event_content, self.alice, self.alice_device_id)

        # We don't have a session with Alice
        self.device.device_keys[self.alice][self.alice_device_id] = self.alice_device
        with pytest.raises(RuntimeError):
            self.device.olm_build_encrypted_event(
                'm.text', event_content, self.alice, self.alice_device_id)

        claim_url = HOSTNAME + MATRIX_V2_API_PATH + '/keys/claim'
        responses.add(responses.POST, claim_url, json=example_claim_keys_response)
        user_devices = {self.alice: {self.alice_device_id}}
        self.device.olm_start_sessions(user_devices)
        assert self.device.olm_build_encrypted_event(
            'm.text', event_content, self.alice, self.alice_device_id)

    def test_olm_decrypt(self):
        self.device.olm_sessions.clear()
        # Since this method doesn't care about high-level event formatting, we will
        # generate things at low level
        our_account = self.device.olm_account
        # Alice needs to start a session with us
        alice = olm.Account()
        sender_key = alice.identity_keys['curve25519']
        our_account.generate_one_time_keys(1)
        otk = next(iter(our_account.one_time_keys['curve25519'].values()))
        self.device.olm_account.mark_keys_as_published()
        session = olm.OutboundSession(alice, our_account.identity_keys['curve25519'], otk)

        plaintext = {"test": "test"}
        message = session.encrypt(json.dumps(plaintext))
        assert self.device._olm_decrypt(message, sender_key) == plaintext

        # New pre-key message, but the session exists this time
        message = session.encrypt(json.dumps(plaintext))
        assert self.device._olm_decrypt(message, sender_key) == plaintext

        # Try to decrypt the same message twice
        with pytest.raises(RuntimeError):
            self.device._olm_decrypt(message, sender_key)

        # Answer Alice in order to have a type 1 message
        message = self.device.olm_sessions[sender_key][0].encrypt(json.dumps(plaintext))
        session.decrypt(message)
        message = session.encrypt(json.dumps(plaintext))
        assert self.device._olm_decrypt(message, sender_key) == plaintext

        # Try to decrypt the same message type 1 twice
        with pytest.raises(RuntimeError):
            self.device._olm_decrypt(message, sender_key)

        # Try to decrypt a message from a session that reused a one-time key
        otk_reused_session = olm.OutboundSession(
            alice, our_account.identity_keys['curve25519'], otk)
        message = otk_reused_session.encrypt(json.dumps(plaintext))
        with pytest.raises(RuntimeError):
            self.device._olm_decrypt(message, sender_key)

        # Try to decrypt an invalid type 0 message
        our_account.generate_one_time_keys(1)
        otk = next(iter(our_account.one_time_keys['curve25519'].values()))
        wrong_session = olm.OutboundSession(alice, sender_key, otk)
        message = wrong_session.encrypt(json.dumps(plaintext))
        with pytest.raises(RuntimeError):
            self.device._olm_decrypt(message, sender_key)

        # Try to decrypt a type 1 message for which we have no sessions
        message = session.encrypt(json.dumps(plaintext))
        self.device.olm_sessions.clear()
        with pytest.raises(RuntimeError):
            self.device._olm_decrypt(message, sender_key)

    def test_olm_decrypt_event(self):
        self.device.device_keys.clear()
        self.device.olm_sessions.clear()
        alice_device = OlmDevice(self.device.api, self.alice, self.alice_device_id)
        alice_device.device_keys[self.user_id][self.device_id] = self.device
        self.device.device_keys[self.alice][self.alice_device_id] = alice_device

        # Artificially start an Olm session from Alice
        self.device.olm_account.generate_one_time_keys(1)
        otk = next(iter(self.device.olm_account.one_time_keys['curve25519'].values()))
        self.device.olm_account.mark_keys_as_published()
        sender_key = self.device.curve25519
        session = olm.OutboundSession(alice_device.olm_account, sender_key, otk)
        alice_device.olm_sessions[sender_key] = [session]

        encrypted_event = alice_device.olm_build_encrypted_event(
            'example_type', {'content': 'test'}, self.user_id, self.device_id)

        # Now we can test
        self.device.olm_decrypt_event(encrypted_event, self.alice)

        # Device verification
        alice_device.verified = True
        encrypted_event = alice_device.olm_build_encrypted_event(
            'example_type', {'content': 'test'}, self.user_id, self.device_id)
        self.device.olm_decrypt_event(encrypted_event, self.alice)

        # The signing_key is wrong
        encrypted_event = alice_device.olm_build_encrypted_event(
            'example_type', {'content': 'test'}, self.user_id, self.device_id)
        self.device.device_keys[self.alice][self.alice_device_id]._ed25519 = 'wrong'
        with pytest.raises(RuntimeError):
            self.device.olm_decrypt_event(encrypted_event, self.alice)

        # We do not have the keys
        encrypted_event = alice_device.olm_build_encrypted_event(
            'example_type', {'content': 'test'}, self.user_id, self.device_id)
        self.device.device_keys[self.alice].clear()
        self.device.olm_decrypt_event(encrypted_event, self.alice)
        self.device.device_keys[self.alice][self.alice_device_id] = alice_device
        alice_device.verified = False

        # Type 1 Olm payload
        alice_device.olm_decrypt_event(
            self.device.olm_build_encrypted_event(
                'example_type', {'content': 'test'}, self.alice, self.alice_device_id
            ),
            self.user_id)
        encrypted_event = alice_device.olm_build_encrypted_event(
            'example_type', {'content': 'test'}, self.user_id, self.device_id)
        self.device.olm_decrypt_event(encrypted_event, self.alice)

        encrypted_event = alice_device.olm_build_encrypted_event(
            'example_type', {'content': 'test'}, self.user_id, self.device_id)
        with pytest.raises(RuntimeError):
            self.device.olm_decrypt_event(encrypted_event, 'wrong')

        wrong_event = deepcopy(encrypted_event)
        wrong_event['algorithm'] = 'wrong'
        with pytest.raises(RuntimeError):
            self.device.olm_decrypt_event(wrong_event, self.alice)

        wrong_event = deepcopy(encrypted_event)
        wrong_event['ciphertext'] = {}
        with pytest.raises(RuntimeError):
            self.device.olm_decrypt_event(wrong_event, self.alice)

        encrypted_event = alice_device.olm_build_encrypted_event(
            'example_type', {'content': 'test'}, self.user_id, self.device_id)
        self.device.user_id = 'wrong'
        with pytest.raises(RuntimeError):
            self.device.olm_decrypt_event(encrypted_event, self.alice)
        self.device.user_id = self.user_id

        encrypted_event = alice_device.olm_build_encrypted_event(
            'example_type', {'content': 'test'}, self.user_id, self.device_id)
        backup = self.device.ed25519
        self.device._ed25519 = 'wrong'
        with pytest.raises(RuntimeError):
            self.device.olm_decrypt_event(encrypted_event, self.alice)
        self.device._ed25519 = backup

    @responses.activate
    def test_olm_ensure_sessions(self):
        claim_url = HOSTNAME + MATRIX_V2_API_PATH + '/keys/claim'
        responses.add(responses.POST, claim_url, json=example_claim_keys_response)
        self.device.olm_sessions.clear()
        self.device.device_keys[self.alice][self.alice_device_id] = self.alice_device
        user_devices = {self.alice: [self.alice_device_id]}

        self.device.olm_ensure_sessions(user_devices)
        assert self.device.olm_sessions[self.alice_curve_key]
        assert len(responses.calls) == 1

        self.device.olm_ensure_sessions(user_devices)
        assert len(responses.calls) == 1

    @responses.activate
    def test_megolm_share_session(self):
        claim_url = HOSTNAME + MATRIX_V2_API_PATH + '/keys/claim'
        responses.add(responses.POST, claim_url, json=example_claim_keys_response)
        to_device_url = HOSTNAME + MATRIX_V2_API_PATH + '/sendToDevice/m.room.encrypted/1'
        responses.add(responses.PUT, to_device_url, json={})
        self.device.olm_sessions.clear()
        self.device.device_keys[self.alice][self.alice_device_id] = self.alice_device
        self.device.device_keys['dummy']['dummy'] = \
            Device(self.cli.api, 'dummy', 'dummy', curve25519_key='a', ed25519_key='a')
        user_devices = {self.alice: [self.alice_device_id], 'dummy': ['dummy']}
        session = MegolmOutboundSession()

        # Sharing with Alice should succeed, but dummy will fail
        self.device.megolm_share_session(self.room_id, user_devices, session)
        assert session.devices == {self.alice_device_id, 'dummy'}

        req = json.loads(responses.calls[1].request.body)['messages']
        assert self.alice in req
        assert 'dummy' not in req

    @responses.activate
    def test_megolm_start_session(self):
        to_device_url = HOSTNAME + MATRIX_V2_API_PATH + '/sendToDevice/m.room.encrypted/1'
        responses.add(responses.PUT, to_device_url, json={})
        self.device.device_keys[self.alice][self.alice_device_id] = self.alice_device
        self.device.device_list.tracked_user_ids.add(self.alice)
        self.device.olm_sessions[self.alice_curve_key] = [self.alice_olm_session]
        user_devices = {self.alice: [self.alice_device_id]}

        self.device.megolm_start_session(self.room, user_devices)
        session = self.device.megolm_outbound_sessions[self.room_id]
        assert self.alice_device_id in session.devices

        # Check that we can decrypt our own messages
        plaintext = {
            'type': 'test',
            'content': {'test': 'test'},
        }
        encrypted_event = self.device.megolm_build_encrypted_event(self.room, plaintext)
        event = {
            'sender': self.alice,
            'room_id': self.room_id,
            'content': encrypted_event,
            'type': 'm.room.encrypted',
            'origin_server_ts': 1,
            'event_id': 1
        }
        self.device.megolm_decrypt_event(event)
        assert event['content'] == plaintext['content']

    @responses.activate
    def test_megolm_share_session_with_new_devices(self):
        to_device_url = HOSTNAME + MATRIX_V2_API_PATH + '/sendToDevice/m.room.encrypted/1'
        responses.add(responses.PUT, to_device_url, json={})
        self.device.device_keys[self.alice][self.alice_device_id] = self.alice_device
        self.device.olm_sessions[self.alice_curve_key] = [self.alice_olm_session]
        session = MegolmOutboundSession()
        self.device.megolm_outbound_sessions[self.room_id] = session
        user_devices = {self.alice: [self.alice_device_id]}

        self.device.megolm_share_session_with_new_devices(
            self.room, user_devices, session)
        assert self.alice_device_id in session.devices
        assert len(responses.calls) == 1

        self.device.megolm_share_session_with_new_devices(
            self.room, user_devices, session)
        assert len(responses.calls) == 1

    def test_megolm_get_recipients(self):
        self.device.device_keys[self.alice][self.alice_device_id] = self.alice_device

        user_devices, _ = self.device.megolm_get_recipients(self.room)
        assert user_devices == {self.alice: [self.alice_device_id]}

        self.device.megolm_outbound_sessions.clear()
        session = MegolmOutboundSession()
        self.device.megolm_outbound_sessions[self.room_id] = session

        user_devices, removed = self.device.megolm_get_recipients(self.room, session)
        assert user_devices == {self.alice: [self.alice_device_id]} and not removed

        self.alice_device.blacklisted = True
        _, removed = self.device.megolm_get_recipients(self.room, session)
        assert not removed
        session.add_device(self.alice_device_id)
        _, removed = self.device.megolm_get_recipients(self.room, session)
        assert removed and self.room_id not in self.device.megolm_outbound_sessions
        self.alice_device.blacklisted = False

        self.room.verify_devices = True
        with pytest.raises(E2EUnknownDevices) as e:
            self.device.megolm_get_recipients(self.room)
        assert e.value.user_devices == {self.alice: [self.alice_device]}
        self.room.verify_devices = False

    @responses.activate
    def test_megolm_build_encrypted_event(self):
        to_device_url = HOSTNAME + MATRIX_V2_API_PATH + '/sendToDevice/m.room.encrypted/1'
        responses.add(responses.PUT, to_device_url, json={})
        self.device.megolm_outbound_sessions.clear()
        self.device.device_keys[self.alice][self.alice_device_id] = self.alice_device
        self.device.device_list.tracked_user_ids.add(self.alice)
        self.device.olm_sessions[self.alice_curve_key] = [self.alice_olm_session]
        event = {'type': 'm.room.message', 'content': {'body': 'test'}}

        self.room.rotation_period_msgs = 1
        self.device.megolm_build_encrypted_event(self.room, event)

        self.device.megolm_build_encrypted_event(self.room, event)

        session = self.device.megolm_outbound_sessions[self.room_id]
        session.encrypt('test')
        self.device.megolm_build_encrypted_event(self.room, event)
        assert self.device.megolm_outbound_sessions[self.room_id].id != session.id

    def test_megolm_remove_outbound_session(self):
        session = MegolmOutboundSession()
        self.device.megolm_outbound_sessions[self.room_id] = session
        self.device.megolm_remove_outbound_session(self.room_id)
        self.device.megolm_remove_outbound_session(self.room_id)

    @responses.activate
    def test_send_encrypted_message(self):
        message_url = HOSTNAME + MATRIX_V2_API_PATH + \
            '/rooms/{}/send/m.room.encrypted/1'.format(quote(self.room.room_id))
        responses.add(responses.PUT, message_url, json={})
        self.device.device_keys[self.alice][self.alice_device_id] = self.alice_device
        self.device.olm_sessions[self.alice_curve_key] = [self.alice_olm_session]
        session = MegolmOutboundSession()
        session.add_device(self.alice_device_id)
        self.device.megolm_outbound_sessions[self.room_id] = session

        self.device.send_encrypted_message(self.room, {'test': 'test'})

    def test_megolm_add_inbound_session(self):
        session = MegolmOutboundSession()
        self.device.megolm_inbound_sessions.clear()

        assert not self.device.megolm_add_inbound_session(
            self.room_id, self.alice_curve_key, self.alice_ed_key, session.id, 'wrong')
        assert self.device.megolm_add_inbound_session(
            self.room_id, self.alice_curve_key, self.alice_ed_key, session.id,
            session.session_key
        )
        assert session.id in \
            self.device.megolm_inbound_sessions[self.room_id][self.alice_curve_key]
        assert not self.device.megolm_add_inbound_session(
            self.room_id, self.alice_curve_key, self.alice_ed_key, session.id,
            session.session_key
        )
        assert not self.device.megolm_add_inbound_session(
            self.room_id, self.alice_curve_key, self.alice_ed_key, 'wrong',
            session.session_key
        )

    def test_handle_room_key_event(self):
        self.device.megolm_inbound_sessions.clear()

        self.device.handle_room_key_event(example_room_key_event, self.alice_curve_key)
        assert self.room_id in self.device.megolm_inbound_sessions

        self.device.handle_room_key_event(example_room_key_event, self.alice_curve_key)

        event = deepcopy(example_room_key_event)
        event['content']['algorithm'] = 'wrong'
        self.device.handle_room_key_event(event, self.alice_curve_key)

        event = deepcopy(example_room_key_event)
        event['content']['session_id'] = 'wrong'
        self.device.handle_room_key_event(event, self.alice_curve_key)

    def test_olm_handle_encrypted_event(self):
        self.device.olm_sessions.clear()
        alice_device = OlmDevice(self.device.api, self.alice, self.alice_device_id)
        alice_device.device_keys[self.user_id][self.device_id] = self.device
        self.device.device_keys[self.alice][self.alice_device_id] = alice_device

        # Artificially start an Olm session from Alice
        self.device.olm_account.generate_one_time_keys(1)
        otk = next(iter(self.device.olm_account.one_time_keys['curve25519'].values()))
        self.device.olm_account.mark_keys_as_published()
        sender_key = self.device.curve25519
        session = olm.OutboundSession(alice_device.olm_account, sender_key, otk)
        alice_device.olm_sessions[sender_key] = [session]

        content = example_room_key_event['content']
        encrypted_event = alice_device.olm_build_encrypted_event(
            'm.room_key', content, self.user_id, self.device_id)
        event = {
            'type': 'm.room.encrypted',
            'content': encrypted_event,
            'sender': self.alice
        }

        self.device.olm_handle_encrypted_event(event)

        # Decrypting the same event twice will trigger an error
        self.device.olm_handle_encrypted_event(event)

        encrypted_event = alice_device.olm_build_encrypted_event(
            'm.other', content, self.user_id, self.device_id)
        event = {
            'type': 'm.room.encrypted',
            'content': encrypted_event,
            'sender': self.alice
        }
        self.device.olm_handle_encrypted_event(event)

        # Simulate redacted event
        event['content'].pop('algorithm')
        self.device.olm_handle_encrypted_event(event)

    def test_megolm_decrypt_event(self):
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

        with pytest.raises(RuntimeError):
            self.device.megolm_decrypt_event(event)

        session_key = out_session.session_key
        in_session = MegolmInboundSession(session_key, self.alice_ed_key)
        sessions = self.device.megolm_inbound_sessions[self.room_id]
        sessions[self.alice_curve_key][in_session.id] = in_session

        # Unknown message index
        with pytest.raises(RuntimeError):
            self.device.megolm_decrypt_event(event)

        ciphertext = out_session.encrypt(json.dumps(plaintext))
        event['content']['ciphertext'] = ciphertext
        self.device.megolm_decrypt_event(event)
        assert event['content'] == plaintext['content']

        # No replay attack
        event['content'] = content
        self.device.megolm_decrypt_event(event)
        assert event['content'] == plaintext['content']

        # Replay attack
        event['content'] = content
        event['event_id'] = 2
        with pytest.raises(RuntimeError):
            self.device.megolm_decrypt_event(event)
        event['event_id'] = 1

        # Device verification
        self.device.device_keys[self.alice][self.alice_device_id] = self.alice_device
        event['content'] = content
        # Unverified
        self.device.megolm_decrypt_event(event)
        assert event['content'] == plaintext['content']
        assert isinstance(event, dict)

        event['content'] = content
        # Verified
        self.alice_device.verified = True
        decrypted_event = self.device.megolm_decrypt_event(event)
        assert decrypted_event['content'] == plaintext['content']
        assert isinstance(decrypted_event, VerifiedEvent)

        in_session = MegolmInboundSession(session_key, self.alice_curve_key)
        sessions = self.device.megolm_inbound_sessions[self.room_id]
        sessions[self.alice_curve_key][in_session.id] = in_session
        # Wrong signing key
        with pytest.raises(RuntimeError):
            self.device.megolm_decrypt_event(event)
        self.alice_device.verified = False

        event['content']['algorithm'] = 'wrong'
        with pytest.raises(RuntimeError):
            self.device.megolm_decrypt_event(event)

        event['content'].pop('algorithm')
        event['type'] = 'encrypted'
        self.device.megolm_decrypt_event(event)
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
