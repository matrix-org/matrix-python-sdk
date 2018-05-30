import pytest
olm = pytest.importorskip("olm")  # noqa

import json
import logging
from copy import deepcopy

import responses

from matrix_client.crypto import olm_device
from matrix_client.api import MATRIX_V2_API_PATH
from matrix_client.client import MatrixClient
from matrix_client.crypto.olm_device import OlmDevice
from test.response_examples import (example_key_upload_response,
                                    example_claim_keys_response)

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
    alice_identity_keys = {
        'curve25519': alice_curve_key,
        'ed25519': '4VjV3OhFUxWFAcO5YOaQVmTIn29JdRmtNh9iAxoyhkc'
    }

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
        self.device.device_keys[self.alice][self.alice_device_id] = \
            self.alice_identity_keys
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
        self.device.device_keys[self.alice][self.alice_device_id] = \
            self.alice_identity_keys
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
        alice_device.device_keys[self.user_id][self.device_id] = self.device.identity_keys
        self.device.device_keys[self.alice][self.alice_device_id] = \
            alice_device.identity_keys

        # Artificially start an Olm session from Alice
        self.device.olm_account.generate_one_time_keys(1)
        otk = next(iter(self.device.olm_account.one_time_keys['curve25519'].values()))
        self.device.olm_account.mark_keys_as_published()
        sender_key = self.device.identity_keys['curve25519']
        session = olm.OutboundSession(alice_device.olm_account, sender_key, otk)
        alice_device.olm_sessions[sender_key] = [session]

        encrypted_event = alice_device.olm_build_encrypted_event(
            'example_type', {'content': 'test'}, self.user_id, self.device_id)

        # Now we can test
        self.device.olm_decrypt_event(encrypted_event, self.alice)

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
        backup = self.device.identity_keys['ed25519']
        self.device.identity_keys['ed25519'] = 'wrong'
        with pytest.raises(RuntimeError):
            self.device.olm_decrypt_event(encrypted_event, self.alice)
        self.device.identity_keys['ed25519'] = backup

    @responses.activate
    def test_olm_ensure_sessions(self):
        claim_url = HOSTNAME + MATRIX_V2_API_PATH + '/keys/claim'
        responses.add(responses.POST, claim_url, json=example_claim_keys_response)
        self.device.olm_sessions.clear()
        alice_device_id = 'JLAFKJWSCS'
        alice_curve_key = 'mmFRSHuJVq3aTudx3KB3w5ZvSFQhgEcy8d+m+vkEfUQ'
        self.device.device_keys[self.alice][alice_device_id] = {
            'curve25519': alice_curve_key,
            'ed25519': '4VjV3OhFUxWFAcO5YOaQVmTIn29JdRmtNh9iAxoyhkc'
        }
        user_devices = {self.alice: [alice_device_id]}

        self.device.olm_ensure_sessions(user_devices)
        assert self.device.olm_sessions[alice_curve_key]
        assert len(responses.calls) == 1

        self.device.olm_ensure_sessions(user_devices)
        assert len(responses.calls) == 1
