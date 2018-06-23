import pytest
pytest.importorskip("olm")  # noqa

import json
from copy import deepcopy

import responses

from matrix_client.api import MATRIX_V2_API_PATH
from matrix_client.client import MatrixClient
from matrix_client.crypto.olm_device import OlmDevice
from test.response_examples import example_key_upload_response

HOSTNAME = 'http://example.com'


class TestOlmDevice:
    cli = MatrixClient(HOSTNAME)
    user_id = '@user:matrix.org'
    device_id = 'QBUAZIFURK'
    device = OlmDevice(cli.api, user_id, device_id)
    signing_key = device.olm_account.identity_keys['ed25519']

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
