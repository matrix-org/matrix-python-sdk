import pytest
pytest.importorskip("olm")  # noqa

from copy import deepcopy

from matrix_client.client import MatrixClient
from matrix_client.crypto.olm_device import OlmDevice

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
