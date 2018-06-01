import logging

import olm
from canonicaljson import encode_canonical_json

from matrix_client.checks import check_user_id

logger = logging.getLogger(__name__)


class OlmDevice(object):
    """Manages the Olm cryptographic functions.

    Has a unique Olm account which holds identity keys.

    Args:
        api (MatrixHttpApi): The api object used to make requests.
        user_id (str): Matrix user ID. Must match the one used when logging in.
        device_id (str): Must match the one used when logging in.
    """

    _olm_algorithm = 'm.olm.v1.curve25519-aes-sha2'
    _megolm_algorithm = 'm.megolm.v1.aes-sha2'
    _algorithms = [_olm_algorithm, _megolm_algorithm]

    def __init__(self, api, user_id, device_id):
        self.api = api
        check_user_id(user_id)
        self.user_id = user_id
        self.device_id = device_id
        self.olm_account = olm.Account()
        logger.info('Initialised Olm Device.')
        self.identity_keys = self.olm_account.identity_keys
        self.one_time_key_counts = {}

    def upload_identity_keys(self):
        """Uploads this device's identity keys to HS.

        This device must be the one used when logging in.
        """
        device_keys = {
            'user_id': self.user_id,
            'device_id': self.device_id,
            'algorithms': self._algorithms,
            'keys': {'{}:{}'.format(alg, self.device_id): key
                     for alg, key in self.identity_keys.items()}
        }
        self.sign_json(device_keys)
        ret = self.api.upload_keys(device_keys=device_keys)
        self.one_time_key_counts = ret['one_time_key_counts']
        logger.info('Uploaded identity keys.')

    def sign_json(self, json):
        """Signs a JSON object.

        NOTE: The object is modified in-place and the return value can be ignored.

        As specified, this is done by encoding the JSON object without ``signatures`` or
        keys grouped as ``unsigned``, using canonical encoding.

        Args:
            json (dict): The JSON object to sign.

        Returns:
            The same JSON object, with a ``signatures`` key added. It is formatted as
            ``"signatures": ed25519:<device_id>: <base64_signature>``.
        """
        signatures = json.pop('signatures', {})
        unsigned = json.pop('unsigned', None)

        signature_base64 = self.olm_account.sign(encode_canonical_json(json))

        key_id = 'ed25519:{}'.format(self.device_id)
        signatures.setdefault(self.user_id, {})[key_id] = signature_base64

        json['signatures'] = signatures
        if unsigned:
            json['unsigned'] = unsigned

        return json

    def verify_json(self, json, user_key, user_id, device_id):
        """Verifies a signed key object's signature.

        The object must have a 'signatures' key associated with an object of the form
        `user_id: {key_id: signature}`.

        Args:
            json (dict): The JSON object to verify.
            user_key (str): The public ed25519 key which was used to sign the object.
            user_id (str): The user who owns the device.
            device_id (str): The device who owns the key.

        Returns:
            True if the verification was successful, False if not.
        """
        try:
            signatures = json.pop('signatures')
        except KeyError:
            return False

        key_id = 'ed25519:{}'.format(device_id)
        try:
            signature_base64 = signatures[user_id][key_id]
        except KeyError:
            json['signatures'] = signatures
            return False

        unsigned = json.pop('unsigned', None)

        try:
            olm.ed25519_verify(user_key, encode_canonical_json(json), signature_base64)
            success = True
        except olm.utility.OlmVerifyError:
            success = False

        json['signatures'] = signatures
        if unsigned:
            json['unsigned'] = unsigned

        return success
