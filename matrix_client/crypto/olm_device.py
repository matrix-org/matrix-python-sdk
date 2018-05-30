import json
import logging
from collections import defaultdict

import olm
from canonicaljson import encode_canonical_json

from matrix_client.checks import check_user_id
from matrix_client.crypto.one_time_keys import OneTimeKeysManager
from matrix_client.crypto.device_list import DeviceList

logger = logging.getLogger(__name__)


class OlmDevice(object):
    """Manages the Olm cryptographic functions.

    Has a unique Olm account which holds identity keys.

    Args:
        api (MatrixHttpApi): The api object used to make requests.
        user_id (str): Matrix user ID. Must match the one used when logging in.
        device_id (str): Must match the one used when logging in.
        signed_keys_proportion (float): Optional. The proportion of signed one-time keys
            we should maintain on the HS compared to unsigned keys. The maximum value of
            ``1`` means only signed keys will be uploaded, while the minimum value of
            ``0`` means only unsigned keys. The actual amount of keys is determined at
            runtime from the given proportion and the maximum number of one-time keys
            we can physically hold.
        keys_threshold (float): Optional. Threshold below which a one-time key
            replenishment is triggered. Must be between ``0`` and ``1``. For example,
            ``0.1`` means that new one-time keys will be uploaded when there is less than
            10% of the maximum number of one-time keys on the server.
    """

    _olm_algorithm = 'm.olm.v1.curve25519-aes-sha2'
    _megolm_algorithm = 'm.megolm.v1.aes-sha2'
    _algorithms = [_olm_algorithm, _megolm_algorithm]

    def __init__(self,
                 api,
                 user_id,
                 device_id,
                 signed_keys_proportion=1,
                 keys_threshold=0.1):
        if not 0 <= signed_keys_proportion <= 1:
            raise ValueError('signed_keys_proportion must be between 0 and 1.')
        if not 0 <= keys_threshold <= 1:
            raise ValueError('keys_threshold must be between 0 and 1.')
        self.api = api
        check_user_id(user_id)
        self.user_id = user_id
        self.device_id = device_id
        self.olm_account = olm.Account()
        logger.info('Initialised Olm Device.')
        self.identity_keys = self.olm_account.identity_keys
        # Try to maintain half the number of one-time keys libolm can hold uploaded
        # on the HS. This is because some keys will be claimed by peers but not
        # used instantly, and we want them to stay in libolm, until the limit is reached
        # and it starts discarding keys, starting by the oldest.
        target_keys_number = self.olm_account.max_one_time_keys // 2
        self.one_time_keys_manager = OneTimeKeysManager(target_keys_number,
                                                        signed_keys_proportion,
                                                        keys_threshold)
        self.device_keys = defaultdict(dict)
        self.device_list = DeviceList(self, api, self.device_keys)
        self.olm_sessions = defaultdict(list)

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
        self.one_time_keys_manager.server_counts = ret['one_time_key_counts']
        logger.info('Uploaded identity keys.')

    def upload_one_time_keys(self, force_update=False):
        """Uploads new one-time keys to the HS, if needed.

        Args:
            force_update (bool): Fetch the number of one-time keys currently on the HS
                before uploading, even if we already know one. In most cases this should
                not be necessary, as we get this value from sync responses.

        Returns:
            A dict containg the number of new keys that were uploaded for each key type
                (signed_curve25519 or curve25519). The format is
                ``<key_type>: <uploaded_number>``. If no keys of a given type have been
                uploaded, the corresponding key will not be present. Consequently, an
                empty dict indicates that no keys were uploaded.
        """
        if force_update or not self.one_time_keys_manager.server_counts:
            counts = self.api.upload_keys()['one_time_key_counts']
            self.one_time_keys_manager.server_counts = counts

        signed_keys_to_upload = self.one_time_keys_manager.signed_curve25519_to_upload
        unsigned_keys_to_upload = self.one_time_keys_manager.curve25519_to_upload

        self.olm_account.generate_one_time_keys(signed_keys_to_upload +
                                                unsigned_keys_to_upload)

        one_time_keys = {}
        keys = self.olm_account.one_time_keys['curve25519']
        for i, key_id in enumerate(keys):
            if i < signed_keys_to_upload:
                key = self.sign_json({'key': keys[key_id]})
                key_type = 'signed_curve25519'
            else:
                key = keys[key_id]
                key_type = 'curve25519'
            one_time_keys['{}:{}'.format(key_type, key_id)] = key

        ret = self.api.upload_keys(one_time_keys=one_time_keys)
        self.one_time_keys_manager.server_counts = ret['one_time_key_counts']
        self.olm_account.mark_keys_as_published()

        keys_uploaded = {}
        if unsigned_keys_to_upload:
            keys_uploaded['curve25519'] = unsigned_keys_to_upload
        if signed_keys_to_upload:
            keys_uploaded['signed_curve25519'] = signed_keys_to_upload
        logger.info('Uploaded new one-time keys: %s.', keys_uploaded)
        return keys_uploaded

    def update_one_time_key_counts(self, counts):
        """Update data on one-time keys count and upload new ones if necessary.

        Args:
            counts (dict): Counts of keys currently on the HS for each key type.
        """
        self.one_time_keys_manager.server_counts = counts
        if self.one_time_keys_manager.should_upload():
            logger.info('Uploading new one-time keys.')
            self.upload_one_time_keys()

    def olm_start_sessions(self, user_devices):
        """Start olm sessions with the given devices.

        NOTE: those device keys must already be known.

        Args:
            user_devices (dict): A map from user_id to an iterable of device_ids.
                The format is ``<user_id>: [<device_id>]``.
        """
        logger.info('Trying to establish Olm sessions with devices: %s.',
                    dict(user_devices))
        payload = defaultdict(dict)
        for user_id in user_devices:
            for device_id in user_devices[user_id]:
                payload[user_id][device_id] = 'signed_curve25519'

        resp = self.api.claim_keys(payload)
        if resp.get('failures'):
            logger.warning('Failed to claim one-time keys from the following unreachable '
                           'homeservers: %s.', resp['failures'])
        keys = resp['one_time_keys']
        if logger.level >= logging.WARNING:
            missing = {}
            for user_id, device_ids in user_devices.items():
                if user_id not in keys:
                    missing[user_id] = device_ids
                else:
                    missing_devices = set(device_ids) - set(keys[user_id])
                    if missing_devices:
                        missing[user_id] = missing_devices
            logger.warning('Failed to claim the keys of %s.', missing)

        for user_id in user_devices:
            for device_id, one_time_key in keys.get(user_id, {}).items():
                try:
                    device_keys = self.device_keys[user_id][device_id]
                except KeyError:
                    logger.warning('Key for device %s of user %s not found, could not '
                                   'start Olm session.', device_id, user_id)
                    continue
                key_object = next(iter(one_time_key.values()))
                verified = self.verify_json(key_object,
                                            device_keys['ed25519'],
                                            user_id,
                                            device_id)
                if verified:
                    session = olm.OutboundSession(self.olm_account,
                                                  device_keys['curve25519'],
                                                  key_object['key'])
                    sessions = self.olm_sessions[device_keys['curve25519']]
                    sessions.append(session)
                    logger.info('Established Olm session %s with device %s of user '
                                '%s.', device_id, session.id, user_id)
                else:
                    logger.warning('Signature verification for one-time key of device %s '
                                   'of user %s failed, could not start olm session.',
                                   device_id, user_id)

    def olm_build_encrypted_event(self, event_type, content, user_id, device_id):
        """Encrypt an event using Olm.

        NOTE: a session with this device must already be established.

        Args:
            event_type (str): The event type, will be encrypted.
            content (dict): The event content, will be encrypted.
            user_id (str): The intended recipient of the event.
            device_id (str): The device to encrypt to.

        Returns:
            The Olm encrypted event, as JSON.
        """
        try:
            keys = self.device_keys[user_id][device_id]
        except KeyError:
            raise RuntimeError('Device is unknown, could not encrypt.')

        signing_key = keys['ed25519']
        identity_key = keys['curve25519']

        payload = {
            'type': event_type,
            'content': content,
            'sender': self.user_id,
            'sender_device': self.device_id,
            'keys': {
                'ed25519': self.identity_keys['ed25519']
            },
            'recipient': user_id,
            'recipient_keys': {
                'ed25519': signing_key
            }
        }

        sessions = self.olm_sessions[identity_key]
        if sessions:
            session = sorted(sessions, key=lambda s: s.id)[0]
        else:
            raise RuntimeError('No session for this device, could not encrypt.')

        encrypted_message = session.encrypt(json.dumps(payload))
        ciphertext_payload = {
            identity_key: {
                'type': encrypted_message.message_type,
                'body': encrypted_message.ciphertext
            }
        }

        event = {
            'algorithm': self._olm_algorithm,
            'sender_key': self.identity_keys['curve25519'],
            'ciphertext': ciphertext_payload
        }
        return event

    def olm_decrypt_event(self, content, user_id):
        """Decrypt an Olm encrypted event, and check its properties.

        Args:
            event (dict): The content property of a m.room.encrypted event.
            user_id (str): The sender of the event.

        Retuns:
            The decrypted event held by the initial event.

        Raises:
            RuntimeError: Error in the decryption process. Nothing can be done. The text
                of the exception indicates what went wrong, and should be logged or
                displayed to the user.
            KeyError: The event is missing a required field.
        """
        if content['algorithm'] != self._olm_algorithm:
            raise RuntimeError('Event was not encrypted with {}.'
                               .format(self._olm_algorithm))

        ciphertext = content['ciphertext']
        try:
            payload = ciphertext[self.identity_keys['curve25519']]
        except KeyError:
            raise RuntimeError('This message was not encrypted for us.')

        msg_type = payload['type']
        if msg_type == 0:
            encrypted_message = olm.OlmPreKeyMessage(payload['body'])
        else:
            encrypted_message = olm.OlmMessage(payload['body'])

        decrypted_event = self._olm_decrypt(encrypted_message, content['sender_key'])

        if decrypted_event['sender'] != user_id:
            raise RuntimeError(
                'Found user {} instead of sender {} in Olm plaintext {}.'
                .format(decrypted_event['sender'], user_id, decrypted_event)
            )
        if decrypted_event['recipient'] != self.user_id:
            raise RuntimeError(
                'Found user {} instead of us ({}) in Olm plaintext {}.'
                .format(decrypted_event['recipient'], self.user_id, decrypted_event)
            )
        our_key = decrypted_event['recipient_keys']['ed25519']
        if our_key != self.identity_keys['ed25519']:
            raise RuntimeError(
                'Found key {} instead of ours own ed25519 key {} in Olm plaintext {}.'
                .format(our_key, self.identity_keys['ed25519'], decrypted_event)
            )

        return decrypted_event

    def _olm_decrypt(self, olm_message, sender_key):
        """Decrypt an Olm encrypted event.

        NOTE: This does no implement any security check.

        Try to decrypt using existing sessions. If it fails, start an new one when
            possible.

        Args:
            olm_message (OlmMessage): Olm encrypted payload.
            sender_key (str): The sender's curve25519 identity key.

        Returns:
            The decrypted event held by the initial payload, as JSON.
        """

        sessions = self.olm_sessions[sender_key]

        # Try to decrypt message body using one of the known sessions for that device
        for session in sessions:
            try:
                event = session.decrypt(olm_message)
                logger.info('Success decrypting Olm event using existing session %s.',
                            session.id)
                break
            except olm.session.OlmSessionError as e:
                if olm_message.message_type == 0:
                    if session.matches(olm_message, sender_key):
                        # We had a matching session for a pre-key message, but it didn't
                        # work. This means something is wrong, so we fail now.
                        raise RuntimeError('Error decrypting pre-key message with '
                                           'existing Olm session {}, reason: {}.'
                                           .format(session.id, e))
                # Simply keep trying otherwise
        else:
            if olm_message.message_type > 0:
                # Not a pre-key message, we should have had a matching session
                if sessions:
                    raise RuntimeError('Error decrypting with existing sessions.')
                raise RuntimeError('No existing sessions.')

            # We have a pre-key message without any matching session, in this case
            # we should try to create one.
            try:
                session = olm.session.InboundSession(
                    self.olm_account, olm_message, sender_key)
            except olm.session.OlmSessionError as e:
                raise RuntimeError('Error decrypting pre-key message when trying to '
                                   'establish a new session: {}.'.format(e))

            logger.info('Created new Olm session %s.', session.id)
            try:
                event = session.decrypt(olm_message)
            except olm.session.OlmSessionError as e:
                raise RuntimeError('Error decrypting pre-key message with new session: '
                                   '{}.'.format(e))
            self.olm_account.remove_one_time_keys(session)
            sessions.append(session)

        return json.loads(event)

    def olm_ensure_sessions(self, user_devices):
        """Start Olm sessions with the given devices if one doesn't exist already.

        Args:
            user_devices (dict): A map from user ids to a list of device ids.
        """
        user_devices_no_session = defaultdict(list)
        for user_id in user_devices:
            for device_id in user_devices[user_id]:
                curve_key = self.device_keys[user_id][device_id]['curve25519']
                # Check if we have a list of sessions for this device, which can be
                # empty. Implicitely, an empty list will indicate that we already tried
                # to establish a session with a device, but this attempt was
                # unsuccessful. We do not retry to establish a session.
                if curve_key not in self.olm_sessions:
                    user_devices_no_session[user_id].append(device_id)
        if user_devices_no_session:
            self.olm_start_sessions(user_devices_no_session)

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
