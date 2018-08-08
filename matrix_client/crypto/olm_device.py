import json
import logging
from collections import defaultdict

import olm
from canonicaljson import encode_canonical_json

from matrix_client.checks import check_user_id
from matrix_client.device import Device
from matrix_client.errors import E2EUnknownDevices, UnableToDecryptError
from matrix_client.crypto.one_time_keys import OneTimeKeysManager
from matrix_client.crypto.device_list import DeviceList
from matrix_client.crypto.sessions import MegolmOutboundSession, MegolmInboundSession
from matrix_client.crypto.crypto_store import CryptoStore
from matrix_client.crypto.verified_event import VerifiedEvent
from matrix_client.crypto.key_sharing import KeySharingManager
from matrix_client.crypto.key_export import encrypt_and_save, decrypt_and_read

logger = logging.getLogger(__name__)


class OlmDevice(Device):
    """Manages the Olm cryptographic functions.

    Has a unique Olm account which holds identity keys.

    Args:
        api (MatrixHttpApi): The api object used to make requests.
        user_id (str): Matrix user ID. Must match the one used when logging in.
        device_id (str): Optional. Must match the one used when logging in. If absent,
            attempt to retrieve it from database using ``user_id``.
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
        Store (class): Optional. Custom storage class. It should implement the same
            methods as :class:`~matrix_client.crypto.crypto_store.CryptoStore`.
        store_conf (dict): Optional. Configuration parameters for keys storage. Refer to
            :func:`~matrix_client.crypto.crypto_store.CryptoStore` for supported options,
            since it will be passed to this class.
        load_all (bool): Optional. If True, all content of the database for the current
            device will be loaded at once. This will increase runtime performance but
            also launch time and memory usage.

    Raises:
        ``ValueError`` if ``device_id`` was not given and couldn't be retrieved
            from database.
    """

    _olm_algorithm = 'm.olm.v1.curve25519-aes-sha2'
    _megolm_algorithm = 'm.megolm.v1.aes-sha2'
    _algorithms = [_olm_algorithm, _megolm_algorithm]

    def __init__(self,
                 api,
                 user_id,
                 device_id=None,
                 signed_keys_proportion=1,
                 keys_threshold=0.1,
                 Store=CryptoStore,
                 store_conf=None,
                 load_all=False):
        if not 0 <= signed_keys_proportion <= 1:
            raise ValueError('signed_keys_proportion must be between 0 and 1.')
        if not 0 <= keys_threshold <= 1:
            raise ValueError('keys_threshold must be between 0 and 1.')
        self.api = api
        check_user_id(user_id)
        self.user_id = user_id
        conf = store_conf or {}
        self.db = Store(user_id, device_id=device_id, **conf)
        self.olm_sessions = defaultdict(list)
        self.megolm_inbound_sessions = defaultdict(lambda: defaultdict(dict))
        self.megolm_outbound_sessions = {}
        self.device_keys = defaultdict(dict)
        self.olm_account = self.db.get_olm_account()
        if not device_id:
            device_id = self.db.device_id
        if self.olm_account:
            if load_all:
                self.db.load_olm_sessions(self.olm_sessions)
                self.db.load_inbound_sessions(self.megolm_inbound_sessions)
                self.db.load_outbound_sessions(self.megolm_outbound_sessions)
                self.db.load_device_keys(self.api, self.device_keys)
            logger.info('Loaded Olm account from database for device %s.', device_id)
        else:
            self.olm_account = olm.Account()
            self.db.replace_olm_account(self.olm_account)
            logger.info('Created new Olm account for device %s.', device_id)
        # Try to maintain half the number of one-time keys libolm can hold uploaded
        # on the HS. This is because some keys will be claimed by peers but not
        # used instantly, and we want them to stay in libolm, until the limit is reached
        # and it starts discarding keys, starting by the oldest.
        target_keys_number = self.olm_account.max_one_time_keys // 2
        self.one_time_keys_manager = OneTimeKeysManager(target_keys_number,
                                                        signed_keys_proportion,
                                                        keys_threshold)
        self.device_list = DeviceList(self, api, self.device_keys, self.db)
        self.megolm_index_record = defaultdict(dict)
        self.key_sharing_manager = KeySharingManager(api, self.db, user_id, device_id,
                                                     self)
        keys = self.olm_account.identity_keys
        super(OlmDevice, self).__init__(self.api, self.user_id, device_id,
                                        database=self.db, ed25519_key=keys['ed25519'],
                                        curve25519_key=keys['curve25519'])

    def upload_identity_keys(self):
        """Uploads this device's identity keys to HS.

        This device must be the one used when logging in.
        """
        device_keys = {
            'user_id': self.user_id,
            'device_id': self.device_id,
            'algorithms': self._algorithms,
            'keys': {
                'curve25519:{}'.format(self.device_id): self.curve25519,
                'ed25519:{}'.format(self.device_id): self.ed25519
            }
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
        self.db.save_olm_account(self.olm_account)

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

        new_sessions = defaultdict(list)
        for user_id in user_devices:
            for device_id, one_time_key in keys.get(user_id, {}).items():
                try:
                    device = self.device_keys[user_id][device_id]
                except KeyError:
                    logger.warning('Key for device %s of user %s not found, could not '
                                   'start Olm session.', device_id, user_id)
                    continue
                key_object = next(iter(one_time_key.values()))
                verified = self.verify_json(key_object,
                                            device.ed25519,
                                            user_id,
                                            device_id)
                if verified:
                    session = olm.OutboundSession(self.olm_account,
                                                  device.curve25519,
                                                  key_object['key'])
                    sessions = self.olm_sessions[device.curve25519]
                    sessions.append(session)
                    new_sessions[device.curve25519].append(session)
                    logger.info('Established Olm session %s with device %s of user '
                                '%s.', device_id, session.id, user_id)
                else:
                    logger.warning('Signature verification for one-time key of device %s '
                                   'of user %s failed, could not start olm session.',
                                   device_id, user_id)
        self.db.save_olm_sessions(new_sessions)

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
            device = self.device_keys[user_id][device_id]
        except KeyError:
            raise RuntimeError('Device is unknown, could not encrypt.')

        payload = {
            'type': event_type,
            'content': content,
            'sender': self.user_id,
            'sender_device': self.device_id,
            'keys': {
                'ed25519': self.ed25519
            },
            'recipient': user_id,
            'recipient_keys': {
                'ed25519': device.ed25519
            }
        }

        sessions = self.olm_sessions[device.curve25519]
        if sessions:
            session = sorted(sessions, key=lambda s: s.id)[0]
        else:
            raise RuntimeError('No session for this device, could not encrypt.')

        encrypted_message = session.encrypt(json.dumps(payload))
        self.db.save_olm_session(device.curve25519, session)
        ciphertext_payload = {
            device.curve25519: {
                'type': encrypted_message.message_type,
                'body': encrypted_message.ciphertext
            }
        }

        event = {
            'algorithm': self._olm_algorithm,
            'sender_key': self.curve25519,
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
            payload = ciphertext[self.curve25519]
        except KeyError:
            raise RuntimeError('This message was not encrypted for us.')

        msg_type = payload['type']
        if msg_type == 0:
            encrypted_message = olm.OlmPreKeyMessage(payload['body'])
        else:
            encrypted_message = olm.OlmMessage(payload['body'])

        sender_key = content['sender_key']
        decrypted_event = self._olm_decrypt(encrypted_message, sender_key)

        signing_key = decrypted_event['keys']['ed25519']
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
        if our_key != self.ed25519:
            raise RuntimeError(
                'Found key {} instead of ours own ed25519 key {} in Olm plaintext {}.'
                .format(our_key, self.ed25519, decrypted_event)
            )
        try:
            device = self.device_keys[user_id][decrypted_event['sender_device']]
        except KeyError:
            pass
        else:
            if device.verified:
                if device.curve25519 != sender_key or device.ed25519 != signing_key:
                    raise RuntimeError(
                        'Device keys mismatch between payload and /keys/query data.'
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
        if not sessions:
            # `sessions` should get populated by this method
            self.db.get_olm_sessions(sender_key, self.olm_sessions)

        # Try to decrypt message body using one of the known sessions for that device
        for session in sessions:
            try:
                event = session.decrypt(olm_message)
                self.db.save_olm_session(sender_key, session)
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
            self.db.save_olm_account(self.olm_account)
            self.db.save_olm_session(sender_key, session)
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
                curve_key = self.device_keys[user_id][device_id].curve25519
                # Check if we have a list of sessions for this device, which can be
                # empty. Implicitely, an empty list will indicate that we already tried
                # to establish a session with a device, but this attempt was
                # unsuccessful. We do not retry to establish a session.
                if curve_key not in self.olm_sessions:
                    sessions = self.db.get_olm_sessions(curve_key, self.olm_sessions)
                    if not sessions:
                        user_devices_no_session[user_id].append(device_id)
        if user_devices_no_session:
            self.olm_start_sessions(user_devices_no_session)

    def megolm_start_session(self, room, user_devices):
        """Start a megolm session in a room, and share it with its members.

        Args:
            room (Room): The room to use.
            user_devices (dict): Map from user id to a list of device ids. The session
                will be shared with those devices.

        Returns:
            The newly created session.
        """
        session = MegolmOutboundSession(max_age=room.rotation_period_ms,
                                        max_messages=room.rotation_period_msgs)
        self.megolm_outbound_sessions[room.room_id] = session
        logger.info('Starting a new Meglom outbound session %s in %s.',
                    session.id, room.room_id)

        self.db.remove_outbound_session(room.room_id)
        self.db.save_outbound_session(room.room_id, session)
        self.megolm_share_session(room.room_id, user_devices, session)
        # Store a corresponding inbound session, so that we can decrypt our own messages
        self.megolm_add_inbound_session(
            room.room_id, self.curve25519, self.ed25519, session.id, session.session_key)
        return session

    def megolm_share_session(self, room_id, user_devices, session):
        """Share an already existing outbound megolm session with the specified devices.

        Args:
            room_id (str): The room corresponding to the session.
            user_devices (dict): A map from user ids to a list of device ids.
            session (MegolmOutboundSession): The session object.
        """

        logger.info('Attempting to share Megolm session %s in %s with %s.',
                    session.id, room_id, user_devices)
        self.olm_ensure_sessions(user_devices)

        event = {
            'algorithm': self._megolm_algorithm,
            'room_id': room_id,
            'session_id': session.id,
            'session_key': session.session_key
        }

        messages = defaultdict(dict)
        new_devices = set()
        for user_id in user_devices:
            for device_id in user_devices[user_id]:
                try:
                    messages[user_id][device_id] = self.olm_build_encrypted_event(
                        'm.room_key', event, user_id, device_id
                    )
                except RuntimeError as e:
                    logger.warning('Could not share megolm session %s with device %s of '
                                   'user %s: %s', session.id,
                                   device_id, user_id, e)
                # We will not retry to share session with failed devices
                new_devices.add(device_id)
        self.api.send_to_device('m.room.encrypted', messages)
        session.add_devices(new_devices)
        self.db.save_megolm_outbound_devices(room_id, new_devices)

    def megolm_share_session_with_new_devices(self, room, user_devices, session):
        """Share a megolm session with new devices in a room.

        Args:
            room (Room): The room corresponding to the session.
            session (MegolmOutboundSession): The session to share.
            user_devices (dict): Map from user id to a list of device ids. The session
                will be shared with those devices if not already.
        """
        new_user_devices = {}
        for user_id in user_devices:
            missing_devices = list(set(self.device_keys[user_id].keys()) -
                                   self.megolm_outbound_sessions[room.room_id].devices)
            if missing_devices:
                new_user_devices[user_id] = missing_devices

        if new_user_devices:
            logger.info('Sharing existing Megolm outbound session %s with new '
                        'devices: %s', session.id, new_user_devices)
            self.megolm_share_session(room.room_id, new_user_devices, session)

    def megolm_get_recipients(self, room, session=None):
        """Get the devices who should be able to decrypt a Megolm event in a room.

        This implements device verification checks.

        Args:
            room (Room): The room to use.
            session (MegolmOutboundSession): Optional. If a device the session had
                been shared with has been blacklisted, remove the session.

        Returns:
            A two element tuple containing a map from user id to a list of device ids,
            and a boolean indicating whether the session has been removed.

        Raises:
            E2EUnknownDevices if there are never seen before devices in the room.
        """
        users = room.get_joined_members()

        user_devices = defaultdict(list)
        unknown_devices = defaultdict(list)
        removed_session = False
        for user in users:
            for device_id, device in self.device_keys[user.user_id].items():
                if device.blacklisted:
                    if session and device.device_id in session.devices:
                        self.megolm_remove_outbound_session(room.room_id)
                        removed_session = True
                else:
                    if not room.verify_devices or device.ignored or device.verified:
                        user_devices[user.user_id].append(device_id)
                    else:
                        unknown_devices[user.user_id].append(device)
        if unknown_devices and room.verify_devices:
            logger.warning('Room %s contains unknown devices which have not been '
                           'verified.', room.room_id)
            raise E2EUnknownDevices(unknown_devices)

        return user_devices, removed_session

    def megolm_build_encrypted_event(self, room, event):
        """Build an encrypted Megolm payload from a plaintext event.

        If no session exists in the room, a new one will be initiated. Also takes care
        of rotating the session periodically.

        Args:
            room (Room): The room the event will be sent in.
            event (dict): Matrix event.

        Returns:
            The encrypted event, as a dict.

        Raises:
            E2EUnknownDevices if there are never seen before devices in the room.
        """
        room_id = room.room_id

        try:
            session = self.megolm_outbound_sessions[room_id]
        except KeyError:
            session = self.db.get_outbound_session(room_id, self.megolm_outbound_sessions)
            # We have to fetch device keys if there is no session. If there is one, we are
            # already tracking the device list of users in the room, so it shouldn't be
            # needed.
            # However, there is the edge case where a device is blacklisted, and then the
            # client is shutdown. When we load the session, if we do not fetch the keys
            # (which triggers loading the devices from db), we would miss that a device
            # had been blacklisted and we would keep using the session instead of rotating
            # it as expected. Hence we also fetch device keys after a session is loaded.
            self.device_list.get_room_device_keys(room)

        user_devices, removed_session = self.megolm_get_recipients(room, session)

        if not session or removed_session or session.should_rotate():
            session = self.megolm_start_session(room, user_devices)
        else:
            self.megolm_share_session_with_new_devices(room, user_devices, session)

        payload = {
            'type': event['type'],
            'content': event['content'],
            'room_id': room_id
        }

        encrypted_payload = session.encrypt(json.dumps(payload))
        self.db.save_outbound_session(room_id, session)

        encrypted_event = {
            'algorithm': self._megolm_algorithm,
            'sender_key': self.curve25519,
            'ciphertext': encrypted_payload,
            'session_id': session.id,
            'device_id': self.device_id
        }
        return encrypted_event

    def megolm_remove_outbound_session(self, room_id):
        """Remove an existing Megolm outbound session in a room.

        If there is no such session, nothing will happen.

        Args:
            room_id (str): The room to use.
        """
        try:
            self.megolm_outbound_sessions.pop(room_id)
            self.db.remove_outbound_session(room_id)
            logger.info('Removed Meglom outbound session in %s.', room_id)
        except KeyError:
            pass

    def send_encrypted_message(self, room, content):
        """Send a m.room.encrypted event in a room.

        Args:
            room (Room): The room to use.
            content (dict): The content of the event, will be encrypted.

        Raises:
            MatrixRequestError if there was an error sending the event.
            E2EUnknownDevices if there are never seen before devices in the room.
                The event will not be sent.
        """
        event = {'content': content, 'room_id': room.room_id, 'type': 'm.room.message'}
        encrypted_event = self.megolm_build_encrypted_event(room, event)
        return self.api.send_message_event(
            room.room_id, 'm.room.encrypted', encrypted_event)

    def olm_handle_encrypted_event(self, encrypted_event):
        """Decrypt and process an Olm m.room.encrypted event.

        Once decrypted, the event is processed according to its type.

        Args:
            encrypted_event (dict): m.room.encrypted event.
        """
        content = encrypted_event['content']
        if 'algorithm' not in content or content['algorithm'] != self._olm_algorithm:
            return

        sender = encrypted_event['sender']
        try:
            event = self.olm_decrypt_event(content, sender)
        except RuntimeError as e:
            logger.warning('Failed to decrypt toDevice Olm event sent by user %s: %s',
                           encrypted_event['sender'], e)
            return

        sender_key = encrypted_event['content']['sender_key']
        if event['type'] == 'm.room_key':
            self.handle_room_key_event(event, sender_key)
        elif event['type'] == 'm.forwarded_room_key':
            self.key_sharing_manager.handle_forwarded_room_key_event(event, sender,
                                                                     sender_key)

    def handle_room_key_event(self, event, sender_key):
        """Handle a m.room_key event.

        Args:
            event (dict): m.room_key event.
        """
        signing_key = event['keys']['ed25519']
        content = event['content']
        if content['algorithm'] != self._megolm_algorithm:
            logger.info('Ignoring unsupported algorithm %s in m.room_key event.',
                        content['algorithm'])
            return
        user_id = event['sender']
        device_id = event['sender_device']

        try:
            new = self.megolm_add_inbound_session(content['room_id'], sender_key,
                                                  signing_key, content['session_id'],
                                                  content['session_key'])
        except ValueError as e:
            logger.warning(e)
            return
        if new:
            logger.info('Created a new Megolm inbound session with device %s of '
                        'user %s.', device_id, user_id)
        else:
            logger.info('Inbound Megolm session with device %s of user %s '
                        'already exists or is invalid.', device_id, user_id)

    def megolm_add_inbound_session(self, room_id, sender_key, signing_key, session_id,
                                   session_key, forwarding_chain=None,
                                   export_format=False):
        """Create a new Megolm inbound session if necessary.

        Args:
            room_id (str): The room corresponding to the session.
            sender_key (str): The curve25519 key of the sender's device.
            session_id (str): The id of the session.
            session_key (str): The key of the session.
            signing_key (str): The ed25519 key of the event which established the session.

        Returns:
            ``True`` if a new session was created, ``False`` if it already existed.

        Raises:
            ValueError if one of the parameters were invalid.
        """
        sessions = self.megolm_inbound_sessions[room_id][sender_key]
        if session_id in sessions:
            return False
        # Load the session if it exists
        if self.db.get_inbound_session(room_id, sender_key, session_id, sessions):
            return False
        try:
            if export_format:
                session = MegolmInboundSession.import_session(session_key, signing_key,
                                                              forwarding_chain)
            else:
                session = MegolmInboundSession(session_key, signing_key)
        except olm.OlmGroupSessionError as e:
            raise ValueError('olmlib error when trying to add the session: {}.'.format(e))
        if session.id != session_id:
            raise ValueError('Session ID mismatch in m.room_key event. Expected {} from '
                             'event property, got {}.'.format(session_id, session.id))
        self.db.save_inbound_session(room_id, sender_key, session)
        sessions[session_id] = session
        return True

    def megolm_decrypt_event(self, event):
        """Decrypt a Megolm m.room.encrypted event.

        Args:
            event (dict): The event to decrypt. It may be modified in the process.

        Returns:
            The decrypted event, as a normal ``dict`` if unverified, or as a
            :class:`.VerifiedEvent` if verified.
        """
        content = event['content']
        device_id = content['device_id']
        user_id = event['sender']
        if 'algorithm' not in content:
            # Assume that this is a redacted event
            return
        if content['algorithm'] != self._megolm_algorithm:
            raise RuntimeError('Incorrect algorithm "{}" value in event sent by device '
                               '{} of user {}.'.format(content['algorithm'], device_id,
                                                       user_id))

        sender_key = content['sender_key']
        room_id = event['room_id']
        session_id = content['session_id']
        sessions = self.megolm_inbound_sessions[room_id][sender_key]
        try:
            session = sessions[session_id]
        except KeyError:
            session = self.db.get_inbound_session(
                room_id, sender_key, session_id, sessions)
            if not session:
                raise UnableToDecryptError(
                    "Unable to decrypt event sent by device {} of user {}: The sender's "
                    "device has not sent us the keys for this message."
                    .format(device_id, user_id)
                )

        try:
            decrypted_event, message_index = session.decrypt(content['ciphertext'])
        except olm.group_session.OlmGroupSessionError as e:
            raise RuntimeError('Unable to decrypt event sent by device {} of user {} '
                               'with matching megolm session: {}.'.format(device_id,
                                                                          user_id, e))

        try:
            device = self.device_keys[user_id][device_id]
        except KeyError:
            pass
        else:
            # Do not mark events decrypted using a forwarded key as verified
            if device.verified and not session.forwarding_chain:
                if device.ed25519 != session.ed25519 or device.curve25519 != sender_key:
                    raise RuntimeError('Device keys mismatch in event sent by device {}.'
                                       .format(device.device_id))
                event = VerifiedEvent(event)

        try:
            properties = self.megolm_index_record[session.id][message_index]
        except KeyError:
            self.megolm_index_record[session.id][message_index] = {
                'origin_server_ts': event['origin_server_ts'],
                'event_id': event['event_id']
            }
        else:
            if properties['origin_server_ts'] != event['origin_server_ts'] or \
                    properties['event_id'] != event['event_id']:
                raise RuntimeError('Detected a replay attack from device {} of user {} '
                                   'on decrypted event: {}.'.format(device_id, user_id,
                                                                    decrypted_event))

        decrypted_event = json.loads(decrypted_event)

        event['type'] = decrypted_event['type']
        event['content'] = decrypted_event['content']

        return event

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

    def export_keys(self, outfile, passphrase, count=10000):
        """Export all the Megolm decryption keys of this device.

        The keys will be encrypted using the passphrase.

        NOTE:
            This does not save other information such as the private identity keys
            of the device.

        Args:
            outfile (str): The file to write the keys to.
            passphrase (str): The encryption passphrase.
            count (int): Optional. Round count for the underlying key derivation.
                It is not recommended to specify it unless absolutely sure of the
                consequences.
        """
        session_list = []
        self.db.load_inbound_sessions(self.megolm_inbound_sessions)
        for room_id in self.megolm_inbound_sessions:
            for sender_key, sessions in self.megolm_inbound_sessions[room_id].items():
                for session in sessions.values():
                    payload = {
                        'algorithm': self._megolm_algorithm,
                        'sender_key': sender_key,
                        'sender_claimed_keys': {
                            'ed25519': session.ed25519
                        },
                        'forwarding_curve25519_key_chain': session.forwarding_chain,
                        'room_id': room_id,
                        'session_id': session.id,
                        'session_key': session.export_session(session.first_known_index)
                    }
                    session_list.append(payload)
        data = json.dumps({'sessions': session_list}).encode()
        encrypt_and_save(data, outfile, passphrase, count=count)
        logger.info('Success exporting keys to %s.', outfile)

    def import_keys(self, infile, passphrase):
        """Import Megolm decryption keys.

        The keys will be added to the current instance as well as written to database.

        Args:
            infile (str): The file containing the keys.
            passphrase (str): The decryption passphrase.
        """
        data = decrypt_and_read(infile, passphrase)
        session_list = json.loads(data)['sessions']
        for session in session_list:
            if session['algorithm'] != self._megolm_algorithm:
                logger.warning('Ignoring session with unsupported algorithm.')
                continue
            # This could be improved by writing everything to db at once at the end
            self.megolm_add_inbound_session(
                session['room_id'], session['sender_key'],
                session['sender_claimed_keys']['ed25519'], session['session_id'],
                session['session_key'], session['forwarding_curve25519_key_chain'],
                export_format=True
            )
        logger.info('Success importing keys from %s.', infile)
