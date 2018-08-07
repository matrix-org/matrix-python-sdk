import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


class KeySharingManager(object):

    def __init__(self, api, db, user_id, device_id, olm_device):
        self.api = api
        self.db = db
        self.user_id = user_id
        self.device_id = device_id
        self.olm_device = olm_device
        self.queued_key_requests = defaultdict(dict)
        self.outgoing_key_requests = set()
        self.db.load_outgoing_key_requests(self.outgoing_key_requests)
        self.key_request_callback = None
        self.key_forward_callback = None

    def handle_forwarded_room_key_event(self, event, sender, sender_key):
        """Handle a ``m.forwarded_room_key`` event.

        The key it contains will be used only if it was requested previously, and comes
        from a device owned by the current user. A cancelation will be sent. Otherwise, it
        will be discarded, and no cancelation will be sent.

        Args:
            event (dict): A ``m.forwarded_room_key`` event.
            sender_key (str): The Curve25519 key of the event's sender.
        """
        if sender != self.user_id:
            logger.info('Ignoring m.forwarded_room_key event sent by %s.', sender)
            return
        content = event['content']
        if content['algorithm'] != self.olm_device._megolm_algorithm:
            logger.info('Ignoring unsupported algorithm %s in m.forwarded_room_key '
                        'event from device %s.', content['algorithm'], sender_key)
            return

        session_id = content['session_id']
        if session_id not in self.outgoing_key_requests:
            logger.info('Ignoring session key we have not requested from device %s.',
                        sender_key)
            return

        room_id = content['room_id']
        session_sender_key = content['sender_key']
        signing_key = content['sender_claimed_ed25519_key']
        chain = content['forwarding_curve25519_key_chain']
        chain.append(session_sender_key)
        try:
            self.olm_device.megolm_add_inbound_session(
                room_id, session_sender_key, signing_key, session_id,
                content['session_key'], forwarding_chain=chain, export_format=True
            )
        except ValueError as e:
            logger.warning('Error in forwarded room key payload for session %s: %s',
                           session_id, e)
            return
        payload = {
            'action': 'cancel_request',
            'request_id': session_id,
            'requesting_device_id': self.device_id
        }
        self.api.send_to_device('m.room_key_request', {self.user_id: {'*': payload}})
        self.outgoing_key_requests.discard(session_id)
        self.db.remove_outgoing_key_request(session_id)
        if self.key_forward_callback:
            self.key_forward_callback(session_id)

    def handle_key_request(self, event):
        """Handle a ``m.room_key_request`` event.

        Args:
            event (dict): m.room_key_request event.
        """
        if event['sender'] != self.user_id:
            logger.info("Ignoring m.room_key_request event from %s.", event['sender'])
            return

        content = event['content']
        device_id = content['requesting_device_id']
        if device_id == self.device_id:
            return
        try:
            self.olm_device.device_keys[self.user_id][device_id]
        except KeyError:
            logger.info("Ignoring m.room_key_request event from device %s, which "
                        "we don't own.", device_id)
            return

        # Build a queue of key requests as we don't want to tell client of each requests,
        # knowing that the canceling event might be coming right up next.
        request_id = content['request_id']
        if content['action'] == 'request':
            body = content['body']
            if body['algorithm'] != self.olm_device._megolm_algorithm:
                return
            if request_id not in self.queued_key_requests[device_id]:
                self.queued_key_requests[device_id][request_id] = body
        elif content['action'] == 'cancel_request':
            # This doesn't remove request_id from the dict, so we will never
            # add an event with this request ID again.
            self.queued_key_requests[device_id][request_id].clear()

    def trigger_key_requests_callback(self):
        if not self.key_request_callback:
            return
        devices = {}
        for device_id in self.queued_key_requests:
            device = self.olm_device.device_keys[self.user_id][device_id]
            devices[device_id] = device
        if devices:
            self.key_request_callback(devices, self.process_key_requests)

    def process_key_requests(self, device_ids):
        """Share the key requested by the given device_ids.

        This empties the key request queue we keep upon completion, meaning that any
        request from a device not present in ``device_ids`` will be discarded.

        Args:
            device_ids (iterable): The device IDs who should see their request answered,
                if possible.
        """
        logger.info('Sharing requested sessions with devices %s.', device_ids)

        # TODO: improve this as in the case of a new device which request keys
        # on start-up, we may not have the time to fetch its keys.
        self.olm_device.olm_ensure_sessions({self.user_id: device_ids})
        for device_id in device_ids:
            if not self.queued_key_requests[device_id]:
                continue
            for event in self.queued_key_requests[device_id].values():
                session_id = event['session_id']
                room_id = event['room_id']
                sender_key = event['sender_key']
                sessions = self.olm_device.megolm_inbound_sessions[room_id][sender_key]
                try:
                    session = sessions[session_id]
                except KeyError:
                    session = self.olm_device.db.get_inbound_session(room_id, sender_key,
                                                                     session_id)
                    if not session:
                        continue
                payload = self.build_forwarded_room_key_event(room_id, sender_key,
                                                              session)
                event = self.olm_device.olm_build_encrypted_event(
                    'm.forwarded_room_key', payload, self.user_id, device_id)
                self.api.send_to_device(
                    'm.room.encrypted', {self.user_id: {device_id: event}})
        self.queued_key_requests.clear()

    def build_forwarded_room_key_event(self, room_id, sender_key, session):
        payload = {
            'algorithm': self.olm_device._megolm_algorithm,
            'room_id': room_id,
            'sender_key': sender_key,
            'sender_claimed_ed25519_key': session.ed25519,
            'session_id': session.id,
            'session_key': session.export_session(session.first_known_index),
            'forwarding_curve25519_key_chain': session.forwarding_chain,
        }
        return payload

    def request_missing_key(self, encrypted_event, force=False):
        """Request the key used to encrypt the event from our devices.

        Args:
            encrypted_event (dict): A ``m.room.encrypted`` Megolm event.
            force (bool): Optional. If ``True``, send a request even if one has already
                been sent.
        """
        # If no callback is registered in ordered to handle forwarded keys, it is
        # useless to request them.
        if not self.key_forward_callback:
            return
        content = encrypted_event['content']
        session_id = content['session_id']
        if session_id in self.outgoing_key_requests and not force:
            logger.info('Already have an outgoing key request for session %s.',
                        session_id)
            return
        logger.info('Requesting keys for session %s.', session_id)
        payload = {
            'action': 'request',
            'body': {
                'algorithm': content['algorithm'],
                'session_id': session_id,
                'room_id': encrypted_event['room_id'],
                'sender_key': content['sender_key']
            },
            'request_id': session_id,
            'requesting_device_id': self.device_id
        }
        self.api.send_to_device('m.room_key_request', {self.user_id: {'*': payload}})
        self.outgoing_key_requests.add(session_id)
        self.db.add_outgoing_key_request(session_id)
