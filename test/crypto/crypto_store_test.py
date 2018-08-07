import pytest
olm = pytest.importorskip("olm")  # noqa

import os
from collections import defaultdict
from tempfile import mkdtemp

from matrix_client.crypto.crypto_store import CryptoStore
from matrix_client.crypto.olm_device import OlmDevice
from matrix_client.crypto.sessions import MegolmOutboundSession, MegolmInboundSession
from matrix_client.room import Room
from matrix_client.user import User


class TestCryptoStore(object):

    # Initialise a store and test some init code
    device_id = 'AUIETSRN'
    user_id = '@user:matrix.org'
    room_id = '!test:example.com'
    room = Room(None, room_id)
    user = User(None, user_id, '')
    room._members[user_id] = user
    db_name = 'test.db'
    db_path = mkdtemp()
    store_conf = {
        'db_name': db_name,
        'db_path': db_path
    }
    store = CryptoStore(
        user_id, device_id=device_id, db_path=db_path, db_name=db_name)
    db_filepath = os.path.join(db_path, db_name)
    assert os.path.exists(db_filepath)
    store.close()
    store = CryptoStore(
        user_id, device_id=device_id, db_path=db_path, db_name=db_name)

    @pytest.fixture(autouse=True, scope='class')
    def cleanup(self):
        yield
        os.remove(self.db_filepath)

    @pytest.fixture()
    def account(self):
        account = self.store.get_olm_account()
        if account is None:
            account = olm.Account()
            self.store.save_olm_account(account)
        return account

    @pytest.fixture()
    def curve_key(self, account):
        return account.identity_keys['curve25519']

    @pytest.fixture()
    def ed_key(self, account):
        return account.identity_keys['ed25519']

    @pytest.fixture()
    def device(self):
        return OlmDevice(None, self.user_id, self.device_id, store_conf=self.store_conf)

    def test_olm_account_persistence(self):
        account = olm.Account()
        identity_keys = account.identity_keys
        self.store.remove_olm_account()

        # Try to load inexisting account
        saved_account = self.store.get_olm_account()
        assert saved_account is None

        # Try to load inexisting account without device_id
        self.store.device_id = None
        with pytest.raises(ValueError):
            self.store.get_olm_account()
        self.store.device_id = self.device_id

        # Save and load
        self.store.save_olm_account(account)
        saved_account = self.store.get_olm_account()
        assert saved_account.identity_keys == identity_keys

        # Save and load without device_id
        self.store.save_olm_account(account)
        self.store.device_id = None
        saved_account = self.store.get_olm_account()
        assert saved_account.identity_keys == identity_keys
        assert self.store.device_id == self.device_id

        # Replace the account, causing foreign keys to be deleted
        self.store.save_sync_token('test')
        self.store.replace_olm_account(account)
        assert self.store.get_sync_token() is None

        # Load the account from an OlmDevice
        device = OlmDevice(None, self.user_id, self.device_id, store_conf=self.store_conf)
        assert device.olm_account.identity_keys == account.identity_keys

        # Load the account from an OlmDevice, without device_id
        device = OlmDevice(None, self.user_id, store_conf=self.store_conf)
        assert device.device_id == self.device_id

    def test_olm_sessions_persistence(self, account, curve_key, device):
        session = olm.OutboundSession(account, curve_key, curve_key)
        sessions = defaultdict(list)

        self.store.load_olm_sessions(sessions)
        assert not sessions
        assert not self.store.get_olm_sessions(curve_key)

        self.store.save_olm_session(curve_key, session)
        self.store.load_olm_sessions(sessions)
        assert sessions[curve_key][0].id == session.id

        saved_sessions = self.store.get_olm_sessions(curve_key)
        assert saved_sessions[0].id == session.id

        sessions.clear()
        saved_sessions = self.store.get_olm_sessions(curve_key, sessions)
        assert sessions[curve_key][0].id == session.id

        # Replace the session when its internal state has changed
        pickle = session.pickle()
        session.encrypt('test')
        self.store.save_olm_session(curve_key, session)
        saved_sessions = self.store.get_olm_sessions(curve_key)
        assert saved_sessions[0].pickle != pickle

        # Load sessions dynamically
        assert not device.olm_sessions
        with pytest.raises(AttributeError):
            device._olm_decrypt(None, curve_key)
        assert device.olm_sessions[curve_key][0].id == session.id

        device.olm_sessions.clear()
        device.device_keys[self.user_id][self.device_id] = device
        device.olm_ensure_sessions({self.user_id: [self.device_id]})
        assert device.olm_sessions[curve_key][0].id == session.id

        # Test cascade deletion
        self.store.remove_olm_account()
        assert not self.store.get_olm_sessions(curve_key)

    def test_megolm_inbound_persistence(self, curve_key, ed_key, device):
        out_session = olm.OutboundGroupSession()
        session = MegolmInboundSession(out_session.session_key, ed_key)
        session.forwarding_chain.append(curve_key)
        sessions = defaultdict(lambda: defaultdict(dict))

        self.store.load_inbound_sessions(sessions)
        assert not sessions
        assert not self.store.get_inbound_session(self.room_id, curve_key, session.id)

        self.store.save_inbound_session(self.room_id, curve_key, session)
        self.store.load_inbound_sessions(sessions)
        assert sessions[self.room_id][curve_key][session.id].id == session.id

        saved_session = self.store.get_inbound_session(self.room_id, curve_key,
                                                       session.id)
        assert saved_session.id == session.id
        assert saved_session.forwarding_chain == [curve_key]

        sessions = {}
        saved_session = self.store.get_inbound_session(self.room_id, curve_key,
                                                       session.id, sessions)
        assert sessions[session.id].id == session.id

        assert not device.megolm_inbound_sessions
        created = device.megolm_add_inbound_session(
            self.room_id, curve_key, ed_key, session.id, out_session.session_key)
        assert not created
        assert device.megolm_inbound_sessions[self.room_id][curve_key][session.id].id == \
            session.id

        device.megolm_inbound_sessions.clear()
        content = {
            'sender_key': curve_key,
            'session_id': session.id,
            'algorithm': device._megolm_algorithm,
            'device_id': ''
        }
        event = {
            'sender': '',
            'room_id': self.room_id,
            'content': content
        }
        with pytest.raises(KeyError):
            device.megolm_decrypt_event(event)
        assert device.megolm_inbound_sessions[self.room_id][curve_key][session.id].id == \
            session.id

        self.store.remove_olm_account()
        assert not self.store.get_inbound_session(self.room_id, curve_key, session.id)

    @pytest.mark.usefixtures('account')
    def test_megolm_outbound_persistence(self, device):
        session = MegolmOutboundSession(max_messages=2, max_age=100000)
        session.message_count = 1
        session.add_device(self.device_id)
        sessions = {}

        self.store.load_outbound_sessions(sessions)
        assert not sessions
        assert not self.store.get_outbound_session(self.room_id)

        self.store.save_outbound_session(self.room_id, session)
        self.store.save_megolm_outbound_devices(self.room_id, {self.device_id})
        self.store.load_outbound_sessions(sessions)
        assert sessions[self.room_id].id == session.id
        assert sessions[self.room_id].devices == session.devices
        assert sessions[self.room_id].creation_time == session.creation_time
        assert sessions[self.room_id].max_messages == session.max_messages
        assert sessions[self.room_id].message_count == session.message_count
        assert sessions[self.room_id].max_age == session.max_age

        saved_session = self.store.get_outbound_session(self.room_id)
        assert saved_session.id == session.id
        assert saved_session.devices == session.devices
        assert saved_session.creation_time == session.creation_time
        assert saved_session.max_messages == session.max_messages
        assert saved_session.message_count == session.message_count
        assert saved_session.max_age == session.max_age

        sessions.clear()
        saved_session = self.store.get_outbound_session(self.room_id, sessions)
        assert sessions[self.room_id].id == session.id

        self.store.remove_outbound_session(self.room_id)
        assert not self.store.get_outbound_session(self.room_id)

        self.store.save_outbound_session(self.room_id, session)
        saved_session = self.store.get_outbound_session(self.room_id)
        # Verify the saved devices have been erased with the session
        assert not saved_session.devices

        room = Room(None, self.room_id)
        with pytest.raises(AttributeError):
            device.megolm_build_encrypted_event(room, {})
        assert device.megolm_outbound_sessions[self.room_id].id == session.id

        self.store.remove_olm_account()
        assert not self.store.get_outbound_session(self.room_id)

    @pytest.mark.usefixtures('account')
    def test_device_keys_persistence(self, device):
        user_devices = {self.user_id: [self.device_id]}
        device_keys = defaultdict(dict)
        device._verified = True

        self.store.load_device_keys(None, device_keys)
        assert not device_keys
        assert not self.store.get_device_keys(None, user_devices, device_keys)
        assert not device_keys

        device_keys_to_save = {self.user_id: {self.device_id: device}}
        self.store.save_device_keys(device_keys_to_save)
        self.store.load_device_keys(None, device_keys)
        assert device_keys[self.user_id][self.device_id].curve25519 == \
            device.curve25519
        assert device_keys[self.user_id][self.device_id].verified

        device_keys.clear()
        devices = self.store.get_device_keys(None, user_devices)[self.user_id]
        assert devices[self.device_id].curve25519 == device.curve25519
        assert self.store.get_device_keys(None, user_devices, device_keys)
        assert device_keys[self.user_id][self.device_id].curve25519 == \
            device.curve25519
        assert device_keys[self.user_id][self.device_id].verified

        # Test device verification persistence
        device.verified = False
        device.ignored = True
        devices = self.store.get_device_keys(None, user_devices)[self.user_id]
        assert not devices[self.device_id].verified
        assert devices[self.device_id].ignored

        # Test [] wildcard
        devices = self.store.get_device_keys(None, {self.user_id: []})[self.user_id]
        assert devices[self.device_id].curve25519 == device.curve25519

        device.device_list.tracked_user_ids = {self.user_id}
        device.device_list.get_room_device_keys(self.room)
        assert device_keys[self.user_id][self.device_id].curve25519 == \
            device.curve25519

        # Test multiples []
        device_keys.clear()
        user_id = 'test'
        device_id = 'test'
        device_keys_to_save[user_id] = {device_id: device}
        self.store.save_device_keys(device_keys_to_save)
        user_devices[user_id] = []
        user_devices[self.user_id] = []
        device_keys = self.store.get_device_keys(None, user_devices)
        assert device_keys[self.user_id][self.device_id].curve25519 == device.curve25519
        assert device_keys[user_id][device_id].curve25519 == device.curve25519

        # Try to verify a device that has no keys
        device._ed25519 = None
        with pytest.raises(ValueError):
            device.verified = False

        self.store.remove_olm_account()
        assert not self.store.get_device_keys(None, user_devices)

    @pytest.mark.usefixtures('account')
    def test_tracked_users_persistence(self):
        tracked_user_ids = set()
        tracked_user_ids_to_save = {self.user_id}

        self.store.load_tracked_users(tracked_user_ids)
        assert not tracked_user_ids

        self.store.save_tracked_users(tracked_user_ids_to_save)
        self.store.load_tracked_users(tracked_user_ids)
        assert tracked_user_ids == tracked_user_ids_to_save

        self.store.remove_tracked_users({self.user_id})
        tracked_user_ids.clear()
        self.store.load_tracked_users(tracked_user_ids)
        assert not tracked_user_ids

    @pytest.mark.usefixtures('account')
    def test_sync_token_persistence(self):
        sync_token = 'test'

        assert not self.store.get_sync_token()

        self.store.save_sync_token(sync_token)
        assert self.store.get_sync_token() == sync_token

        sync_token = 'new'
        self.store.save_sync_token(sync_token)
        assert self.store.get_sync_token() == sync_token

    @pytest.mark.usefixtures('account')
    def test_key_requests(self):
        session_id = 'test'
        session_ids = set()

        self.store.load_outgoing_key_requests(session_ids)
        assert not session_ids

        self.store.add_outgoing_key_request(session_id)
        self.store.load_outgoing_key_requests(session_ids)
        assert session_id in session_ids

        session_ids.clear()
        self.store.remove_outgoing_key_request(session_id)
        self.store.load_outgoing_key_requests(session_ids)
        assert not session_ids

    def test_load_all(self, account, curve_key, ed_key, device):
        curve_key = account.identity_keys['curve25519']
        session = olm.OutboundSession(account, curve_key, curve_key)
        out_session = MegolmOutboundSession()
        out_session.add_device(self.device_id)
        in_session = MegolmInboundSession(out_session.session_key, ed_key)
        device_keys_to_save = {self.user_id: {self.device_id: device}}

        self.store.save_inbound_session(self.room_id, curve_key, in_session)
        self.store.save_olm_session(curve_key, session)
        self.store.save_outbound_session(self.room_id, out_session)
        self.store.save_megolm_outbound_devices(self.room_id, {self.device_id})
        self.store.save_device_keys(device_keys_to_save)

        device = OlmDevice(
            None, self.user_id, self.device_id, store_conf=self.store_conf, load_all=True)

        assert session.id in {s.id for s in device.olm_sessions[curve_key]}
        saved_in_session = \
            device.megolm_inbound_sessions[self.room_id][curve_key][in_session.id]
        assert saved_in_session.id == in_session.id
        saved_out_session = device.megolm_outbound_sessions[self.room_id]
        assert saved_out_session.id == out_session.id
        assert saved_out_session.devices == out_session.devices
        assert device.device_keys[self.user_id][self.device_id].curve25519 == \
            device.curve25519
