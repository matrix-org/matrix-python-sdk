import pytest
olm = pytest.importorskip("olm")  # noqa

import os
from collections import defaultdict
from tempfile import mkdtemp

from matrix_client.crypto.crypto_store import CryptoStore
from matrix_client.crypto.olm_device import OlmDevice


class TestCryptoStore(object):

    # Initialise a store and test some init code
    device_id = 'AUIETSRN'
    user_id = '@user:matrix.org'
    db_name = 'test.db'
    db_path = mkdtemp()
    store_conf = {
        'db_name': db_name,
        'db_path': db_path
    }
    store = CryptoStore(device_id, db_path=db_path, db_name=db_name)
    db_filepath = os.path.join(db_path, db_name)
    assert os.path.exists(db_filepath)
    store.close()
    store = CryptoStore(device_id, db_path=db_path, db_name='test.db')

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

    def test_olm_account_persistence(self):
        account = olm.Account()
        identity_keys = account.identity_keys
        self.store.remove_olm_account()

        # Try to load inexisting account
        saved_account = self.store.get_olm_account()
        assert saved_account is None

        # Save and load
        self.store.save_olm_account(account)
        saved_account = self.store.get_olm_account()
        assert saved_account.identity_keys == identity_keys

        # Load the account from an OlmDevice
        device = OlmDevice(None, self.user_id, self.device_id, store_conf=self.store_conf)
        assert device.olm_account.identity_keys == account.identity_keys

    def test_olm_sessions_persistence(self, account):
        curve_key = account.identity_keys['curve25519']
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

        # Load all sessions at once
        device = OlmDevice(
            None, self.user_id, self.device_id, store_conf=self.store_conf, load_all=True)
        assert device.olm_sessions[curve_key][0].id == session.id

        # Load sessions dynamically
        device = OlmDevice(None, self.user_id, self.device_id, store_conf=self.store_conf)
        assert not device.olm_sessions
        with pytest.raises(AttributeError):
            device._olm_decrypt(None, curve_key)
        assert device.olm_sessions[curve_key][0].id == session.id

        device.olm_sessions.clear()
        device.device_keys[self.user_id][self.device_id] = {'curve25519': curve_key}
        device.olm_ensure_sessions({self.user_id: [self.device_id]})
        assert device.olm_sessions[curve_key][0].id == session.id

        # Test cascade deletion
        self.store.remove_olm_account()
        assert not self.store.get_olm_sessions(curve_key)
