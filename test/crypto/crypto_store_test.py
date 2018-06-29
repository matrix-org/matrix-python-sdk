import pytest
olm = pytest.importorskip("olm")  # noqa

import os
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
