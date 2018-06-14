import logging
import os
import sqlite3

import olm
from appdirs import user_data_dir

logger = logging.getLogger(__name__)


class CryptoStore(object):
    """Manages persistent storage for an OlmDevice.

    Args:
        device_id (str): The device id of the OlmDevice.
        db_name (str): Optional. The name of the database file to use. Will be created
            if necessary.
        db_path (str): Optional. The path where to store the database file. Defaults to
            the system default application data directory.
        app_name (str): Optional. The application name, which will be used to determine
            where the database is located. Ignored if db_path is supplied.
        pickle_key (str): Optional. A key to encrypt the database contents.
    """

    def __init__(self,
                 device_id,
                 db_name='crypto.db',
                 db_path=None,
                 app_name='matrix-python-sdk',
                 pickle_key='DEFAULT_KEY'):
        self.device_id = device_id
        data_dir = db_path or user_data_dir(app_name, '')
        try:
            os.makedirs(data_dir)
        except OSError:
            pass
        self.conn = sqlite3.connect(os.path.join(data_dir, db_name))
        self.pickle_key = pickle_key
        self.create_tables_if_needed()

    def create_tables_if_needed(self):
        """Ensures all the tables exist."""
        c = self.conn.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS accounts (device_id TEXT PRIMARY KEY,'
                  'account BLOB)')
        c.close()
        self.conn.commit()

    def save_olm_account(self, account):
        """Saves an Olm account.

        Args:
            account (olm.Account): The account object to save.
        """
        account_data = account.pickle(self.pickle_key)
        c = self.conn.cursor()
        c.execute('INSERT OR IGNORE INTO accounts (device_id, account) VALUES (?,?)',
                  (self.device_id, account_data))
        c.execute('UPDATE accounts SET account=? WHERE device_id=?',
                  (account_data, self.device_id))
        c.close()
        self.conn.commit()

    def get_olm_account(self):
        """Gets the Olm account.

        Returns:
            olm.Account object, or None if it wasn't found for the current device_id.
        """
        c = self.conn.cursor()
        c.execute(
            'SELECT account FROM accounts WHERE device_id=?', (self.device_id,))
        try:
            account_data = c.fetchone()[0]
            # sqlite gives us unicode in Python2, we want bytes
            account_data = bytes(account_data)
        except TypeError:
            return None
        finally:
            c.close()
        return olm.Account.from_pickle(account_data, self.pickle_key)

    def remove_olm_account(self):
        """Removes the Olm account.

        NOTE: Doing so will remove any saved information associated with the account
        (keys, sessions...)
        """
        c = self.conn.cursor()
        c.execute('DELETE FROM accounts WHERE device_id=?', (self.device_id,))
        c.close()

    def close(self):
        self.conn.close()
