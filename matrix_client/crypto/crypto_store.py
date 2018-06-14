import logging
import os
import sqlite3
from datetime import timedelta

import olm
from appdirs import user_data_dir

from matrix_client.crypto.megolm_outbound_session import MegolmOutboundSession

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
        self.conn = sqlite3.connect(os.path.join(data_dir, db_name),
                                    detect_types=sqlite3.PARSE_DECLTYPES)
        self.pickle_key = pickle_key
        self.create_tables_if_needed()

    def create_tables_if_needed(self):
        """Ensures all the tables exist."""
        c = self.conn.cursor()
        c.execute('PRAGMA foreign_keys = ON')
        c.execute('CREATE TABLE IF NOT EXISTS accounts (device_id TEXT PRIMARY KEY,'
                  'account BLOB)')
        c.execute('CREATE TABLE IF NOT EXISTS olm_sessions (device_id TEXT,'
                  'session_id TEXT PRIMARY KEY, curve_key TEXT, session BLOB,'
                  'FOREIGN KEY(device_id) REFERENCES accounts(device_id) '
                  'ON DELETE CASCADE)')
        c.execute('CREATE TABLE IF NOT EXISTS megolm_inbound_sessions '
                  '(device_id TEXT, session_id TEXT PRIMARY KEY, room_id TEXT,'
                  'curve_key TEXT, session BLOB,'
                  'FOREIGN KEY(device_id) REFERENCES accounts(device_id) '
                  'ON DELETE CASCADE)')
        c.execute('CREATE TABLE IF NOT EXISTS megolm_outbound_sessions '
                  '(device_id TEXT, room_id TEXT PRIMARY KEY, session BLOB,'
                  'max_age_s FLOAT, max_messages INTEGER, creation_time TIMESTAMP,'
                  'message_count INTEGER,'
                  'FOREIGN KEY(device_id) REFERENCES accounts(device_id) '
                  'ON DELETE CASCADE)')
        c.execute('CREATE TABLE IF NOT EXISTS megolm_outbound_devices '
                  '(device_id TEXT, room_id TEXT, user_device_id TEXT,'
                  'UNIQUE(device_id, room_id, user_device_id),'
                  'FOREIGN KEY(room_id) REFERENCES megolm_outbound_sessions(room_id) '
                  'ON DELETE CASCADE,'
                  'FOREIGN KEY(device_id) REFERENCES accounts(device_id))')
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

    def save_olm_session(self, curve_key, session):
        self.save_olm_sessions({curve_key: [session]})

    def save_olm_sessions(self, sessions):
        """Saves Olm sessions.

        Args:
            sessions (defaultdict(list)): A map from curve25519 keys to a list of
                olm.Session objects.
        """
        c = self.conn.cursor()
        rows = [(self.device_id, s.id, key, s.pickle(self.pickle_key))
                for key in sessions for s in sessions[key]]
        c.executemany('REPLACE INTO olm_sessions VALUES (?,?,?,?)', rows)
        c.close()
        self.conn.commit()

    def load_olm_sessions(self, sessions):
        """Loads all saved Olm sessions.

        Args:
            sessions (defaultdict(list)): A map from curve25519 keys to a list of
                olm.Session objects, which will be populated.
        """
        c = self.conn.cursor()
        rows = c.execute('SELECT curve_key, session FROM olm_sessions WHERE device_id=?',
                         (self.device_id,))
        for row in rows:
            session = olm.Session.from_pickle(bytes(row[1]), self.pickle_key)
            sessions[row[0]].append(session)
        c.close()

    def get_olm_sessions(self, curve_key, sessions_dict=None):
        """Get the Olm sessions corresponding to a device.

        Args:
            curve_key (str): The curve25519 key of the device.
            sessions_dict (defaultdict(list)): Optional. A map from curve25519 keys to a
                list of olm.Session objects, to which the session list will be added.

        Returns:
            A list of olm.Session objects, or None if none were found.

        NOTE:
            When overriding this, be careful to append the retrieved sessions to the
            list of sessions already present and not to overwrite its reference.
        """
        c = self.conn.cursor()
        rows = c.execute(
            'SELECT session FROM olm_sessions WHERE device_id=? AND curve_key=?',
            (self.device_id, curve_key)
        )
        sessions = [olm.Session.from_pickle(bytes(row[0]), self.pickle_key)
                    for row in rows]
        if sessions_dict is not None:
            sessions_dict[curve_key].extend(sessions)
        c.close()
        # For consistency with other get_ methods, do not return an empty list
        return sessions or None

    def save_inbound_session(self, room_id, curve_key, session):
        """Saves a Megolm inbound session.

        Args:
            room_id (str): The room corresponding to the session.
            curve_key (str): The curve25519 key of the device.
            session (olm.InboundGroupSession): The session to save.
        """
        c = self.conn.cursor()
        c.execute('REPLACE INTO megolm_inbound_sessions VALUES (?,?,?,?,?)',
                  (self.device_id, session.id, room_id, curve_key,
                   session.pickle(self.pickle_key)))
        c.close()
        self.conn.commit()

    def load_inbound_sessions(self, sessions):
        """Loads all saved inbound Megolm sessions.

        Args:
            sessions (defaultdict(defaultdict(dict))): An object which will get
                populated with the sessions. The format is
                ``{<room_id>: {<curve25519_key>: {<session_id>:
                <olm.InboundGroupSession>}}}``.
        """
        c = self.conn.cursor()
        rows = c.execute(
            'SELECT room_id, curve_key, session FROM megolm_inbound_sessions WHERE '
            'device_id=?', (self.device_id,)
        )
        for row in rows:
            session = olm.InboundGroupSession.from_pickle(bytes(row[2]), self.pickle_key)
            sessions[row[0]][row[1]][session.id] = session
        c.close()

    def get_inbound_session(self, room_id, curve_key, session_id, sessions=None):
        """Gets a saved inbound Megolm session.

        Args:
            room_id (str): The room corresponding to the session.
            curve_key (str): The curve25519 key of the device.
            session_id (str): The id of the session.
            sessions (dict): Optional. A map from session id to olm.InboundGroupSession
                object, to which the session will be added.

        Returns:
            olm.InboundGroupSession object, or None if the session was not found.
        """
        c = self.conn.cursor()
        c.execute(
            'SELECT session FROM megolm_inbound_sessions WHERE device_id=? AND room_id=? '
            'AND curve_key=? AND session_id=?',
            (self.device_id, room_id, curve_key, session_id)
        )
        try:
            session_data = c.fetchone()[0]
            session_data = bytes(session_data)
        except TypeError:
            return None
        finally:
            c.close()
        session = olm.InboundGroupSession.from_pickle(session_data, self.pickle_key)
        if sessions is not None:
            sessions[session.id] = session
        return session

    def save_outbound_session(self, room_id, session):
        """Saves a Megolm outbound session.

        Args:
            room_id (str): The room corresponding to the session.
            session (MegolmOutboundSession): The session to save.
        """
        c = self.conn.cursor()
        pickle = session.pickle(self.pickle_key)
        c.execute(
            'INSERT OR IGNORE INTO megolm_outbound_sessions VALUES (?,?,?,?,?,?,?)',
            (self.device_id, room_id, pickle, session.max_age.total_seconds(),
             session.max_messages, session.creation_time, session.message_count)
        )
        c.execute('UPDATE megolm_outbound_sessions SET session=? WHERE device_id=? AND '
                  'room_id=?', (pickle, self.device_id, room_id))
        c.close()
        self.conn.commit()

    def load_outbound_sessions(self, sessions):
        """Loads all saved outbound Megolm sessions.

        Also loads the devices each are shared with.

        Args:
            sessions (dict): A map from room_id to a :class:`.MegolmOutboundSession`
                object, which will be populated.
        """
        c = self.conn.cursor()
        rows = c.execute(
            'SELECT room_id, session, max_age_s, max_messages, creation_time,'
            'message_count FROM megolm_outbound_sessions WHERE device_id=?',
            (self.device_id,)
        )
        for row in rows.fetchall():
            device_ids = c.execute(
                'SELECT user_device_id FROM megolm_outbound_devices WHERE device_id=? '
                'AND room_id=?', (self.device_id, row[0])
            )
            devices = {device_id[0] for device_id in device_ids}
            max_age_s = row[2]
            max_age = timedelta(seconds=max_age_s)
            session = MegolmOutboundSession.from_pickle(
                bytes(row[1]), devices, max_age, row[3], row[4], row[5], self.pickle_key)
            sessions[row[0]] = session
        c.close()

    def get_outbound_session(self, room_id, sessions=None):
        """Gets a saved outbound Megolm session.

        Also loads the devices it is shared with.

        Args:
            room_id (str): The room corresponding to the session.
            sessions (dict): Optional. A map from room_id to a
                :class:`.MegolmOutboundSession` object, to which the session will be
                added.

        Returns:
            :class:`.MegolmOutboundSession` object, or ``None`` if the session was
            not found.
        """
        c = self.conn.cursor()
        c.execute(
            'SELECT session, max_age_s, max_messages, creation_time, message_count '
            'FROM megolm_outbound_sessions WHERE device_id=? AND room_id=?',
            (self.device_id, room_id)
        )
        try:
            row = c.fetchone()
            session_data = bytes(row[0])
        except TypeError:
            c.close()
            return None
        device_ids = c.execute(
            'SELECT user_device_id FROM megolm_outbound_devices WHERE device_id=? '
            'AND room_id=?', (self.device_id, room_id)
        )
        devices = {device_id[0] for device_id in device_ids}
        c.close()
        max_age_s = row[1]
        max_age = timedelta(seconds=max_age_s)
        session = MegolmOutboundSession.from_pickle(
            session_data, devices, max_age, row[2], row[3], row[4], self.pickle_key)
        if sessions is not None:
            sessions[room_id] = session
        return session

    def remove_outbound_session(self, room_id):
        """Removes a saved outbound Megolm session.

        Args:
            room_id (str): The room corresponding to the session.
        """
        c = self.conn.cursor()
        c.execute('DELETE FROM megolm_outbound_sessions WHERE device_id=? AND room_id=?',
                  (self.device_id, room_id))
        c.close()
        self.conn.commit()

    def save_megolm_outbound_devices(self, room_id, device_ids):
        """Saves devices an outbound Megolm session is shared with.

        Args:
            room_id (str): The room corresponding to the session.
            device_ids (iterable): A list of device ids.
        """
        c = self.conn.cursor()
        rows = [(self.device_id, room_id, device_id) for device_id in device_ids]
        c.executemany(
            'INSERT OR IGNORE INTO megolm_outbound_devices VALUES (?,?,?)', rows)
        c.close()
        self.conn.commit()

    def close(self):
        self.conn.close()
