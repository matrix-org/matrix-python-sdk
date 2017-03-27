import json
import os
import urllib
import appdirs
import pickle

import olm

from .client import MatrixClient

SUPPORTED_ALGORITHMS = ["m.olm.curve25519-aes-sha256"]
DEFAULT_PICKLE_KEY = "DEFAULT_PICKLE_KEY"
OLM_ALGORITHM = "m.olm.v1.curve25519-aes-sha2"

class OlmAccount(olm.Account):
    def __init__(self, pickle_key=DEFAULT_PICKLE_KEY):
        super(OlmAccount, self).__init__()
        self._pickle_key = pickle_key.encode('utf-8')

    def __setstate__(self, state):
        account_buff = state.pop('account_buff')
        # pickle does not call __init__ but we need the underlying Olm.Session
        # to create a new buffer.
        self.__init__()
        self.unpickle(self._pickle_key, account_buff)

    def __getstate__(self):
        # interesting thing is the pickle is very large compared to the c-types buff
        # size, example: len(account.buff) ==
        return {'account_buff': self.pickle(self._pickle_key)}

class OlmSession(olm.Session):
    def __init__(self, user_id, device_info, pickle_key=DEFAULT_PICKLE_KEY):
        super(OlmSession, self).__init__()
        self.to_user_id = user_id
        self.to_device_id = device_info['device_id']
        self.to_device_info = device_info
        self.to_device_keys = {name.split(':')[0]:key for name, key in device_info['keys'].items()}
        self._pickle_key = pickle_key.encode('utf-8')

    @property
    def to_ed25519_key(self):
        return self.to_device_keys['ed25519']

    @property
    def to_curve25519_key(self):
        return self.to_device_keys['curve25519']

    def __setstate__(self, state):
        session_buff = state.pop('session_buff')
        # pickle does not call __init__ but we need the underlying Olm.Session
        # to create a new buffer.
        self.__init__(state['to_user_id'], state['to_device_info'])
        self.unpickle(self._pickle_key, session_buff)

    def __getstate__(self):
        state = self.__dict__
        state['session_buff'] = self.pickle(self._pickle_key)
        del state['buf']
        del state['ptr']
        del state['_pickle_key']
        return state

class OlmDevice(object):
    def __init__(self, api, user_id, device_id, pickle_key=DEFAULT_PICKLE_KEY, olm_account=None):
        self.api = api
        self._user_id = user_id
        self._device_id = device_id
        self._pickle_key = pickle_key.encode('utf-8')
        self.sessions = {}
        self.device_keys = {}
        if not olm_account:
            self.olm_account = OlmAccount()
            self.olm_account.create()

    @property
    def user_id(self):
        return self._user_id

    @property
    def device_id(self):
        return self._device_id

    # def __setstate__(self, state):
    #     session_buff = state.pop('session_buff')
    #     # pickle does not call __init__ but we need the underlying Olm.Session
    #     # to create a new buffer.
    #     self.__init__(state['to_user_id'], state['to_device_info'])

    def __getstate__(self):
        state = self.__dict__
        return { key: state[key] for key in ['_user_id', '_device_id', 'sessions', 'device_keys', 'olm_account'] }

    @classmethod
    def load_or_create_olm_device(cls, api, user_id, device_id):
        device_file_path = cls.get_device_file_path(device_id)
        if os.path.exists(device_file_path):
            with open(device_file_path, 'rb') as rfile:
                olm_device = pickle.load(rfile)
                olm_device.api = api
                return olm_device
        else:
            olm_device = OlmDevice(api, user_id, device_id)
            # olm_device.persist_olm_device()
            return olm_device

    def persist_olm_device(self):
        with open(self.get_device_file_path(self.device_id), 'wb') as wfile:
            pickle.dump(self, wfile)

    # Deprecate me
    # def load_or_create_olm_account(self):
    #     self.olm_account = OlmAccount()
    #     device_file_path = self.get_device_file_path(self.device_id)
    #     if os.path.exists(device_file_path):
    #         with open(device_file_path, 'rb') as rfile:
    #             olm_device_info = pickle.load(rfile)
    #             self.olm_account.unpickle(
    #                 self._pickle_key, olm_device_info['olm_account']
    #             )
    #     else:
    #         self.olm_account.create()
    #         self.persist_account()

    # # TODO persist sessions
    # def persist_account(self, persist_sessions=True):
    #     olm_account_buff = self.olm_account.pickle(self._pickle_key)
    #     with open(self.get_device_file_path(), 'wb') as wfile:
    #         pickle.dump({
    #                 'olm_account': olm_account_buff
    #             }, wfile)

    @staticmethod
    def get_device_file_path(device_id):
        user_data_dir = appdirs.user_data_dir(
            appname='matrix-python-sdk', roaming=True)
        try:
            os.makedirs(user_data_dir)
        except FileExistsError:
            pass # Because python doesn't have make -p
        return os.path.join(user_data_dir, "%s.pickle" % device_id)

    def new_outbound_session(self, user_id, device_info, identity_key, one_time_key):
        olm_session = OlmSession(user_id, device_info)
        olm_session.create_outbound(self.olm_account,
            identity_key.encode('utf-8'),
            one_time_key.encode('utf-8'))
        return olm_session

    def new_inbound_session(self, one_time_key_message):
        olm_session = olm.Session()
        olm_session.create_inbound(self.olm_account, one_time_key_message)
        return olm_session

    def fetch_user_device_keys(self, user_id):
        user_device_keys = self.device_keys.get(user_id, None)
        if not user_device_keys:
            user_device_keys = self.api.query_user_keys(user_id)['device_keys'][user_id]
        self.device_keys[user_id] = user_device_keys
        return user_device_keys

    def create_outbound_sessions_to_user(self, user_id, device_ids=[], start_new=False):
        if user_id not in self.sessions:
            self.sessions[user_id] = {}

        user_device_keys = self.fetch_user_device_keys(user_id)
        device_keys_to_engage = {
            device_id: device_info['keys']['curve25519:%s' % device_id] for device_id, device_info in user_device_keys.items()
                if not device_ids or device_id in device_ids
        }
        # IF no curve25519 available try
        # signed_curve25519
        def gen_key_request(user_id, device_ids, format='curve25519'):
            return {
                user_id: { device_id: format for device_id in device_ids }
            }
        key_request = gen_key_request(user_id, device_keys_to_engage.keys())
        one_time_keys = self.api.claim_keys(key_request)['one_time_keys']
        # Try to claim the signed keys if no unsigned ones are found
        if user_id not in one_time_keys:
            key_request = gen_key_request(user_id, device_keys_to_engage.keys(), format='signed_curve25519')
            one_time_keys = self.api.claim_keys(key_request)['one_time_keys']
        if user_id not in one_time_keys:
            raise Exception("Failed to obtain one_time_keys for user %s" %user_id)
        one_time_keys = one_time_keys[user_id]
        for device_id, info in one_time_keys.items():
            identity_key = device_keys_to_engage[device_id]
            # process signed_curve as well
            # This should be better specd
            if isinstance(info, dict):
                one_time_key = info[[key for key in info.keys() if key.startswith('signed_curve25519')][0]]['key']
            else:
                one_time_key = info
            if not device_id in self.sessions[user_id]:
                self.sessions[user_id][device_id] = {}
            if not 'outbound' in self.sessions[user_id][device_id]:
                self.sessions[user_id][device_id]['outbound'] = {}
            outbound_sessions = self.sessions[user_id][device_id]['outbound']
            # TODO identity_key and device_id might not always be consistent
            if not outbound_sessions or start_new:
                device_info = user_device_keys[device_id]
                outbound_session = self.new_outbound_session(user_id, device_info, identity_key, one_time_key)
                outbound_sessions[outbound_session.session_id().decode('utf-8')] = outbound_session
        return self.sessions[user_id]

    def encrypt_for_device(self, user_id, device_id, content):
        outbound_session = self.sessions[user_id][device_id]['outbound']
        encrypted_content = outbound_session.encrypt(content.encode('utf-8'))
        return (
            outbound_session.session_id().decode('utf-8'),
            encrypted_content.decode('utf-8')
        )

    @staticmethod
    def prepare_message_body(user_id, room_id, session, plaintext):
        return json.dumps({
            'content': {
                'msgtype': "m.text",
                'body': plaintext
            },
            'type': 'm.room.message',
            'recipient': session.to_user_id,
            'recipient_keys': {
                'ed25519': session.to_ed25519_key
            },
            'sender': user_id,
            'room_id': room_id
        }).encode('utf-8')

    def send_encrypted_message_to_session(self, room_id, session, plaintext):
        message_body = self.prepare_message_body(self.user_id, room_id, session, plaintext)
        encrypted_msg_type, encrypted_msg = session.encrypt(message_body)
        sender_key = self.olm_account.identity_keys()['curve25519']
        # It should be possible to send to multiple sessions in one event
        # otherwise session.to_identity_key wouldn't serve as much purpose..
        # But currently that's not possible? Since outbound session_id is specified
        # once at the top level
        ciphertext_body = {
            session.to_curve25519_key: {
                'body': encrypted_msg.decode('utf-8'),
                'type': encrypted_msg_type
            }
        }
        return self.api.send_message_event(room_id, 'm.room.encrypted', {
            'algorithm': OLM_ALGORITHM,
            'ciphertext': ciphertext_body,
            'device_id': self.device_id,
            'sender_key': sender_key,
            'session_id': session.session_id().decode('utf-8')
        })

    def send_encrypted_message_to_user(self, room_id, user_id, plaintext):
        user_sessions = self.create_outbound_sessions_to_user(user_id)
        for device_id, sessions in user_sessions.items():
            # Mimic riot code for now
            # what's the significance of // Use the session with the lowest ID. sessionIds.sort(); return sessionIds[0];
            # is there something special about lower_id sessions  ? wouldn't that be better handled by last ratchet timestamp or something
            outbound_session = sorted(sessions['outbound'].items(), key= lambda k,v: k)[0][1]
            # Should be possible to send only one event with multiple ciphertexts per
            # each session but doesn't seem to be spec'd? See above comments.
            self.send_encrypted_message_to_session(room_id, session, plaintext)


    def upload_device_keys(self):
        identity_keys = self.olm_account.identity_keys
        device_id = self.device_id
        device_keys = {
            "algorithms": SUPPORTED_ALGORITHMS,
            "device_id": device_id,
            "keys": identity_keys(),
            "user_id": self.user_id,
        }
        sig = self.olm_account.sign(json.dumps(device_keys).encode('utf-8')).decode('utf-8')
        device_keys['signatures'] = {}
        device_keys['signatures'][self.user_id] = {}
        device_keys['signatures'][self.user_id]["ed25519:%s" % device_id] = sig
        content = {
            'device_keys': device_keys
        }
        ret = self.api.upload_keys(content)
        self._one_time_key_counts = ret['one_time_key_counts']
        return ret

    # TODO Support upload of signed keys
    def upload_device_one_time_keys(self):
        # One-time public keys for "pre-key" messages. The names of the properties should be in the format <algorithm>:<key_id>. The format of the key is determined by the key algorithm.
        max_one_time_keys = self.olm_account.max_number_of_one_time_keys()
        key_limit = max_one_time_keys // 2
        key_count = self._one_time_key_counts.get('curve25519', 0)
        num_keys = max(key_limit - key_count, 0)
        self.olm_account.generate_one_time_keys(num_keys)
        one_time_keys = self.olm_account.one_time_keys()
        one_time_keys = {'curve25519:' + key_id: key for key_id, key
            in one_time_keys['curve25519'].items()}
        content = {
            'one_time_keys': one_time_keys
        }
        ret = self.api.upload_keys(content, device_id=self.device_id)
        self._one_time_key_counts = ret['one_time_key_counts']
        self.olm_account.mark_keys_as_published()
        return ret
