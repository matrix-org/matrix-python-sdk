import json
import os
import urllib
import appdirs
import pickle
import time
import olm

from .client import MatrixClient

SUPPORTED_ALGORITHMS = ["m.olm.curve25519-aes-sha256"]
DEFAULT_PICKLE_KEY = "DEFAULT_PICKLE_KEY"
OLM_ALGORITHM = "m.olm.v1.curve25519-aes-sha2"
# Not Supported at the moment
MEGOLM_ALGORITHM = "m.megolm.v1.aes-sha2"

class OlmAccount(olm.Account):
    def __init__(self, pickle_key=DEFAULT_PICKLE_KEY):
        super(OlmAccount, self).__init__()
        self._pickle_key = pickle_key.encode("utf-8")

    def __setstate__(self, state):
        account_buff = state.pop("account_buff")
        # pickle does not call __init__ but we need the underlying Olm.Session
        # to create a new buffer.
        self.__init__()
        self.unpickle(self._pickle_key, account_buff)

    def __getstate__(self):
        # interesting thing is the pickle is very large compared to the c-types buff
        # size, example: len(account.buff) ==
        return {"account_buff": self.pickle(self._pickle_key)}

class OlmSession(olm.Session):
    def __init__(self, user_id, device_info, pickle_key=DEFAULT_PICKLE_KEY):
        super(OlmSession, self).__init__()
        self.to_user_id = user_id
        self.to_device_id = device_info["device_id"]
        self.to_device_info = device_info
        self.to_device_keys = {name.split(":")[0]:key for name, key in device_info["keys"].items()}
        self._pickle_key = pickle_key.encode("utf-8")

    @property
    def to_ed25519_key(self):
        return self.to_device_keys["ed25519"]

    @property
    def to_curve25519_key(self):
        return self.to_device_keys["curve25519"]

    def __setstate__(self, state):
        session_buff = state.pop("session_buff")
        # pickle does not call __init__ but we need the underlying Olm.Session
        # to create a new buffer.
        self.__init__(state["to_user_id"], state["to_device_info"])
        self.unpickle(self._pickle_key, session_buff)

    def __getstate__(self):
        state= {key: val for key, val in self.__dict__.items() if key not in ["buf", "ptr", "_pickle_key"]}
        state["session_buff"] = self.pickle(self._pickle_key)
        return state

class OlmDevice(object):
    def __init__(self, api, user_id, device_id,
                 pickle_key=DEFAULT_PICKLE_KEY,
                 persistance=False,
                 olm_account=None):
        self.api = api
        self._user_id = user_id
        self._device_id = device_id
        self._pickle_key = pickle_key.encode("utf-8")
        self.sessions = {}
        self.device_keys = {}
        self.persistance = persistance
        self.olm_account = olm_account
        if not olm_account:
            self.olm_account = OlmAccount()
            self.olm_account.create()
        if self.persistance:
            self.persist_olm_device()

    def process_event(self, event):
        if event.get("type", "") != "m.room.encrypted":
            return
        content = event["content"]
        # Only OLM supported atm
        if content.get("algorithm", "") != OLM_ALGORITHM:
            return
        receiving_key = self.olm_account.identity_keys()["curve25519"]
        if not receiving_key in content["ciphertext"]:
            return
        payload = content["ciphertext"][receiving_key]
        encrypted_msg, encrypted_msg_type = payload["body"], payload["type"]
        inbound_session = None
        sender = event["sender"]
        sender_key = content["sender_key"]
        if encrypted_msg_type > 0:
            clear_data = self.decrypt_with_existing_session(
                sender,
                sender_key,
                encrypted_msg_type,
                encrypted_msg
            )
        else:
            inbound_session = self.new_inbound_session(sender, sender_key)
            inbound_session.create_inbound_from(
                self.olm_account,
                sender_key.encode("utf-8"),
                encrypted_msg.encode("utf-8")
            )
            clear_data = inbound_session.decrypt(encrypted_msg_type, encrypted_msg)
        clear_data = json.loads(clear_data.decode("utf-8"))
        assert(sender == clear_data.get("sender", ""))
        assert(event["room_id"] == clear_data.get("room_id", ""))
        assert(self.user_id == clear_data.get("recipient", ""))
        # We add the inbound session after asserting for unknown key-share attacks
        if inbound_session:
            self.add_session(
                sender,
                clear_data["sender_device"],
                inbound_session,
                "inbound"
            )
            if self.persistance:
                self.persist_olm_device()
        event["clear_data"] = clear_data
        return event


    def new_inbound_session(self, user_id, user_key):
        user_device = self.get_device_for_user_key(user_id, user_key)
        if not user_device:
            self.fetch_user_device_keys(user_id)
            user_device = self.get_device_for_user_key(user_id, user_key)
        olm_session = OlmSession(user_id, user_device)
        return olm_session

    def get_device_for_user_key(self, user_id, user_key):
        user_devices = self.device_keys.get(user_id, {})
        for device in user_devices.values():
            if device['keys']['curve25519:%s' %device['device_id']] == user_key:
                return device

    def decrypt_with_existing_session(self, user_id, user_key, msg_type, msg):
        user_device = self.get_device_for_user_key(user_id, user_key)
        if not user_device:
            self.fetch_user_device_keys(user_id)
            user_device = self.get_device_for_user_key(user_id, user_key)
        device_sessions = self.sessions.get(user_id, {}).get(user_device["device_id"], {})
        def _sessions_list(d, sessions=None):
            if sessions is None:
                sessions = []
            if isinstance(d, dict):
                _sessions_list(list(d.values())[0], sessions)
            else:
                sessions.append(d)
            return sessions
        msg_type, msg = msg_type.encode("utf-8"), msg.encode("utf-8")
        for session in _sessions_list(device_sessions):
            try:
                return session.decrypt(msg_type, msg).decode("utf-8")
            except olm.OlmError:
                pass

    @property
    def user_id(self):
        return self._user_id

    @property
    def device_id(self):
        return self._device_id

    def __getstate__(self):
        state = self.__dict__
        return { key: state[key] for key in ["_user_id", "_device_id", "sessions", "device_keys", "olm_account"] }

    @classmethod
    def load_or_create_olm_device(cls, api, user_id, device_id, persistance=False):
        device_file_path = cls.get_device_file_path(device_id)
        if os.path.exists(device_file_path):
            with open(device_file_path, "rb") as rfile:
                olm_device = pickle.load(rfile)
            olm_device.api = api
            olm_device.persistance = persistance
            return olm_device
        else:
            olm_device = OlmDevice(api, user_id, device_id, persistance=persistance)
            return olm_device

    def persist_olm_device(self):
        with open(self.get_device_file_path(self.device_id), "wb") as wfile:
            pickle.dump(self, wfile)

    @staticmethod
    def get_device_file_path(device_id):
        user_data_dir = appdirs.user_data_dir(
            appname="matrix-python-sdk", roaming=True)
        try:
            os.makedirs(user_data_dir)
        except FileExistsError:
            pass # Because python doesn"t have make -p
        return os.path.join(user_data_dir, "%s.pickle" % device_id)

    # Note refresh will prune old device info
    # But not old sessions associated with those devices
    def fetch_user_device_keys(self, user_id, refresh=False):
        user_device_keys = self.device_keys.get(user_id, None)
        if not user_device_keys or refresh:
            user_device_keys = self.api.query_user_keys(user_id)["device_keys"][user_id]
        self.device_keys[user_id] = user_device_keys
        if self.persistance:
            self.persist_olm_device()
        return user_device_keys

    def get_outbound_sessions(self, user_id, device_id):
        try:
            if "outbound" in self.sessions[user_id][device_id]:
                return self.sessions[user_id][device_id]["outbound"]
            else:
                # TODO don't cause side-effects in a get_ method
                sessions = self.sessions[user_id][device_id]["inbound"]
                self.sessions[user_id][device_id]["outbound"] = sessions
                return sessions
        except KeyError:
            return None

    def add_session(self, user_id, device_id, session, type):
        if user_id not in self.sessions:
            self.sessions[user_id] = {}
        if device_id not in self.sessions[user_id]:
            self.sessions[user_id][device_id] = {}
        session_id = session.session_id().decode("utf-8")
        if type not in self.sessions[user_id][device_id]:
            self.sessions[user_id][device_id][type] = {}
        self.sessions[user_id][device_id][type][session_id] = session
        if self.persistance:
            self.persist_olm_device()

    def new_outbound_session(self, user_id, device_info, identity_key, one_time_key):
        session = OlmSession(user_id, device_info)
        session.create_outbound(self.olm_account,
            identity_key.encode("utf-8"),
            one_time_key.encode("utf-8"))
        self.add_session(user_id, device_info['device_id'], session, 'outbound')
        return session

    @staticmethod
    def gen_key_request(user_id, device_ids, format="signed_curve25519"):
            return {
                user_id: { device_id: format for device_id in device_ids }
            }

    def ensure_outbound_sessions_for_user(self, user_id, device_ids=[], start_new=False):
        user_device_keys = self.fetch_user_device_keys(user_id)
        user_sessions = self.sessions.get(user_id, {})
        if device_ids:
            user_device_keys = { device_id: device_info for device_id, device_info in user_device_keys.items() if device_id in device_ids }

        device_keys_to_engage = {}
        for device_id, device_info in user_device_keys.items():
            # TODO fix since device_id might remain the same but signing keys could switch
            if not start_new and device_id in user_sessions:
                continue
            device_keys_to_engage[device_id] = device_info["keys"]["curve25519:%s" % device_id]
        if not device_keys_to_engage:
            return self.sessions[user_id]

        key_request = self.gen_key_request(user_id, device_keys_to_engage.keys())
        one_time_keys = self.api.claim_keys(key_request)["one_time_keys"]
        if user_id not in one_time_keys:
            raise Exception("Failed to obtain one_time_keys for user %s" %user_id)
        one_time_keys = one_time_keys[user_id]
        for device_id, info in one_time_keys.items():
            identity_key = device_keys_to_engage[device_id]
            # process signed_curve as well
            # This should be better specd
            if isinstance(info, dict):
                one_time_key = info[[key for key in info.keys() if key.startswith("signed_curve25519")][0]]["key"]
            else:
                one_time_key = info
                self.new_outbound_session(
                    user_id,
                    user_device_keys[device_id],
                    identity_key,
                    one_time_key
                )
        return self.sessions[user_id]

    def encrypt_for_device(self, user_id, device_id, content):
        outbound_session = self.sessions[user_id][device_id]["outbound"]
        encrypted_content = outbound_session.encrypt(content.encode("utf-8"))
        return (
            outbound_session.session_id().decode("utf-8"),
            encrypted_content.decode("utf-8")
        )

    @staticmethod
    def prepare_message_body(user_id, room_id, session, plaintext):
        return json.dumps({
            "content": {
                "msgtype": "m.text",
                "body": plaintext
            },
            "type": "m.room.message",
            "recipient": session.to_user_id,
            "recipient_keys": {
                "ed25519": session.to_ed25519_key
            },
            "sender": user_id,
            "room_id": room_id
        }).encode("utf-8")

    def send_encrypted_message_to_session(self, room_id, session, plaintext):
        return self._send_encrypted_message_to_sessions(self, room_id, [session], plaintext)

    def _send_encrypted_message_to_sessions(self, room_id, sessions, plaintext):
        sender_key = self.olm_account.identity_keys()["curve25519"]
        ciphertext_body = {}
        # Note that because each message body includes specific information
        # such as the recipient devices recipient_ed25519_key, sending the same plaintext to multiple devices requires multiple payloads
        for session in sessions:
            message_body = self.prepare_message_body(self.user_id, room_id, session, plaintext)
            encrypted_msg_type, encrypted_msg = session.encrypt(message_body)
            ciphertext_body[session.to_curve25519_key] = {
                    "body": encrypted_msg.decode("utf-8"),
                    "type": encrypted_msg_type
                }

        return self.api.send_message_event(room_id, "m.room.encrypted", {
            "algorithm": OLM_ALGORITHM,
            "ciphertext": ciphertext_body,
            "device_id": self.device_id,
            "sender_key": sender_key,
        })

    def send_encrypted_message_to_user(self, room_id, user_id, plaintext, device_ids=[]):
        user_sessions = self.ensure_outbound_sessions_for_user(user_id, device_ids)
        outbound_sessions = []
        for device_id, sessions in user_sessions.items():
            if device_ids and device_id not in device_ids:
                continue
            # Mimic riot code for now
            # what"s the significance of // Use the session with the lowest ID. sessionIds.sort(); return sessionIds[0];
            # is there something special about lower_id sessions  ? wouldn"t that be better handled by last ratchet timestamp or something
            outbound_session = sorted(sessions["outbound"].items(), key= lambda x: [0])[0][1]
            outbound_sessions.append(outbound_session)
        return self._send_encrypted_message_to_sessions(room_id, outbound_sessions, plaintext)

    def prepare_signed_device_keys(self):
        identity_keys = self.olm_account.identity_keys()
        # Identity keys need to be mapped with the ":" reference syntax
        identity_keys = {"%s:%s" %(key, self.device_id): val for key, val in identity_keys.items() }
        device_keys = {
            "algorithms": SUPPORTED_ALGORITHMS,
            "device_id": self.device_id,
            "keys": identity_keys,
            "user_id": self.user_id
        }
        # Note we must adhere to the same no white-space JSON format for signing as the JS-SDK
        # uses for verification.
        # TODO: Update this in the docs somewhere.
        sig = self.olm_account.sign(json.dumps(device_keys, separators=(",", ":")).encode("utf-8")).decode("utf-8")
        return device_keys, sig

    def upload_device_keys(self):
        device_keys, sig = self.prepare_signed_device_keys()
        device_keys["signatures"] = {}
        device_keys["signatures"][self.user_id] = {}
        device_keys["signatures"][self.user_id]["ed25519:%s" % self.device_id] = sig
        content = {
            "device_keys": device_keys
        }
        ret = self.api.upload_keys(content)
        self._one_time_key_counts = ret["one_time_key_counts"]
        return ret

    def upload_device_one_time_keys(self, signed=True):
        # One-time public keys for "pre-key" messages. The names of the properties should be in the format <algorithm>:<key_id>. The format of the key is determined by the key algorithm.
        max_one_time_keys = self.olm_account.max_number_of_one_time_keys()
        key_limit = max_one_time_keys // 2
        if signed:
            key_count = self._one_time_key_counts.get("signed_curve25519", 0)
        else:
            key_count = self._one_time_key_counts.get("curve25519", 0)
        num_keys = max(key_limit - key_count, 0)
        self.olm_account.generate_one_time_keys(num_keys)
        one_time_keys = self.olm_account.one_time_keys()
        # Signature should be over the non-white-spaced JSON of {"key":<key>}
        # Upload format is
        # {
        #     "one_time_keys": {
        #         "signed_curve25519:<key_id>": {
        #             "key": <key>,
        #             "signatures": {
        #                 <user_id>: {
        #                     "ed25519:<device_id>": <signature>
        #                 }
        #             }
        #         }
        #     }
        # }
        if signed:
            signed_one_time_keys = {}
            for key_id, key in one_time_keys["curve25519"].items():
                key_body = { "key": key }
                key_body_raw = json.dumps(key_body, separators=(",", ":")).encode("utf-8")
                signature = self.olm_account.sign(key_body_raw).decode("utf-8")
                signature_body = {
                    self.user_id: {
                        "ed25519:%s" %self.device_id: signature
                    }
                }
                key_body["signatures"] = signature_body
                signed_one_time_keys["signed_curve25519:%s" % key_id] = key_body
            one_time_keys = signed_one_time_keys
        else:
            one_time_keys = {"curve25519:%s" % key_id: key for key_id, key
                in one_time_keys["curve25519"].items()}
        content = {
            "one_time_keys": one_time_keys
        }
        ret = self.api.upload_keys(content, device_id=self.device_id)
        self._one_time_key_counts = ret["one_time_key_counts"]
        self.olm_account.mark_keys_as_published()
        return ret

if __name__ == "__main__":
    from olm import utility
    olm_device = OlmDevice(None, "@test:test", "TEST_DEVICE")
    device_keys, sig = olm_device.prepare_signed_device_keys()
    pub_key = olm_device.olm_account.identity_keys()["ed25519"]
    assert(utility.ed25519_verify(pub_key.encode("utf-8"),
                                  json.dumps(device_keys, separators=(",", ":")).encode("utf-8"),
                                  sig.encode("utf-8")))
