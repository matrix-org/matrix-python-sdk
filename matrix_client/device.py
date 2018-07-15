from .errors import MatrixRequestError


class Device(object):

    def __init__(self,
                 api,
                 device_id,
                 display_name=None,
                 last_seen_ip=None,
                 last_seen_ts=None,
                 verified=False,
                 blacklisted=False,
                 ignored=False,
                 ed25519_key=None,
                 curve25519_key=None):
        self.api = api
        self.device_id = device_id
        self.display_name = display_name
        self.last_seen_ts = last_seen_ts
        self.last_seen_ip = last_seen_ip
        self.verified = verified
        self.blacklisted = blacklisted
        self.ignored = ignored
        self._ed25519 = ed25519_key
        self._curve25519 = curve25519_key

    def get_info(self):
        """Gets information on the device.

        The ``display_name``, ``last_seen_ip`` and ``last_seen_ts`` attribute will
        get updated, if these were available.

        Returns:
            True if successful, False if the device was not found.
        """
        try:
            info = self.api.get_device(self.device_id)
        except MatrixRequestError as e:
            if e.code == 404:
                return False
            raise
        self.display_name = info.get('display_name')
        self.last_seen_ip = info.get('last_seen_ip')
        self.last_seen_ts = info.get('last_seen_ts')
        return True

    @property
    def ed25519(self):
        return self._ed25519

    @property
    def curve25519(self):
        return self._curve25519
