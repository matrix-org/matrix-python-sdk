"""Tests can import OlmDevice from here, and know it won't try to use a database."""

from matrix_client.crypto.crypto_store import CryptoStore
from matrix_client.crypto.olm_device import OlmDevice as BaseOlmDevice


class DummyStore(CryptoStore):
    def __init__(*args, **kw): pass

    def nop(*args, **kw): pass

    def __getattribute__(self, name):
        if name in dir(CryptoStore):
            return object.__getattribute__(self, 'nop')
        raise AttributeError


class OlmDevice(BaseOlmDevice):

    def __init__(self, *args, **kw):
        super(OlmDevice, self).__init__(*args, Store=DummyStore, **kw)
