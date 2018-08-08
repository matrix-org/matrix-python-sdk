import pytest
olm = pytest.importorskip("olm")  # noqa

import os
from tempfile import mkstemp

from unpaddedbase64 import decode_base64, encode_base64

from matrix_client.crypto.key_export import (encrypt, encrypt_and_save, decrypt,
                                             decrypt_and_read)
from matrix_client.crypto.sessions import MegolmInboundSession
from test.crypto.dummy_olm_device import OlmDevice


def test_encrypt_decrypt():
    plaintext = b'test'
    passphrase = 'pass'
    # Set a ridiculously low round count for this test to be fast
    ciphertext = encrypt(plaintext, passphrase, count=1)

    assert decrypt(ciphertext, passphrase) == plaintext

    ciphertext_bytes = decode_base64(ciphertext)

    # Wrong hmac
    ciphertext = encode_base64(ciphertext_bytes[:-32] + b'A' * 32)
    with pytest.raises(ValueError):
        decrypt(ciphertext, passphrase)

    # Wrong version
    ciphertext = encode_base64(bytes([42]) + ciphertext_bytes[1:])
    with pytest.raises(ValueError):
        decrypt(ciphertext, passphrase)


def test_encrypt_decrypt_and_save():
    plaintext = b'test'
    passphrase = 'pass'
    try:
        filename = mkstemp()[1]
        encrypt_and_save(plaintext, filename, passphrase, count=1)
        assert decrypt_and_read(filename, passphrase) == plaintext

        # Bad header
        with open(filename, 'w') as f:
            f.write('wrong')
        with pytest.raises(ValueError):
            decrypt_and_read(filename, passphrase)
    finally:
        os.remove(filename)


def test_import_export():
    passphrase = 'pass'
    device = OlmDevice(None, '@test:localhost', 'AUIETSRN')
    out = olm.OutboundGroupSession()
    session = MegolmInboundSession(out.session_key, 'signing_key')
    device.megolm_inbound_sessions['room']['sender_key'][session.id] = session

    try:
        filename = mkstemp()[1]
        device.export_keys(filename, passphrase, count=1)
        other_device = OlmDevice(None, '@test:localhost', 'AUIETSRN')
        other_device.import_keys(filename, passphrase)
        sessions = other_device.megolm_inbound_sessions['room']['sender_key']
        assert sessions[session.id].id == session.id

        # Unknown algorithn
        other_device = OlmDevice(None, '@test:localhost', 'AUIETSRN')
        other_device._megolm_algorithm = 'wrong'
        other_device.import_keys(filename, passphrase)
        assert not other_device.megolm_inbound_sessions
    finally:
        os.remove(filename)
