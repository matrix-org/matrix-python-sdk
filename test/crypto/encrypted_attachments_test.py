import pytest
pytest.importorskip('olm') # noqa

from matrix_client.crypto.encrypt_attachments import (encrypt_attachment,
                                                      decrypt_attachment)


def test_encrypt_decrypt():
    message = b'test'
    ciphertext, info = encrypt_attachment(message)
    assert decrypt_attachment(ciphertext, info) == message

    ciphertext += b'\x00'
    with pytest.raises(RuntimeError):
        decrypt_attachment(ciphertext, info)
