import unpaddedbase64
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from Crypto.Hash import SHA256


def encrypt_attachment(plaintext):
    """Encrypt a plaintext in order to send it as an encrypted attachment.

    Args:
        plaintext (bytes): The data to encrypt.

    Returns:
        A tuple of the ciphertext bytes and a dict containing the info needed
        to decrypt data. The keys are:

        | key: AES-CTR JWK key object.
        | iv: Base64 encoded 16 byte AES-CTR IV.
        | hashes.sha256: Base64 encoded SHA-256 hash of the ciphertext.
    """
    # 8 bytes IV
    iv = Random.new().read(8)
    # 8 bytes counter, prefixed by the IV
    ctr = Counter.new(64, prefix=iv, initial_value=0)
    key = Random.new().read(32)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    ciphertext = cipher.encrypt(plaintext)
    h = SHA256.new()
    h.update(ciphertext)
    digest = h.digest()
    json_web_key = {
        'kty': 'oct',
        'alg': 'A256CTR',
        'ext': True,
        'k': unpaddedbase64.encode_base64(key, urlsafe=True),
        'key_ops': ['encrypt', 'decrypt']
    }
    keys = {
        'v': 'v2',
        'key': json_web_key,
        # Send IV concatenated with counter
        'iv': unpaddedbase64.encode_base64(iv + b'\x00' * 8),
        'hashes': {
            'sha256': unpaddedbase64.encode_base64(digest),
        }
    }
    return ciphertext, keys


def decrypt_attachment(ciphertext, info):
    """Decrypt an encrypted attachment.

    Args:
        ciphertext (bytes): The data to decrypt.
        info (dict): The information needed to decrypt the attachment.

            | key: AES-CTR JWK key object.
            | iv: Base64 encoded 16 byte AES-CTR IV.
            | hashes.sha256: Base64 encoded SHA-256 hash of the ciphertext.

    Returns:
        The plaintext bytes.

    Raises:
        RuntimeError if the integrity check fails.
    """
    expected_hash = unpaddedbase64.decode_base64(info['hashes']['sha256'])
    h = SHA256.new()
    h.update(ciphertext)
    if h.digest() != expected_hash:
        raise RuntimeError('Mismatched SHA-256 digest.')

    key = unpaddedbase64.decode_base64(info['key']['k'])
    # Drop last 8 bytes, which are 0
    iv = unpaddedbase64.decode_base64(info['iv'])[:8]
    ctr = Counter.new(64, prefix=iv, initial_value=0)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

    return cipher.decrypt(ciphertext)
