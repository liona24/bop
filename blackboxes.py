import secrets
from aes import pad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def _random_padding(min=4, max=16):
    return secrets.token_bytes(min + secrets.randbelow(max - min))


def encrypt_randomly_with_ecb_or_cbc(byteslike=None):
    if byteslike is None:
        len_ = 1 + secrets.randbelow(2048)
        byteslike = secrets.token_bytes(len_)

    key = secrets.token_bytes(16)

    head = _random_padding()
    tail = _random_padding()

    backend = default_backend()

    mode = secrets.choice(['CBC', 'ECB'])

    if mode == 'CBC':
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    else:
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)

    data = pad(head, byteslike, tail)

    enc = cipher.encryptor()
    msg = enc.update(data) + enc.finalize()

    return msg, (mode, key, data)

