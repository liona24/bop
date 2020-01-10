from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, modes

import secrets

__all__ = ['aes_cbc', 'aes_ctr']


class SimpleSymCipherInterface(object):
    def __init__(self, cipher, alg_name, mode_name, **kvargs):
        self.cipher = cipher
        self.alg_name = alg_name
        self.mode_name = mode_name

        for k in kvargs:
            setattr(self, k, kvargs[k])

    def encrypt(self, plaintext):
        enc = self.cipher.encryptor()
        return enc.update(plaintext) + enc.finalize()

    def decrypt(self, ciphertext):
        dec = self.cipher.decryptor()
        return dec.update(ciphertext) + dec.finalize()

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return f"<SimpleSymCipherInterface {self.alg_name} | {self.mode_name}>"


def aes_cbc(key=None, iv=None):
    if key is None:
        key = secrets.token_bytes(16)
    if iv is None:
        iv = secrets.token_bytes(16)

    c = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    return SimpleSymCipherInterface(c, 'AES', 'CBC', key=key, iv=iv)


def aes_ctr(key=None, nonce=None):
    if key is None:
        key = secrets.token_bytes(16)
    if nonce is None:
        nonce = secrets.token_bytes(16)

    c = Cipher(algorithms.AES(key), modes.CTR(nonce), default_backend())
    return SimpleSymCipherInterface(c, 'AES', 'CTR', key=key, nonce=nonce)
