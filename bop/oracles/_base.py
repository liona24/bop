import secrets

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.backends import default_backend

from bop.utils import pad


class _Oracle(object):
    def __init__(self, alg, mode, key=None, keysize=128):
        if key is None:
            key = secrets.token_bytes(keysize // 8)

        self.key = key
        backend = default_backend()
        self.cipher = Cipher(alg(key), mode, backend=backend)
        self.plain = None
        self.msg = None

    def _encrypt(self, *parts):
        self.plain = pad(*parts)

        enc = self.cipher.encryptor()
        self.msg = enc.update(self.plain) + enc.finalize()

        return self.msg

    def _decrypt(self, msg):
        dec = self.cipher.decryptor()

        return dec.update(msg) + dec.finalize()
