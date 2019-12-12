import secrets

from cryptography.hazmat.primitives.ciphers import algorithms, modes

from bop.oracles._base import _Oracle
from bop.utils import is_padding_valid


__all__ = [ 'PaddingCBCOracle', 'PaddingECBOracle' ]


class _PaddingOracle(_Oracle):
    def __init__(self, alg, mode, plaintext=None, key=None, keysize=128):
        super().__init__(alg, mode, key=key, keysize=keysize)

        if plaintext is None:
            len_ = 1 + secrets.randbelow(64)
            plaintext = secrets.token_bytes(len_)

        self.plain = plaintext
        self._encrypt(plaintext)

    def is_valid(self, msg):
        plain = self._decrypt(msg)

        return is_padding_valid(plain)

    def __call__(self, msg):
        return self.is_valid(msg)


class PaddingCBCOracle(_PaddingOracle):
    def __init__(self, plaintext=None, key=None, keysize=128, iv=None):
        if iv is None:
            iv = secrets.token_bytes(16)

        super().__init__(algorithms.AES, modes.CBC(iv), plaintext=plaintext, key=key, keysize=keysize)


class PaddingECBOracle(_PaddingOracle):
    def __init__(self, plaintext=None, key=None, keysize=128):
        super().__init__(algorithms.AES, modes.ECB(), plaintext=plaintext, key=key, keysize=keysize)
