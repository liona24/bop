import secrets

from cryptography.hazmat.primitives.ciphers import algorithms, modes

from oracles._base import _Oracle


__all__ = [ 'KnownInfixECBOracle', 'KnownInfixCBCOracle' ]


class _KnownInfixOracle(_Oracle):
    def __init__(self, alg, mode, head=None, tail=None, key=None, keysize=128):
        super().__init__(alg, mode, key=key, keysize=keysize)

        if tail is None:
            tail = secrets.token_bytes(35)
        if head is None:
            head = b''

        self.tail = tail
        self.head = head

    def encrypt(self, prefix):
        return self._encrypt(self.head, prefix, self.tail)

    def decrypt(self, msg):
        return self._decrypt(msg)

    def __call__(self, prefix):
        return self.encrypt(prefix)


class KnownInfixECBOracle(_KnownInfixOracle):
    def __init__(self, head=None, tail=None, key=None, keysize=128):
        super().__init__(algorithms.AES, modes.ECB(), head=None, tail=None, key=key, keysize=keysize)


class KnownInfixCBCOracle(_KnownInfixOracle):
    def __init__(self, head=None, tail=None, key=None, keysize=128, iv=None):
        if iv is None:
            iv = secrets.token_bytes(16)

        super().__init__(algorithms.AES, modes.CBC(iv), head=head, tail=tail, key=key, keysize=keysize)
