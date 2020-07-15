import secrets

from cryptography.hazmat.primitives.ciphers import algorithms, modes

from bop.oracles._base import _EncryptionOracle
from bop.crypto_constructor import rsa
from bop.utils import is_padding_valid, i2b, pad_pkcs1v5


__all__ = [ 'PaddingCBCOracle', 'PaddingECBOracle' ]


class _PaddingOracle(_EncryptionOracle):
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
    r"""An oracle which leaks information about whether a decrypted ciphertext has valid padding

    Messages are encrypted using AES CBC.

    Keyword Arguments:
        plaintext {byteslike} -- The plaintext to generate the cipher from. Will be generated if None (default: {None})
        key {byteslike} -- The key to use for encryption. Will be generated if None (default: {None})
        keysize {int} -- The size of the key in bits (default: {128})
        iv {byteslike} -- The IV to use for encryption. Will be generated if None (default: {None})

    Usage:
    ```python
    >>> # Messages will be padded automatically
    >>> oracle = PaddingCBCOracle(b'Hello World!')
    >>> with_valid_padding = oracle.msg
    >>> # Make some arbitrary changes to invalidate the message
    >>> with_invalid_padding = oracle.msg[:-2] + b'Hi'
    >>> oracle(with_valid_padding)
    True
    >>> oracle(with_invalid_padding)
    False

    ```
    """
    def __init__(self, plaintext=None, key=None, keysize=128, iv=None):
        if iv is None:
            iv = secrets.token_bytes(16)

        super().__init__(algorithms.AES, modes.CBC(iv), plaintext=plaintext, key=key, keysize=keysize)


class PaddingECBOracle(_PaddingOracle):
    r"""An oracle which leaks information about whether a decrypted ciphertext has valid padding

    Messages are encrypted using AES ECB.

    Keyword Arguments:
        plaintext {byteslike} -- Not used. (default: {None})
        key {byteslike} -- The key to use for encryption. Will be generated if None (default: {None})
        keysize {int} -- The size of the key in bits (default: {128})

    Usage:
    ```python
    >>> # Messages will be padded automatically
    >>> oracle = PaddingCBCOracle(b'Hello World!')
    >>> with_valid_padding = oracle.msg
    >>> # Make some arbitrary changes to invalidate the message
    >>> with_invalid_padding = oracle.msg[:-2] + b'Hi'
    >>> oracle(with_valid_padding)
    True
    >>> oracle(with_invalid_padding)
    False

    ```
    """
    def __init__(self, plaintext=None, key=None, keysize=128):
        super().__init__(algorithms.AES, modes.ECB(), plaintext=plaintext, key=key, keysize=keysize)


class PaddingRSAOracle(object):

    def __init__(self, p=None, q=None, e=0x10001):
        print(p, q)
        self.rsa = rsa(p, q, e)

    def public_key(self):
        return self.rsa.e, self.rsa.n

    def encrypt(self, plain):
        return self.rsa.encrypt(plain)

    def __call__(self, msg):
        plain = self.rsa.decrypt(msg)

        if type(plain) == int:
            plain = i2b(plain)

        # the conversion will hide the first byte if it is zero
        first_byte_is_zero = len(plain) == (self.rsa.key_size // 8 - 1)

        return first_byte_is_zero and plain[0] == 2
