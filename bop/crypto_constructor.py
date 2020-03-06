"""This module exposes interfaces which can be used to easily encrypt/decrypt
data with your favourite algorithms.

The purpose is ease of use. It comes at the cost of no flexibility.
"""

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, modes

import secrets

from bop.utils import invmod, b2i, i2b

__all__ = ['aes_cbc', 'aes_ctr', 'rsa']


class SimpleRSAInterface(object):
    def __init__(self, d, n, e, **kvargs):
        self.d = d
        self.n = n
        self.e = e

        for k in kvargs:
            setattr(self, k, kvargs[k])

    def encrypt(self, plaintext):
        was_bytes = False
        if type(plaintext) != int:
            plaintext = b2i(plaintext)
            was_bytes = True

        c = pow(plaintext, self.e, self.n)

        if was_bytes:
            c = i2b(c)

        return c

    def decrypt(self, cipher):
        was_bytes = False
        if type(cipher) != int:
            cipher = b2i(cipher)
            was_bytes = True

        m = pow(cipher, self.d, self.n)

        if was_bytes:
            m = i2b(m)

        return m

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return f"<SimpleRSA>"


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


def rsa(p=None, q=None, e=0x10001):
    if p is None or q is None:
        p = 0xfe8557c536be50a41a682a848731377fec2e7889a02b68697ba8a93dfd7aca45
        q = 0xcc1215873a81091163885ebd390c0e3ae18c2e5c961cdaa5daa563cbd459685d
        p = 11657510804603879190708332092675312014343829286377852544041511516023862575778860458573625524357360917135073366324924898682703984245741417367112631371911313
        q = 10089976740518582496356045969057602987024596248854888881417032743865018594042312715942618960983484996648974071339742122325713010480659249911953583913570703

    n = p * q

    pq = (p - 1) * (q - 1)
    d = invmod(e, pq)

    key_size = len(bin(n)) - 2

    return SimpleRSAInterface(d, n, e, key_size=key_size)
