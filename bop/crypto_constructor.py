"""This module exposes interfaces which can be used to easily encrypt/decrypt
data with your favourite algorithms.

The purpose is ease of use. It comes at the cost of no flexibility.
"""

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, modes

import secrets
import binascii

from bop.utils import invmod, b2i, i2b, bit_length_exp2
from bop.hashing import sha1

__all__ = ['aes_cbc', 'aes_ctr', 'rsa', 'dsa']


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


class SimpleDSAInterface(object):
    """Provides a simple interface to DSA signing.

    Arguments:
        p {int} -- Parameter p
        q {int} -- Parameter q
        g {int} -- Parameter g
        x {int} -- Private key x
    """

    class Signature(object):
        def __init__(self, r, s, k):
            self.r = r
            self.s = s
            self._k = k

        def __iter__(self):
            return iter([self.r, self.s])

        def __str__(self):
            return binascii.hexlify(i2b(self.r)) + "." + binascii.hexlify(i2b(self.s))

        def __eq__(self, other):
            if type(other) != SimpleDSAInterface.Signature:
                return False
            return self.r == other.r and self.s == other.s

    def __init__(self, p, q, g, x, y, hash):
        self.p = p
        self.q = q
        self.g = g
        self.x = x
        self.y = y
        self.hash = hash

        # this is a hook which can be used to "weaken" this implementation
        self.generate_nonce = None

    @property
    def public_parameters(self):
        return (self.p, self.q, self.g, self.y)

    @property
    def private_key(self):
        return (self.x,)

    def sign(self, msg):
        if type(msg) != bytes:
            msg = i2b(msg)

        h = b2i(self.hash(msg))
        s = 0
        while s == 0:
            r = 0
            while r == 0:
                if self.generate_nonce is not None:
                    k = self.generate_nonce()
                else:
                    k = secrets.randbelow(self.q - 2) + 2

                r = pow(self.g, k, self.p) % self.q
            s = (invmod(k, self.q) * (h + r * self.x)) % self.q

        return self.Signature(r, s, k)

    def verify(self, msg, sig):
        r, s = sig
        if r <= 0 or r >= self.q or s <= 0 or s >= self.q:
            return False

        if type(msg) != bytes:
            msg = i2b(msg)

        h = b2i(self.hash(msg))
        w = invmod(s, self.q)
        u1 = (w * h) % self.q
        u2 = (w * r) % self.q

        v = (pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.q
        return v == r

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "<SimpleDSA>"


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

    key_size = bit_length_exp2(n)
    return SimpleRSAInterface(d, n, e, key_size=key_size)


def dsa(p=None, q=None, g=None, y=None, x=None, hash=sha1):
    if p is None or q is None or g is None:
        p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
        q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
        g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

    if x is None:
        x = secrets.randbelow(q - 2) + 2
    if y is None:
        y = pow(g, x, p)
    return SimpleDSAInterface(p, q, g, x, y, hash)
