from bop.crypto_constructor import rsa


class RsaParityOracle(object):
    """Construct a RSA parity oracle which reports whether a decrypted message was even or odd.
    """

    def __init__(self, e=0x10001, p=None, q=None):
        self.rsa = rsa(p=p, q=q, e=e)

    def encrypt(self, plaintext):
        return self.rsa.encrypt(plaintext)

    def public_key(self):
        return self.rsa.e, self.rsa.n

    def __call__(self, ciphertext):
        plain = self.rsa.decrypt(ciphertext)

        return plain % 2 == 0
