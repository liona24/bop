from bop.crypto_constructor import rsa


class MessageRecoveryOracle(object):
    def __init__(self, e=0x10001, p=None, q=None):
        self.rsa = rsa(p=p, q=q, e=e)
        self.recently_seen = set()

    def encrypt(self, plaintext):
        return self.rsa.encrypt(plaintext)

    def __call__(self, ciphertext):
        if ciphertext in self.recently_seen:
            return None

        self.recently_seen.add(ciphertext)
        return self.rsa.decrypt(ciphertext)
