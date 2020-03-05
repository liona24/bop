from bop.utils import invmod


class MessageRecoveryOracle(object):
    def __init__(self, e=None, p=None, q=None):
        if e is None:
            e = 0x10001

        if p is None or q is None:
            n = 0xcae43cb8b62c7839ce3c771331f29e8b7eba706c381a049f7b2d38191af304a0a518a165a7d7774784d52049adc24da60dc3e0781e32b0633a8d8d676dc48311
            p = 0xfe8557c536be50a41a682a848731377fec2e7889a02b68697ba8a93dfd7aca45
            q = 0xcc1215873a81091163885ebd390c0e3ae18c2e5c961cdaa5daa563cbd459685d
        else:
            n = p * q

        self.e = e
        self.n = n
        pq = (p - 1) * (q - 1)
        self.d = invmod(e, pq)
        self.recently_seen = set()

    def encrypt(self, plaintext):
        return pow(plaintext, self.e, self.n)

    def __call__(self, ciphertext):
        if ciphertext in self.recently_seen:
            return None

        self.recently_seen.add(ciphertext)
        return pow(ciphertext, self.d, self.n)
