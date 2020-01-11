from itertools import chain

from bop.attacks.xor import brute_xor_multi
from bop.data.importer import Res


def ctr_fixed_nonce(iterable_of_ciphertexts, freq=Res.EN_freq_1):
    """Breaks CTR - Streamcipher (incorrectly) used with a fixed nonce using frequency analysis

    Example:
    ```python
    >>> from bop.crypto_constructor import aes_ctr
    >>> from bop.utils import xor
    >>> from bop.data.importer import load, Res
    >>> plaintexts = [b'Hello friendly reader']
    >>> plaintexts.extend(map(lambda x: x.encode('utf-8'), load(Res.EN_example_1)))
    >>> c = aes_ctr()
    >>> ciphertexts = [ c.encrypt(p) for p in plaintexts ]
    >>> _score, guessed_key = ctr_fixed_nonce(ciphertexts)[0]
    >>> xor(ciphertexts[0], guessed_key)
    b'Hello friendly reader'

    ```

    Arguments:
        iterable_of_ciphertexts {iterable} -- Iterable of `bytes`, collection of ciphertexts encrypted with the same key and nonce

    Keyword Arguments:
        freq {Res or dict} -- The frequency distribution to use, either as resource or a custom frequency distribution. (default: {Res.EN_freq_1})

    Returns:
        list -- List of (score, key) pairs. Best score first.
    """
    ciphertexts = sorted(iterable_of_ciphertexts, key=len, reverse=True)
    best = 0
    best_i = 0

    # we try to optimize the length of the ciphertext we can use.
    # sadly we can only take the first <length of shortest> bytes from every
    # cipher text
    for i, c in enumerate(ciphertexts):
        if (i+1) * len(c) >= best:
            best_i = i
            best = (i+1) * len(c)

    keylength = len(ciphertexts[best_i])
    fixed_size_ciphers = bytes(chain(*map(lambda c: c[:keylength], ciphertexts[:best_i + 1])))

    return brute_xor_multi(fixed_size_ciphers, keylength=keylength, freq=freq)
