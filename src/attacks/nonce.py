from itertools import chain

from attacks.xor import brute_xor_multi


def ctr_fixed_nonce(iterable_of_ciphertexts, freq='en'):
    """Breaks CTR - Streamcipher used with a fixed nonce using frequency analysis

    Arguments:
        iterable_of_ciphertexts {iterable} -- Iterable of `bytes`, collection of ciphertexts encrypted with the same key and nonce

    Keyword Arguments:
        freq {str or dict} -- The frequency distribution to use. Specify a language or a custom frequency distribution. (default: {'en'})

    Returns:
        list -- List of (score, key) pairs. Best score first.
    """

    if freq != 'en':
        raise NotImplementedError("Custom frequency currently not yet supported!")

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

    return brute_xor_multi(fixed_size_ciphers, keylength=keylength)
