from itertools import chain

from bop.utils import xor
from bop.attacks.sym.xor import brute_xor_multi
from bop.data.importer import Res


def inject_malformed(ciphertext, offset, is_, should):
    """Inject a custom payload after encrypting a known plaintext with AES CTR

    This is usefull if one wants to bypass some input validation.

    Example:
    ```python
    >>> from bop.crypto_constructor import aes_ctr
    >>> import secrets
    >>> c = aes_ctr()
    >>> plaintext = secrets.token_bytes(7) + b'HEY' + secrets.token_bytes(3)
    >>> ciphertext = c.encrypt(plaintext)
    >>> new_ciphertext = inject_malformed(ciphertext, 7, b'HEY', b'BYE')
    >>> c.decrypt(new_ciphertext)[7:10]
    b'BYE'

    ```

    Arguments:
        ciphertext {byteslike} -- The ciphertext to inject the payload into
        offset {int} -- The offset into the ciphertext at which the `is_` block starts.
        is_ {byteslike} -- The known plaintext, which is to be altered.
        should {byteslike} -- The desired plaintext

    Raises:
        ValueError: If the lengths of `is_` and `should` do not match

    Returns:
        byteslike -- The new ciphertext
    """
    if len(is_) != len(should):
        raise ValueError(f"Length of `is_` should be equal to length of `should`: {len(is_)} != {len(should)}")

    target_area = ciphertext[offset:offset + len(is_)]
    return ciphertext[:offset] + xor(xor(target_area, is_), should) + ciphertext[offset + len(is_):]


def fixed_nonce(iterable_of_ciphertexts, freq=Res.EN_freq_1):
    """Breaks CTR - Streamcipher (incorrectly) used with a fixed nonce using frequency analysis

    Example:
    ```python
    >>> from bop.crypto_constructor import aes_ctr
    >>> from bop.utils import xor
    >>> from bop.data.importer import load, Res
    >>> plaintexts = [b'Hello friendly reader']
    >>> plaintexts.extend(map(lambda x: x.encode('utf-8'), load(Res.EN_example_1)))
    >>> c = aes_ctr(key=b'YELLOW SUBMARINE', nonce=b'NotSoOnce Nonce!')
    >>> ciphertexts = [ c.encrypt(p) for p in plaintexts ]
    >>> _score, guessed_key = fixed_nonce(ciphertexts)[0]
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
