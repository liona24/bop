from bop.hash import sha1
from bop.utils import invmod, i2b, b2i


def _dsa_sign(msg, p, q, g, x, k, hash=hash):
    if type(msg) != bytes:
        msg = i2b(msg)

    h = b2i(hash(msg))

    r = pow(g, k, p) % q
    s = (invmod(k, q) * (h + r * x)) % q

    return r, s


def recover_key_from_nonce(msg, sig, k, q, hash=sha1):
    """Recovers a DSA private key (`x`) from a message-signature-pair given a known nonce

    Example:
    ```python
    >>> from bop.crypto_constructor import dsa
    >>> my_dsa = dsa()
    >>> msg = b"Hello kind stranger!"
    >>> sig = my_dsa.sign(msg)
    >>> leaked_nonce = sig._k
    >>> my_dsa.x == recover_key_from_nonce(msg, sig, leaked_nonce, my_dsa.q, hash=my_dsa.hash)
    True

    ```

    Arguments:
        msg {bytes or int} -- The message which was signed
        sig {tuple or Signature} -- The signature of the given message in form `(r, s)`
        k {int} -- The leaked nonce
        q {int} -- The public parameter q
    """
    if type(msg) != bytes:
        msg = i2b(msg)

    h = b2i(hash(msg))
    r, s = sig

    return ((s * k - h) * invmod(r, q)) % q


def recover_key_from_duplicate_nonce(gen, public_parameters, hash=sha1):
    """Attempt to recover a DSA private key (`x`) from a stream of messages by searching for a duplicate usage of a nonce.

    Note that this is a pretty naive implementation running in O(n^2) where n is the number of messages (signatures) checked.

    Example:
    ```python
    >>> from bop.crypto_constructor import dsa
    >>> import secrets
    >>>
    >>> # Setup a weak implementation
    >>> my_dsa = dsa()
    >>> def weak_nonce_generator():
    ...     return secrets.choice(range(2, 11))
    ...
    >>> my_dsa.generate_nonce = weak_nonce_generator
    >>> def message_src():
    ...     while True:
    ...         msg = secrets.token_bytes(16)
    ...         yield msg, my_dsa.sign(msg)
    ...
    >>> x, leaked_nonce = recover_key_from_duplicate_nonce(message_src(), my_dsa.public_parameters, hash=my_dsa.hash)
    >>> my_dsa.x == x
    True

    ```

    Arguments:
        gen {generator} -- A generator yielding message-signature-pairs `(msg, signature)`.
            It will be consumed until a duplicate nonce is found or it is empty.
        public_parameters {tuple} -- The public parameters of the DSA algorithm used

    Keyword Arguments:
        hash {callable} -- The hash function to use (default: {sha1})

    Returns:
        (int, int) -- (x, leaked_nonce), i.e. the private key and the leaked nonce. Or (None, None) if no duplicate was found.
    """

    p, q, g, y = public_parameters

    first_msg, first_sig = next(gen)
    if type(first_msg) != bytes:
        first_msg = i2b(first_msg)
    bases = [(first_msg, first_sig)]

    # we do a simple exhaustive search for a duplicated nonce
    for msg1, sig1 in gen:
        if type(msg1) != bytes:
            msg1 = i2b(msg1)
        h1 = b2i(hash(msg1))
        r1, s1 = sig1

        for msg2, sig2 in bases:
            h2 = b2i(hash(msg2))
            r2, s2 = sig2
            # Assume k was equal
            k = ((h2 - h1) * invmod(s2 - s1, q)) % q

            # Check if our assumption holds
            x = recover_key_from_nonce(msg1, sig1, k, q, hash=hash)

            if _dsa_sign(msg1, p, q, g, x, k, hash=hash) == (r1, s1):
                return x, k

        bases.append((msg1, sig1))

    return None, None
