from bop.utils import invmod, cubic_root, cubic_root2, i2b, b2i
from bop.hash import sha1

__all__ = ["broadcast_e3", "recover_unpadded", "bleichenbacher_forge_signature", "decrypt"]


def broadcast_e3(messages, public_keys):
    """Perform a RSA broadcast attack for `e=3`

    For this to work the same plain text message has to be encrypted at least
    `e=3` times. This method will solve for the plain text using the chinese
    remainder theorem.

    This attack is well known as [Håstad's broadcast attack](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#H.C3.A5stad.27s_broadcast_attack)

    Example:
    ```python
    >>> plain = 1818
    >>> n0 = 179 * 181
    >>> n1 = 191 * 193
    >>> n2 = 197 * 199
    >>> e = 3
    >>> msg0 = pow(plain, e, n0)
    >>> msg1 = pow(plain, e, n1)
    >>> msg2 = pow(plain, e, n2)
    >>> broadcast_e3([msg0, msg1, msg2], [n0, n1, n2])
    1818

    ```

    Arguments:
        messages {list of int} -- The cipher texts captured
        public_keys {list of int} -- The public key parameters `N` for each message

    Returns:
        int -- The decrypted plain text
    """

    e = 3
    public_keys = public_keys[:e]
    messages = messages[:e]

    assert(len(set(public_keys)) == len(public_keys))
    assert(len(public_keys) == e)
    assert(len(messages) == e)

    it = zip(messages, public_keys)
    x, N = next(it)
    for (c, n) in it:
        x += ((invmod(N, n) * (c - x)) % n) * N
        N *= n

    return cubic_root(x)


def recover_unpadded(oracle, ciphertext, e, n, s=2):
    """Recover the plaintext given an oracle which decrypts recently unique messages.

    This is useful if to bypass the "recently unique" property of the oracle.

    Example:
    ```python3
    >>> from bop.oracles.message_recovery import MessageRecoveryOracle as Oracle
    >>> oracle = Oracle()
    >>> cipher = oracle.encrypt(1337)
    >>> oracle(cipher)
    1337
    >>> # We cannot recover the plaintext again:
    >>> assert(oracle(cipher) is None)
    >>> # Or can we?
    >>> recover_unpadded(oracle, cipher, oracle.rsa.e, oracle.rsa.n)
    1337

    ```

    Arguments:
        oracle {callable} -- The oracle to use. It should decrypt some ciphertext with some fixed key.
            You are only allowed to decrypt a message once.
        ciphertext {int} -- [description]
        e {int} -- The RSA public key parameter e
        n {int} -- The RSA public key parameter n

    Keyword Arguments:
        s {int} -- A *random* parameter to use for key recovery in the range [2, n] (default: {2})

    Returns:
        int -- The recovered plaintext
    """
    new_ciphertext = (pow(s, e, n) * ciphertext) % n
    tmp = oracle(new_ciphertext)
    return (invmod(s, n) * tmp) % n


def bleichenbacher_forge_signature(message, key_size, hash=sha1, protocol=b"DUMMY"):
    r"""Forge a signature RSA (e=3) signature for the given message.

    This method can be used to forge signatures if the checking is incorrectly implemented.

    For this example a dummy PKCS1.5 padding is applied (see argument `protocol`).
    This padding right-aligns the content (i.e. the hash of the message and some
    protocol information). However an incorrect implementation may not check if
    the signature is actually right-aligned.

    You may need a minimum key size for this to work. 1024 bits should be sufficient.

    Example:
    ```python3
    >>> import re
    >>> from bop.hash import sha1
    >>> from bop.crypto_constructor import rsa
    >>> def check(message, sig, rsa):
    ...     c = rsa.encrypt(sig)
    ...     # note that we are ignoring trailing bytes
    ...     # also note that the leading zero byte gets trimmed
    ...     h = re.match(br"^\x01(\xff)*?\x00DUMMY(.{20})", c, re.DOTALL).group(2)
    ...     return h == sha1(message)
    ...
    >>> some_rsa = rsa(e=3)
    >>> my_msg = b"My very valid message"
    >>> my_sig = bleichenbacher_forge_signature(my_msg, some_rsa.key_size)
    >>> check(my_msg, my_sig, some_rsa)
    True

    ```

    Arguments:
        message {bytes} -- The message to sign
        key_size {int} -- The size of the public key parameter N in bits

    Keyword Arguments:
        hash {callable} -- The hash algorithm to use (default: {sha1})
        protocol {bytes} -- The bytes to use which specify meta data. In reality this would be some kind of ASN.1 scheme but for this toy example it does not really matter. (default: {b"DUMMY"})

    Returns:
        bytes -- The signature of the message
    """
    # we fake this. In reality a little bit of effort has to be made in order to specify the
    # hash algorithm used, size of the hash etc.
    h = hash(message)
    payload = b"\x00" + protocol + h
    payload_len = len(payload) * 8

    # this is more or less a heuristic, place digest at about 2/3
    position = key_size // 8 // 3 * 16

    n = (1 << payload_len) - b2i(payload)
    c = (1 << (key_size - 15)) - n * (1 << position)

    root = cubic_root2(c)
    if len(root) == 1:
        # we are lucky
        root = root[0]
    else:
        root = root[-1]

    return i2b(root)


def decrypt(oracle, msg, e, n):
    """Performs a RSA-parity attack given an oracle which reports whether a decrypted plaintext is even or odd

    Example:
    ```python
    >>> from bop.oracles.parity import RsaParityOracle as Oracle
    >>> o = Oracle()
    >>> msg = o.encrypt(b"Hello Bob!")
    >>> e, n = o.public_key()
    >>> decrypt(o, msg, e, n)
    b'Hello Bob!'

    ```

    Args:
        oracle (callable): A function which decrypts ciphers which were encrypted using the given public key and reports whether the resulting plain text is even (`True`) or odd (`False`)
        msg (bytes or int): The encrypted message to decrypt
        e (int): The public key exponent e
        n (int): The public key modul n

    Raises:
        RuntimeError: If the plain text cannot be recovered. This is propably caused by rounding errors

    Returns:
        bytes or int: The decrypted message. Depending on the type given (`msg`) the resulting type matches.
    """
    was_bytes = False
    if type(msg) != int:
        was_bytes = True
        msg = b2i(msg)

    i = 2
    upper = n
    lower = 0

    # we will use this to carry the rounding error, though this is VERY vague
    # the desired plain text is usually off by only 1 anyways
    rest = 1

    while i <= n:
        # encrypt i
        f = pow(i, e, n)

        if oracle(f * msg):
            # even
            upper = (upper + lower) // 2
            rest += (upper + lower) & 1
        else:
            # odd
            lower = (upper + lower) // 2

        i <<= 1

    for plain in range(lower, upper + rest):
        if pow(plain, e, n) == msg:
            if was_bytes:
                return i2b(plain)
            else:
                return plain

    raise RuntimeError("Could not find plain text. Something went wrong :(")
