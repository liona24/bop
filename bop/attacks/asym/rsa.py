from bop.utils import invmod, cubic_root, cubic_root2, i2b, b2i, bit_length_exp2
from bop.hashing import sha1
import secrets

__all__ = ["broadcast_e3", "recover_unpadded", "bleichenbacher_forge_signature", "decrypt_parity_leak", "decrypt_pkcs_padding_leak"]


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
    >>> from bop.hashing import sha1
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


def decrypt_parity_leak(oracle, msg, e, n):
    """Performs a RSA-parity attack given an oracle which reports whether a decrypted plaintext is even or odd

    Example:
    ```python
    >>> from bop.oracles.parity import RsaParityOracle as Oracle
    >>> o = Oracle()
    >>> msg = o.encrypt(b"Hello Bob!")
    >>> e, n = o.public_key()
    >>> decrypt_parity_leak(o, msg, e, n)
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


def decrypt_pkcs_padding_leak(oracle, msg, e, n):
    """Perform an adaptive chosen ciphertext against a weak RSA implementation leaking PKCS1v5 padding information.

    This attack was discovered by Daniel Bleichenbacher and is well described in the original [paper](http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf).

    Side note:\
    This attack is generally faster if `msg` is already properly padded.
    Depending on the keysize the expected running time may be somewhere between a few seconds (key size <= 512 bits) or somewhere around
    one minute for a 1024 public modulus.

    I once tested using a 2048 bit key which ran about an hour..\
    I am pretty sure this implementation is far from optimal, though I am not qualified to judge where I went wrong.


    Example:
    ```python3
    >>> from bop.oracles.padding import PaddingRSAOracle as Oracle
    >>> import bop.utils as utils
    >>> # We will choose smaller params to keep the running time down a little bit
    >>> p, q = utils.gen_rsa_key_params(256)
    >>> o = Oracle(p, q)
    >>> e, n = o.public_key()
    >>> plain = b"Hey! This message is save!"
    >>> # Optional: Pad the message:
    >>> # plain = utils.pad_pkcs1v5(plain, n)
    >>> msg = o.encrypt(plain)
    >>> decrypt_pkcs_padding_leak(o, msg, e, n)
    b'Hey! This message is save!'

    ```


    Args:
        oracle (callable): An oracle which leaks whether the decrypted message has a valid PKCS1v5 padding or not
            (i. e. the first byte is equal to 0 and the second byte is equal to 2)
        msg (bytes or int): The message to decrypt
        e (int): The public exponent
        n (int): The public modulus

    Returns:
        bytes or int: The decrypted message. Depending on the input type the output type is matched.
    """

    was_bytes = False
    if type(msg) != int:
        msg = b2i(msg)
        was_bytes = True

    k = bit_length_exp2(n)
    assert k > 16

    B = 1 << (k - 16)

    s0 = 1
    c0 = msg

    first = True

    M = {(2 * B, 3 * B - 1)}
    if not oracle(msg):
        # Blinding
        # ensure we have a valid padding to work with
        while True:
            s0 = secrets.randbelow(n - 1) + 1
            c0 = (msg * pow(s0, e, n)) % n
            if oracle(c0):
                break

    while True:
        if first:
            # Step 2a
            s = n // (3 * B)
            while oracle((c0 * pow(s, e, n)) % n) is False:
                s += 1
            first = False
        elif len(M) > 1:
            # Step 2b
            s_ = s + 1
            while not oracle((c0 * pow(s_, e, n)) % n):
                s_ += 1
            s = s_
        else:
            # Step 2c
            a, b = next(iter(M))
            found = False
            r = 2 * (b * s - 2 * B) // n
            while not found:
                s_ = (2 * B + r * n) // b

                s_max = (3 * B + r * n) // a

                while s_ <= s_max:
                    if oracle((c0 * pow(s_, e, n)) % n):
                        found = True
                        break
                    s_ += 1

                r += 1

            s = s_

        # Step 3
        M_ = set()
        for a, b in M:
            r_low = (a * s - 3 * B + 1) // n
            r_high = (b * s - 2 * B) // n
            for r in range(r_low, r_high + 1):
                # note the + s - 1 in order to ensure rounding to the next integer
                low = max(a, (2 * B + r * n + s - 1) // s)
                high = min(b, (3 * B - 1 + r * n) // s)

                if low <= high and (low, high) not in M_:
                    M_.add((low, high))

        M = M_

        # Step 4
        if len(M) == 1:
            a, b = next(iter(M))
            if a == b:
                plain = (a * invmod(s0, n)) % n
                if was_bytes:
                    return i2b(plain)
                return plain
