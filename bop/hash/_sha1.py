from bop.utils import chunks
import struct

__all__ = ['sha1_padding', 'sha1', 'Sha1Hash']


def rol(x, n):
    """Performs bitwise left rotation on 32-bit numbers

    ```python
    >>> rol(1 << 31, 1)
    1
    >>> rol((1 << 31) + 1, 2)
    6

    ```
    """
    return ((x << n) | (x >> (32 - n))) & 0xffffffff


def process_chunk(chunk, h):
    """Calculate the hash for one chunk of 512 bits using the initial state `h`

    Arguments:
        chunk {bytes} -- The 512 bit chunk to process
        h {tuple} -- A 5-tuple of 4-byte integers, the initial state

    Returns:
        tuple -- A 5-tuple of 4-byte integers, the updated state
    """

    assert (len(chunk) == 512//8)

    w = [0] * 80
    for i in range(16):
        w[i] = struct.unpack('>I', chunk[i*4:(i+1)*4])[0]

    for i in range(16, 80):
        w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)

    a = h[0]
    b = h[1]
    c = h[2]
    d = h[3]
    e = h[4]

    for i in range(80):
        if i < 20:
            f = d ^ (b & (c ^ d))
            k = 0x5A827999
        elif i < 40:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif i < 60:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d
            k = 0xCA62C1D6

        tmp = (rol(a, 5) + f + e + k + w[i]) & 0xffffffff
        a, b, c, d, e = tmp, a, rol(b, 30), c, d

    return (
        (h[0] + a) & 0xffffffff,
        (h[1] + b) & 0xffffffff,
        (h[2] + c) & 0xffffffff,
        (h[3] + d) & 0xffffffff,
        (h[4] + e) & 0xffffffff,
    )


def sha1_padding(message_length):
    r"""Create the SHA1 padding for a message of the given length

    ```python3
    >>> sha1_padding(53)
    b'\x80\x00\x00\x00\x00\x00\x00\x00\x00\x01\xa8'

    ```

    Arguments:
        message_length {int} -- The length of the message in bytes

    Returns:
        bytes -- The padding to be appended to the message
    """
    padding = b'\x80'
    padding += b'\x00' * ((56 - (message_length + 1) % 64) % 64)
    padding += struct.pack('>Q', message_length * 8)

    return padding


class Sha1Hash(object):
    r"""Represents the state of the SHA1 hashing algorithm.

    Usually you will not want to construct this manually. Use `sha1()` for that.

    The functionality is similiar to stdlib's `hashlib.sha1()`.
    This implementation exists to add more external control of the internal
    state of the algorithm.\
    Otherwise you usually will not want to use this.\
    Also note that SHA1 is considered broken, so you should not use it in general.

    Usage:
    ```python3
    >>> h = Sha1Hash()
    >>> h.update(b'Hey')
    >>> h.digest()
    b"\xe4Y\x9f\xa9\xf2e0t\x00]\xad'\xf0\x86\x83| \xfa\xee\xf4"
    >>> h.update(b'P\xAD' * 33 + b'Bye')
    >>> h.digest()
    b'y\xd7A\xcd~\xfa\x19\xa0\x17)dr\xbf>;\x8e~\xb4c\\'

    ```

    Keyword Arguments:
        h0 {int} -- The first 4 bytes of the internal initial state (default: {0x67452301})
        h1 {int} -- The second 4 bytes of the internal initial state (default: {0xEFCDAB89})
        h2 {int} -- The third 4 bytes of the internal intitial state (default: {0x98BADCFE})
        h3 {int} -- The fourth 4 bytes of the internal initial state (default: {0x10325476})
        h4 {int} -- The fifth 4 bytes of the internal initital state (default: {0xC3D2E1F0})
    """

    def __init__(
            self,
            h0=0x67452301,
            h1=0xEFCDAB89,
            h2=0x98BADCFE,
            h3=0x10325476,
            h4=0xC3D2E1F0):

        self.h = (
            h0,
            h1,
            h2,
            h3,
            h4
        )

        self.leftover = b''
        self.message_length = 0

    def update(self, byteslike):
        """Update the internal state with the given bytes-like object

        Arguments:
            byteslike {bytes} -- The data to feed into the hash
        """
        input = self.leftover + bytes(byteslike)

        chunk = input[:64]
        i = 0
        while len(chunk) == 64:
            self.h = process_chunk(chunk, self.h)
            self.message_length += 64
            i += 1
            chunk = input[i*64:(i+1)*64]

        self.leftover = chunk

    def digest(self):
        """Compute the digest of the data fed so far.

        This method does not affect the inner state. After calling `digest()`
        the caller may continue to feed data.

        Returns:
            bytes -- Digest of size 20 bytes.
        """
        final = self.leftover + sha1_padding(self.message_length + len(self.leftover))
        assert (len(final) % 64 == 0)

        h = self.h

        for c in chunks(final, 64):
            h = process_chunk(bytes(c), h)

        return b''.join([ struct.pack('>I', hi) for hi in h ])


def sha1(data=None):
    r"""Initialize a new SHA1 hash object or quickly generate a SHA1 hash

    Example:
    ```python
    >>> h = sha1()
    >>> h.update(b'Hello World!')
    >>> h.digest()
    b'.\xf7\xbd\xe6\x08\xceT\x04\xe9}_\x04/\x95\xf8\x9f\x1c#(q'

    ```
    Or quickly generate a SHA1 hash if the hash object is not needed:
    ```python
    >>> sha1(b'Hello World!')
    b'.\xf7\xbd\xe6\x08\xceT\x04\xe9}_\x04/\x95\xf8\x9f\x1c#(q'

    ```

    Returns:
        Sha1Hash or bytes-- A new SHA1 hash object or a SHA1 digest if data was provided
    """
    h = Sha1Hash()
    if data is None:
        return h

    h.update(data)
    return h.digest()
