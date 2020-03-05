from bop.utils import invmod, cubic_root

__all__ = ["rsa_e3_broadcast"]


def _prod(iterable):
    x = 1
    for i in iterable:
        x *= i
    return x


def rsa_e3_broadcast(messages, public_keys):
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
    >>> rsa_e3_broadcast([msg0, msg1, msg2], [n0, n1, n2])
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
