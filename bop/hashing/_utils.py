from ._sha1 import sha1
from bop.utils import xor


__all__ = ['mac', 'hmac']


def mac(key, msg, alg=sha1):
    """Compute the MAC (message authentication code) for the given message using the given key

    Arguments:
        key {bytes} -- The key to sign the message with
        msg {bytes} -- The message to sign

    Keyword Arguments:
        alg {callable} -- The hash algorithm to use. (default: {sha1})

    Returns:
        bytes -- The MAC computed
    """
    return alg(key + msg)


def hmac(key, msg, alg=sha1):
    """Compute the HMAC (keyed-hash message authentication code) for the given message using the given key

    Arguments:
        key {bytes} -- The key to sign the message with
        msg {bytes} -- The message to sign

    Keyword Arguments:
        alg {callable} -- The hash algorithm to use. (default: {sha1})

    Returns:
        bytes -- The HMAC computed
    """
    if len(key) > 64:
        key = alg(key)

    if len(key) < 64:
        key = key + b'\x00' * (64 - len(key))

    outer = xor(key, 0x5c)
    inner = xor(key, 0x36)

    return alg(outer + alg(inner + msg))
