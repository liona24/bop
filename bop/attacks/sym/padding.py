from bop.utils import chunks, xor


def cbc_decrypt(oracle, msg, iv=None, blocksize=16):
    r"""Performs a CBC - blockcipher attack when given a padding oracle.

    A padding oracle reports whether a message given for decryption has valid
    padding after decrpyting it.

    This attack is able to decrypt the given message without knowing the secret key.

    Example:
    ```python
    >>> import secrets
    >>> from bop.oracles.padding import PaddingCBCOracle as Oracle
    >>> iv = secrets.token_bytes(16)
    >>> plain = b'Hello Bop.'
    >>> o = Oracle(plaintext=plain, iv=iv)
    >>> cbc_decrypt(o, o.msg, iv=iv)
    b'Hello Bop.\x06\x06\x06\x06\x06\x06'

    ```

    Arguments:
        oracle {oracles.PaddingOracle} -- The padding oracle
        msg {bytes} -- The encrypted message to decrypt

    Keyword Arguments:
        iv {bytes} -- The initialization vector used for decryption (default: {None})
        blocksize {int} -- The CBC block size in bytes (default: {16})

    Returns:
        bytes -- The decrypted message
    """
    assert (len(msg) % blocksize == 0)

    blocks = list(chunks(msg, blocksize))

    if iv is not None:
        blocks = [iv] + blocks
    # if we do not know the iv we cannot decrypt the first block

    it0, it1 = iter(blocks), iter(blocks)
    next(it1)

    plaintext = []

    # iterate over consecutive blocks
    for (iv, block) in zip(it0, it1):
        # this is our 'artificial iv', we only ever need 2 consecutive blocks
        # so we treat the first one as iv
        iv = bytes(iv)
        # the block we are actually decrypting
        block = bytes(block)

        decrypted = [0] * blocksize

        backtrace = []
        i = blocksize - 1
        b0 = 0

        # for each byte in the block, in reverse order
        while i >= 0:

            # we now alter each byte in the block, one byte at a time
            # by flipping bits of our iv.
            # the padding oracle will tell us if the tampered block was correct
            # Consider the last byte: A valid padding would be \x01
            # We now try all possible values for the last byte. Eventually
            # the oracle will report that we successfully changed the value
            # of the last byte to \x01

            # the value the result should have, i.e. the layout of the padding
            value_should = blocksize - i
            mask = [0] * blocksize
            mask[i+1:] = xor(decrypted[i+1:], value_should)

            # try out all possible values
            for b in range(b0, 256):
                mask[i] = b
                tampered_iv = xor(mask, iv)

                if oracle(tampered_iv + block):
                    decrypted[i] = b ^ value_should
                    backtrace.append((i, b+1))
                    break
            else:
                # if the padding is valid naturally we may encounter collisions, i.e. hitting the "correct" byte twice.
                # if we ignore the second hit we will eventually fail if the first hit was the wrong one
                # therefor we trace such behaviour and perform backtracking to the last successfull i
                i, b0 = backtrace.pop()
                decrypted[:i] = [0] * i
                continue

            i -= 1
            b0 = 0

        plaintext.extend(decrypted)

    return bytes(plaintext)
