from bop.utils import xor, chunks


def inject_malformed(ciphertext, offset, is_, should, iv=None, blocksize=16):
    """Inject a custom payload after encrypting a known plaintext using AES CBC.

    This is usefull if one wants to bypass some input validation. Note that the maximum payload size is `blocksize`.
    In order to achieve this payload size the controlled block has to be aligned though, i.e. offset % blocksize = 0.

    Also note that block preceeding the block carrying the payload is destroyed when applying this technique.

    Example:
    ```python
    >>> from bop.crypto_constructor import aes_cbc
    >>> import secrets
    >>> c = aes_cbc()
    >>> plaintext = secrets.token_bytes(18) + b'HEY' + secrets.token_bytes(11)
    >>> ciphertext = c.encrypt(plaintext)
    >>> _, new_ciphertext = inject_malformed(ciphertext, 18, b'HEY', b'BYE')
    >>> c.decrypt(new_ciphertext)[18:21]
    b'BYE'

    ```

    Arguments:
        ciphertext {byteslike} -- The ciphertext to inject the payload into
        offset {int} -- The offset into the ciphertext at which the `is_` block starts.
        is_ {byteslike} -- The known plaintext, which is to be altered.
        should {byteslike} -- The desired plaintext

    Keyword Arguments:
        iv {byteslike} -- Provide the IV if available. This will allow injecting into the first block. Not required otherwise (default: {None})
        blocksize {int} -- The blocksize in bytes used for the AES algorithm (default: {16})

    Raises:
        ValueError: If the lengths of `is_` and `should` do not match
        ValueError: If the payload cannot be injected at the offset provided
        ValueError: If the payload is too long

    Returns:
        (bytes, bytes) -- A tuple containing the new IV and the new ciphertext respectively. IV will be None if not provided.
    """
    n = len(should)

    if len(is_) != n:
        raise ValueError(f"Length of `is_` should be equal to length of `should`: {len(is_)} != {n}")
    if offset < blocksize and iv is None:
        raise ValueError(f"Cannot alter block located before offset {offset}! At least one full-sized block is required in front of the payload!")

    if iv is not None:
        ciphertext = iv + ciphertext
        offset += blocksize

    possible_payload_size = blocksize - (offset % blocksize)
    if n > possible_payload_size:
        # Maximum value if blocks are aligned is equal to blocksize
        raise ValueError(f"Cannot inject payload: Too long ({n} > {possible_payload_size})")

    new_ciphertext = bytearray(ciphertext)

    i = offset - blocksize
    target_area = ciphertext[i:i + n]
    new_ciphertext[i:i + n] = xor(xor(target_area, is_), should)

    new_ciphertext = bytes(new_ciphertext)

    if iv is not None:
        iv = new_ciphertext[:blocksize]
        new_ciphertext = new_ciphertext[blocksize:]

    return iv, new_ciphertext


def decrypt(oracle, msg, iv=None, blocksize=16):
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
    >>> decrypt(o, o.msg, iv=iv)
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
