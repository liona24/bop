from bop.utils import xor


def cbc_inject_malformed(ciphertext, offset, is_, should, iv=None, blocksize=16):
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
    >>> _, new_ciphertext = cbc_inject_malformed(ciphertext, 18, b'HEY', b'BYE')
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


def ctr_inject_malformed(ciphertext, offset, is_, should):
    """Inject a custom payload after encrypting a known plaintext with AES CTR

    This is usefull if one wants to bypass some input validation.

    Example:
    ```python
    >>> from bop.crypto_constructor import aes_ctr
    >>> import secrets
    >>> c = aes_ctr()
    >>> plaintext = secrets.token_bytes(7) + b'HEY' + secrets.token_bytes(3)
    >>> ciphertext = c.encrypt(plaintext)
    >>> new_ciphertext = ctr_inject_malformed(ciphertext, 7, b'HEY', b'BYE')
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
