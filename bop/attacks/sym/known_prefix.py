from bop.utils import chunks, infix_block_diffs


def ecb_guess_block_layout(oracle, default_prefix=None, pb=b'\x01', max_blocksize=3*512):
    """Guesses the blocklayout given an ECB - Infix - Oracle

    A blocklayout consists of 3 parameters:
    The blocksize of the ECB algorithm (in bytes)
    The block offset, i.e. the index of the first block which can be solely controlled by the attacker
    The padding offset, i.e. the number of bytes which cannot be controlled before the attacker controlled bytes

    ```
    <- blocksize ->
    X X X X X X X X | X X X X A A A A | A A A A A A A A | ...
    0                 1                 2
        block offset -------------------^
                     <------>
                        padding offset
    ```

    Example:
    ```python
    >>> from bop.oracles.known_infix import KnownInfixECBOracle as Oracle
    >>> o = Oracle(head=b'Some prefix, 26 bytes long', tail=b'Very secret, very transparent text.')
    >>> ecb_guess_block_layout(o)
    (16, 2, 10)

    ```
    Example:
    ```python
    >>> from bop.oracles.known_infix import KnownInfixECBOracle as Oracle
    >>> o = Oracle(tail=b'Very secret, very transparent text.')
    >>> ecb_guess_block_layout(o)
    (16, 0, 0)

    ```

    Arguments:
        oracle {callable} -- The oracle used.

    Keyword Arguments:
        default_prefix {bytes} -- A default prefix which will be prepended before any attack data (default: {None})
        pb {bytes} -- The default padding byte used for alignment (default: {b'\x01'})
        max_blocksize {int} -- The maximum blocksize to try (default: {3*512})

    Raises:
        RuntimeError: If the guessing routine fails. This may be caused by an plaintext containing at least one block of padding bytes (`pb`). In this case retry with a different padding byte.

    Returns:
        (int, int, int) -- the blocksize, the block offset, the padding offset respectively.
    """

    if default_prefix is None:
        default_prefix = b''

    def ask_oracle(byteslike=b''):
        return oracle(default_prefix + byteslike)

    # we do not enforce that our known prefix is encrypted at the beginning.
    # it can aswell be somewhere in the middle of the encrypted data.
    # we still call it 'prefix' because with this attack we can only decrypt
    # what is encrypted afterwards

    # in order to find the block offset we will atempt to alter the cipher text
    # and make a first guess which block our data is encrypted in
    baseline = ask_oracle()
    base_cipher_len = len(baseline)

    # !! NOTE !!
    # this routine fails if the oracle encrypts the secret text [pb] * blocksize
    # AND the text aligns with a block after our controlable prefix

    for i in range(2, max_blocksize):

        if base_cipher_len % i != 0:
            continue

        prefix = pb * i
        c = ask_oracle(prefix)

        base_blocks = list(chunks(baseline, i))
        c_blocks = list(chunks(c, i))

        diffs = infix_block_diffs(base_blocks, c_blocks)

        if len(diffs) == 1:
            # our prefix starts aligned
            blocksize = i
            padding_offset = 0
            block_offset = diffs[0]
            break

        if len(diffs) == 2:
            # our prefix is not aligned.
            blocksize = i
            block_offset = diffs[1]

            # we now have to guess the padding_offset

            # to do so we slowly reduce padding until we do not find the first diff block anymore
            # this is quite cheap, however if the encrypted text after our prefix starts with
            # our padding byte we cannot guess the offset correctly

            ref = c_blocks[diffs[0]]

            for j in range(2, i):
                prefix = pb * (i - j)
                c = ask_oracle(prefix)
                c_blocks = list(chunks(c, blocksize))

                if ref != c_blocks[diffs[0]]:
                    padding_offset = j - 1
                    break
            else:
                raise RuntimeError("Could not guess prefix offset. Attack failed. Maybe try a different padding value!")

            # offset and blocksize is found
            break
    else:
        raise RuntimeError('Could not guess block size. Attack failed. Maybe try a different padding value!')

    return blocksize, block_offset, padding_offset


def ecb_decrypt_tail(oracle, default_prefix=None, pb=b'\x01', blocklayout=None):
    r"""Performs a ECB - Known - Prefix Attack using the given oracle.

    The oracle is required to encrypt given input with the same secret key.

    This attack is able to decrypt the plaintext after the controlled prefix.

    Example:
    ```python
    >>> from bop.oracles.known_infix import KnownInfixECBOracle as Oracle
    >>> o = Oracle(head=b'Some prefix, 26 bytes long', tail=b'Very secret, very transparent text.')
    >>> decrypted, blocklayout = ecb_decrypt_tail(o)
    >>> decrypted
    b'Very secret, very transparent text.\x01'

    ```

    Arguments:
        oracle {oracle} -- The oracle, any callable which encrypts the given input with the same key.

    Keyword Arguments:
        default_prefix {bytes} -- A default prefix which will be prepended before any attack data (default: {None})
        pb {bytes} -- The default padding byte used for alignment (default: {b'\x01'})
        blocklayout {(int, int, int)} -- A tuple containing blocklayout information (blocksize, block_offset, padding_offset), the block size of the cipher in bytes, the index of the block where the attacker controlled data starts, the offset within this block where the attacker controlled data starts. If not given, the blocklayout will be guessed. (For more details see `ecb_guess_block_layout`) (default: {None})

    Returns:
        (bytes, (int, int, int)) -- The decrypted message and a tuple with the blocksize, the block offset, the padding offset respectively.
    """

    if default_prefix is None:
        default_prefix = b''

    def ask_oracle(byteslike=b''):
        return oracle(default_prefix + byteslike)

    cipher_len = len(ask_oracle())

    if blocklayout is not None:
        blocksize, block_offset, padding_offset = blocklayout
    else:
        # TODO: If we really want correct offset guessing we simply would have to do the guessing routine twice with different padding bytes
        blocksize, block_offset, padding_offset = ecb_guess_block_layout(
            oracle,
            default_prefix=default_prefix,
            pb=pb
        )

    if padding_offset > 0:
        default_prefix += pb * (blocksize - padding_offset)

    # add an initial dummy padding
    decrypted = pb * blocksize

    block_index = 0
    base_offset = block_offset * blocksize

    # for each block
    while base_offset + block_index * blocksize <= cipher_len:

        off = block_index * blocksize

        # for each byte in the block
        for n in range(blocksize):

            # this prefix cycles through our decrypted bytes
            # these are always the last 15 bytes known
            prefix = decrypted[-blocksize + 1:]

            # now we trim the prefix to align the encrypted blocks, this way we shift our
            # unknown byte to the last position of the block
            # starting at offset = block_index * blocksize
            c = ask_oracle(prefix[:blocksize - 1 - n])
            ref = c[base_offset + off:base_offset + off + blocksize]

            # test each possible byte value
            for i in range(256):
                # we now construct all possible blocks with the given prefix
                # and store the result of encryption
                c = ask_oracle(prefix + bytes([i]))
                if ref == c[base_offset:base_offset + blocksize]:
                    next_byte = i
                    break
            else:
                # this can be caused by PKCS-7 padding,
                # when trying to guess the padding bytes (because they may change)
                break
            decrypted += bytes([next_byte])

        block_index += 1

    # finally remove our initial dummy padding
    return decrypted[blocksize:], (blocksize, block_offset, padding_offset)
