from itertools import product
import re

from bop.data.importer import load, Res
from bop.utils import chunks, xor, hamming_dist, analyze_frequency, to_distribution, measure_similarity


__all__ = [ 'guess_key_length', 'brute_xor', 'brute_xor_multi' ]


def brute_xor(c, freq=Res.EN_freq_1):
    """Attempts to decrypt the given XOR ciphertext using frequency analysis.

    It is assumed that the given ciphertext was encrypted using XOR with a key of length 1.
    If this is not given you may want to use `brute_xor_multi`.

    Example:
    ```python
    >>> plain = b'Hello my name is Bop. We just have to make sure that this text is somewhat lengthy. You know. Stuff. Foo.'
    >>> key = 27
    >>> cipher = bytes(map(lambda x: x ^ key, plain))
    >>> score, guessed_key = brute_xor(cipher)[0]
    >>> guessed_key
    27

    ```

    Arguments:
        c {bytes} -- The ciphertext

    Returns:
        list -- List of (score, key) pairs. Best score first.
    """
    results = []
    frequency_distribution = load(freq)
    for key in range(0, 255):
        p = xor(c, key)

        f = analyze_frequency(p)
        d = to_distribution(f)

        results.append((measure_similarity(frequency_distribution, d), key))

    results.sort()
    return results


def brute_xor_multi(c, keylength=None, freq=Res.EN_freq_1, **kvargs):
    """Attempts to decrypt the given XOR ciphertext using frequency analysis

    Examples:
    ```python
    >>> plain = b'Hello my name is Bop. We just have to make sure that this text is somewhat lengthy.'
    >>> key = (27, 134)
    >>> cipher = bytes(map(lambda x: key[x[0] % 2] ^ x[1], enumerate(plain)))
    >>> score, guessed_key = brute_xor_multi(cipher, keylength=2)[0]
    >>> guessed_key
    [27, 134]

    ```
    Or even attempt to guess the keylength:
    ```python
    >>> plain = b'We can even break mutli byte XOR encryption without knowing the size of the key. Though we may be required to provide even lengthier ciphertexts. But even if the key is not one hundred percent on point you will still get an idea of the plaintext eventually.'
    >>> key = (123, 45, 89)
    >>> cipher = bytes(map(lambda x: key[x[0] % 3] ^ x[1], enumerate(plain)))
    >>> score, guessed_key = brute_xor_multi(cipher)[0]
    >>> guessed_key
    [123, 45, 89]

    ```

    Arguments:
        c {bytes} -- The ciphertext

    Keyword Arguments:
        keylength {int} -- The length of the key used. Will be guessed using `guess_key_length` if `None` (default: {None})
        freq {Res or dict} -- Reference frequency distribution

    Additional `kvargs` may be passed when `keylength=None`, i.e. a guessing of keylength is attempted:
        prefer_short {bool} -- Occasionally guessing the key length suggest longer keys than actually required. This will result in cyclic keys. If this flag is set to `True` an attempt is made to detect such cyclic keys and reduce them to minimum length. (default: {True})
    Any other argument will be passed to `guess_key_length`.

    Returns:
        list -- List of (score, key) pairs. Best score first.
    """

    prefer_short = kvargs.pop('prefer_short', True)

    if keylength is None:
        keylength = guess_key_length(c, **kvargs)[0]
        if prefer_short:
            # TODO we may improve the guessing routine further if this cycle pattern does fuzzy matching
            cycle_pattern = re.compile(br'^(.*?)(\1)+$')
    else:
        prefer_short = False

    blocks = chunks(c, keylength, fillvalue=0)

    keyparts = [ [] for _ in range(keylength) ]

    # transpose blocks and brute force each (corresponding to the same single key)
    for i, c_block in enumerate(zip(*blocks)):
        result = brute_xor(c_block, freq=freq)

        keyparts[i].append((result[0][0], result[0][1]))
        # keyparts[i].append((result[1][0], result[1][1]))

    possible_keys = []
    # iterate over possible key compositions
    for keypart in product(*keyparts):
        # keypart = [ (part_score, key) ] * keylength
        score = sum(map(lambda x: x[0], keypart)) / len(keypart)
        key = list(map(lambda x: x[1], keypart))

        if prefer_short:
            m = cycle_pattern.match(bytes(key))
            if m:
                key = list(map(int, m.group(1)))

        possible_keys.append((score, key))

    # sort by best score
    possible_keys.sort()

    return possible_keys


def eval_key_length(c, keylength, depth=-1):
    """Determines a score which represents how likely the given keylength for the given cipher is.

    The key length is evaluated by editing - distance (hamming distance).

    Arguments:
        c {bytes} -- The ciphertext
        keylength {int} -- The keylength to evaluate

    Keyword Arguments:
        depth {int} -- Scoring is done by comparing consecutive blocks. This argument specifies the number of consecutive blocks to use. -1 for all available. (default: {-1})

    Returns:
        float -- Score of this keylength (lower is better)
    """
    dist = 0
    sample_count = 0
    pairs_of_chunks = chunks(
        chunks(c, keylength, fillvalue=0),
        2
    )

    real_depth = depth
    if depth == -1:
        real_depth = len(c) // keylength + 1

    for (_, (chunk1, chunk2)) in zip(range(real_depth), pairs_of_chunks):
        if chunk1 is None or chunk2 is None:
            break

        dist += hamming_dist(chunk1, chunk2)
        sample_count += 1

    if sample_count == 0:
        return None

    return dist / sample_count / keylength


def guess_key_length(c, start=2, stop=40, depth=-1):
    """Attempts to guess the keylength for the given ciphertext `c`

    Arguments:
        c {bytes} -- The ciphertext

    Keyword Arguments:
        start {int} -- Minimal key length to check (inclusive) (default: {2})
        stop {int} -- Maximum key length to check (exclusive) (default: {40})
        depth {int} -- Scoring is done by comparing consecutive blocks. This argument specifies the number of consecutive blocks to use. -1 for all available. (default: {-1})

    Returns:
        list -- List of possible key lengths in descending order by likelihood
    """
    rv = []
    for keylength in range(start, stop):

        eval_result = eval_key_length(c, keylength, depth=depth)
        if eval_result is None:
            break

        rv.append((eval_result, keylength))

    rv.sort()
    return list(map(lambda x: x[1], rv))
