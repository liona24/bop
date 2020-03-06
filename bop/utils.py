import math
import string
from collections import defaultdict, deque, Counter
from itertools import zip_longest, islice, cycle
import cryptography.hazmat.primitives.padding as padding
import time
import binascii

try:
    now = time.time_ns
except AttributeError:
    now = time.time

PRINTABLE = set(map(ord, string.printable))


def infix_block_diffs(a, b):
    """Find the first infix missmatch between the given iterables.

    This function greedily matches the given iterators until a missmatch occurs.
    It will then try to exhaust this missmatch until the sequences match again.
    Check the example for further clarification.

    Example:
    ```python
    >>> a = [1, 2, 3, 6, 7, 8]
    >>> b = [1, 2, 4, 5, 6, 7, 8]
    >>> infix_block_diffs(a, b)
    [2, 3]

    ```

    Arguments:
        a {iterable} -- The first iterator to match
        b {iterable} -- The second iterator to match

    Returns:
        list -- List of indices where a missmatch occured.
    """
    # This method performs a somewhat fancy computation, though I cannot remember
    # why I chose it to. Eventually it'll get back to me..

    blocks = defaultdict(deque)
    for i, x in enumerate(a):
        blocks[x].append(i)

    it_b = iter(b)
    for i, x in enumerate(it_b):
        # iter until we do not match anymore

        if len(blocks[x]) > 0 and blocks[x][0] == i:
            blocks[x].popleft()
        else:
            first_miss = i
            break
    else:
        # no unmatched blocks
        return []

    rv = [ first_miss ]

    for i, x in enumerate(it_b, 1):
        if len(blocks[x]) > 0 and blocks[x][0] in [first_miss + 1, first_miss]:
            # try to find the next matching block in a
            break
        rv.append(first_miss + i)

    # we assume that the rest matches, because there should only be an infix missmatch
    return rv


def chunks(iterable, n, fillvalue=None):
    """Generator to yield equal sized chunks from the given iterable

    Example:
    ```python
    >>> iterable = [1, 2, 3, 4, 5]
    >>> list(chunks(iterable, 2, fillvalue=-1))
    [(1, 2), (3, 4), (5, -1)]

    ```

    Arguments:
        iterable {iterable} -- The iterable to drain
        n {int} -- The size of each chunk

    Keyword Arguments:
        fillvalue {any} -- The fill value to use if the iterable cannot be evenly distributed into n-sized chunks (default: {None})

    Yields:
        tuple -- Tuple of size `n` with elements from `iterable`
    """
    its = [ iter(iterable) ] * n
    yield from zip_longest(*its, fillvalue=fillvalue)


def n_grams(iterable, n):
    """Generator to yield n-grams from the given iterable

    Example
    ```python
    >>> iterable = [1, 2, 3, 4]
    >>> list(n_grams(iterable, 2))
    [(1, 2), (2, 3), (3, 4)]

    ```

    Arguments:
        iterable {iterable} -- The iterable to drain
        n {int} -- Size of each gram

    Yields:
        tuple -- Tuple of size `n` with elements from `iterable`
    """
    it = iter(iterable)
    d = deque(islice(it, n))
    yield tuple(d)
    for x in it:
        d.popleft()
        d.append(x)
        yield tuple(d)


def pad(*parts, blocksize=16, mode='pkcs7'):
    r"""Combines the given portions of data and pads them using the given scheme.

    Example:
    ```python
    >>> a = b'ABC'
    >>> b = b'DEFGH'
    >>> pad(a, b, blocksize=16, mode='pkcs7')
    b'ABCDEFGH\x08\x08\x08\x08\x08\x08\x08\x08'

    ```

    Keyword Arguments:
        blocksize {int} -- The desired blocksize in bytes (default: {16})
        mode {str} -- The padding scheme to use. Case insensitive. The available schemes are the ones supported be the cryptography module (https://cryptography.io/en/latest/hazmat/primitives/padding/#cryptography.hazmat.primitives.padding) (default: {'pkcs7'})

    Returns:
        bytes -- The padded data block
    """

    padding_scheme = getattr(padding, mode.upper(), None)
    if padding_scheme is None:
        raise ValueError(f"The given padding scheme '{mode}' is not supported!")

    padder = padding_scheme(blocksize * 8).padder()
    data = b''
    for p in parts:
        if len(p) > 0:
            data += padder.update(p)

    return data + padder.finalize()


def is_padding_valid(byteslike, mode='pkcs7'):
    """Checks whether the padding is valid in the given bytes-like object.

    Arguments:
        byteslike {byteslike} -- The blob to check

    Keyword Arguments:
        mode {str} -- The padding mode to check for (default: {'pkcs7'})

    Returns:
        bool -- `True` if the padding is valid, `False` if it is invalid.
    """
    pad_byte = byteslike[-1]

    if int(pad_byte) == 0 or int(pad_byte) > 16:
        return False

    for (_, b) in zip(range(int(pad_byte)), reversed(byteslike)):
        if b != pad_byte:
            return False

    return True


def find_dup_blocks(byteslike, blocksize=16):
    r"""Finds duplicate blocks in the given bytes-like object

    Example:
    ```python
    >>> blob = b'ABCmamABClklmamABC'
    >>> # tuple(b'ABC') = (65, 66, 67)
    >>> # tuple(b'mam') = (109, 97, 109)
    >>> find_dup_blocks(blob, blocksize=3)
    [(3, (65, 66, 67)), (2, (109, 97, 109))]

    ```

    Arguments:
        byteslike {byteslike} -- The collection of bytes to search

    Keyword Arguments:
        blocksize {int} -- The size of each block in bytes (default: {16})

    Returns:
        list of (int, bytes) -- The list of non-unique blocks found and their occurence count, sorted by frequency
    """

    count_repetitions = Counter(chunks(byteslike, blocksize, fillvalue=0))
    dups = [
        (count_repetitions[key], key) for key in count_repetitions if count_repetitions[key] > 1
    ]

    dups.sort(reverse=True)

    return dups


def hamming_dist(x, y):
    """Compute the hamming distance of the given iterables of `int`

    Examples:
    ```python
    >>> x = [1, 2, 3]
    >>> y = [1, 2]
    >>> hamming_dist(x, y)
    2

    ```

    Arguments:
        x {iterable} -- The first sequence
        y {iterable} -- The second sequence

    Returns:
        int -- The accumulated hamming distance
    """
    d = 0
    for bx, by in zip_longest(x, y, fillvalue=0):
        d += bin(bx ^ by).count('1')
    return d


def xor(buffer, x):
    r"""Compute the XOR of the given operands

    The second operand may either be a single value or a list-like of values.
    If so, it will be applied cyclicly.

    Examples:
    ```python
    >>> a = bytes(b'abcd')
    >>> b = 10
    >>> xor(a, b)
    b'khin'

    ```

    ```python
    >>> a = bytes(b'abcdefgh')
    >>> b = bytes(b'abcd')
    >>> xor(a, b)
    b'\x00\x00\x00\x00\x04\x04\x04\x0c'

    ```

    Arguments:
        buffer {byteslike} -- The first operand
        x {int or list of int} -- The second operand

    Returns:
        bytes -- The result of the XOR operation
    """
    try:
        it = cycle(x)
    except TypeError:
        it = cycle([x])

    return bytes([op1 ^ op2 for op1, op2 in zip(buffer, it)])


def analyze_frequency(buffer, n=1):
    """Analyze the frequency of n-grams in the given buffer.

    Example:
    ```python
    >>> a = b'ABAABCCBAABA'
    >>> analyze_frequency(a, n=1)
    Counter({(65,): 6, (66,): 4, (67,): 2})

    ```

    Or similiar with `n=2`:

    ```python
    >>> a = b'ABABA'
    >>> analyze_frequency(a, n=2)
    Counter({(65, 66): 2, (66, 65): 2})

    ```

    Arguments:
        buffer {iterable} -- Iterable of bytes

    Keyword Arguments:
        n {int} -- The size of the n-grams to evaluate (default: {1})

    Returns:
        Counter -- Counter object containing occurence counts of each n-gram
    """
    return Counter(n_grams(buffer, n))


def to_distribution(counter):
    """Helper method to transform a frequency histogram to a probability distribution

    Example:
    ```python
    >>> counts = analyze_frequency(b'aabbbccccc')
    >>> to_distribution(counts)
    {'a': 0.2, 'b': 0.3, 'c': 0.5}

    ```

    Arguments:
        counter {Counter} -- Counter interpreted as histogram. Keys should be given as `int`

    Returns:
        dict -- Dictionary containing (key, probability)
    """
    rv = {}
    total = sum(counter.values())
    for key in counter:
        rv[''.join(map(chr, key))] = counter[key] / total

    return rv


def measure_similarity(d1, d2):
    """Calculates similarity of two discrete distributions.

    Similiarity is measured by the Kullback - Leibler - Divergence (https://en.wikipedia.org/wiki/Kullback%E2%80%93Leibler_divergence)

    The distributions are assumed to be given as dictionaries.

    Arguments:
        d1 {dict} -- The first distribution
        d2 {dict} -- The second distribution

    Returns:
        float -- Resulting similarity score.
    """
    kl = 0
    for key in d1:
        p = d1.get(key, 0)
        q = max(1e-7, d2.get(key, 0))
        kl += p * math.log2(p / q)
    return kl


def non_printable_chars(buffer):
    r"""Returns all non - printable characters available in `buffer`

    Example:
    ```python
    >>> a = b'\x01\x12ABC\x12109+#\t'
    >>> expected = { 0x01, 0x12 }
    >>> assert (non_printable_chars(a) == expected)

    ```

    Arguments:
        buffer {iterable} -- Iterable of characters

    Returns:
        set -- Non-printable characters of buffer
    """
    return set(buffer) - PRINTABLE


def time_it(x, *args, **kvargs):
    """Time the call to callable `x`

    All `args` and `kvargs` are passed to the function call, i.e. `x(*args, **kvargs)`

    Arguments:
        x {callable} -- The function to measure execution time of

    Returns:
        (float, Any) -- The measured execution time and the results returned by the callable
    """
    start = now()
    rv = x(*args, **kvargs)
    stop = now()

    return stop - start, rv


def argmax(iterable):
    """Return the index of the maximum element of the given iterable

    Example:
    ```python
    >>> argmax([1, 2, 3, 4, 4, 4])
    3

    ```

    Arguments:
        iterable {iterable} -- The iterable to consume

    Returns:
        int -- The index of the maximum element
    """
    it = iter(iterable)
    mx = next(it)
    i = 0
    for j, v in enumerate(it, 1):
        if v > mx:
            mx = v
            i = j

    return i


def invmod(u, v):
    """Calculate the multiplicative inverse of `u mod v`

    This function is taken from [here](https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/Util/number.py).

    Example:
    ```python
    >>> invmod(3, 7)
    5
    >>> invmod(19129, 128121291)
    1024756

    ```

    Arguments:
        u {int} -- u
        v {int} -- v

    Returns:
        int -- Multiplicative inverse `x` such that `(1 == u*x) mod v`
    """
    u3, v3 = u, v
    u1, v1 = 1, 0
    while v3 > 0:
        q = divmod(u3, v3)[0]
        u1, v1 = v1, u1 - v1 * q
        u3, v3 = v3, u3 - v3 * q
    while u1 < 0:
        u1 = u1 + v
    return u1


def cubic_root(x):
    """Calculates the cubic integer root of `x`

    Examples:
    ```python
    >>> cubic_root(1818*1818*1818)
    1818
    >>> cubic_root(3*3*5*5*7*7) is None
    True

    ```

    Returns:
        int -- The cubic root of `x`
    """
    rv = cubic_root2(x)
    if len(rv) != 1:
        return None
    else:
        return rv[0]


def cubic_root2(x):
    """Calculate the cube root of `x`. If `x` is not a perfect cube return the best candidates.

    Examples:
    ```python
    >>> cubic_root2(1818*1818*1818)
    [1818]
    >>> cubic_root2(7*7*7 - 1)
    [6, 7]

    ```

    This is a slight variant of `cubic_root`. Instead of returning `None` if no
    root exists the two best candidates are returned.

    The smaller candidate is always returned first.

    Returns:
        list -- The cubic root of `x` or the two closest candidates
    """
    low, high = 0, x
    last_results = [0, 0]
    parity = 0

    while True:
        root = (low + high) // 2
        cube = root * root * root

        if cube == x:
            return [root]
        if last_results[parity ^ 1] == root:
            return sorted(last_results)

        if cube > x:
            high = root
        else:
            low = root

        last_results[parity] = root
        parity ^= 1


def i2b(integer):
    r"""Convert an integer into big-endian byte representation

    ```python
    >>> i2b(11)
    b'\x0b'

    ```

    Raises:
        ValueError: If the given number is negative

    Returns:
        bytes -- The byte representation
    """
    if integer < 0:
        raise ValueError("Requires non-negative integer")

    hx = hex(integer)[2:]
    if len(hx) % 2 != 0:
        hx = "0" + hx
    return binascii.unhexlify(hx)


def b2i(bytes):
    r"""Convert a big-endian bytes object into its integer representation

    Example:
    ```python3
    >>> b2i(b"\x0a")
    10

    ```

    Returns:
        int -- The converted integer
    """
    return int(binascii.hexlify(bytes), 16)
