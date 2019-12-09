import string
import os
from collections import Counter
from itertools import product
import math
import json

from utils import n_grams, chunks, xor, hamming_dist


__all__ = [ 'guess_key_length', 'brute_xor', 'brute_xor_multi' ]


PRINTABLE = set(map(ord, string.printable))

__folder__ = os.path.dirname(__file__)

with open(os.path.join(__folder__, '../freq_en_1.json'), 'r') as f:
    FREQ_EN_1 = json.load(f)


def analyze_frequency(buffer, n=1):
    """Analyze the frequency of n-grams in the given buffer.

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

    Arguments:
        counter {Counter} -- Counter interpreted as histogram

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
    """Returns all non - printable characters available in `buffer`

    Arguments:
        buffer {iterable} -- Iterable of characters

    Returns:
        set -- Non-printable characters of buffer
    """
    return set(buffer) - PRINTABLE


def brute_xor(c):
    """Attempts to decrypt the given XOR ciphertext using frequency analysis.

    It is assumed that the given ciphertext was encrypted using XOR with a key of length 1.
    If this is not given you may want to use `brute_xor_multi`.

    TODO: This currently only works for the english language.

    Arguments:
        c {bytes} -- The ciphertext

    Returns:
        list -- List of (score, key) pairs. Best score first.
    """
    results = []
    for key in range(0, 255):
        p = xor(c, key)

        f = analyze_frequency(p)
        d = to_distribution(f)

        results.append((measure_similarity(FREQ_EN_1, d), key))

    results.sort()
    return results


def brute_xor_multi(c, keylength=None):
    """Attempts to decrypt the given XOR ciphertext using frequency analysis

    Arguments:
        c {bytes} -- The ciphertext

    Keyword Arguments:
        keylength {int} -- The length of the key used. Will be guessed if `None` (default: {None})

    Returns:
        list -- List of (score, key) pairs. Best score first.
    """

    if keylength is None:
        keylength = guess_key_length(c, depth=8)[0]
        print('Guessed keylength = %d' % keylength)

    blocks = chunks(c, keylength, fillvalue=0)

    keyparts = [ [] for _ in range(keylength) ]

    # transpose blocks and brute force each (corresponding to the same single key)
    for i, c_block in enumerate(zip(*blocks)):
        result = brute_xor(c_block)

        keyparts[i].append((result[0][0], result[0][1]))
        # keyparts[i].append((result[1][0], result[1][1]))

    possible_keys = []
    # iterate over possible key compositions
    for keypart in product(*keyparts):
        # keypart = [ (part_score, key) ] * keylength
        score = sum(map(lambda x: x[0], keypart)) / len(keypart)
        key = list(map(lambda x: x[1], keypart))
        possible_keys.append((score, key))

    # sort by best score
    possible_keys.sort()

    return possible_keys


def eval_key_length(c, keylength, depth=1):
    """Determines a score which represents how likely the given keylength for the given cipher is.

    Arguments:
        c {bytes} -- The ciphertext
        keylength {int} -- The keylength to evaluate

    Keyword Arguments:
        depth {int} -- Scoring is done by comparing consecutive blocks. This argument specifies the number of consecutive blocks to use. -1 for all available. (default: {1})

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


def guess_key_length(c, start=2, stop=40, depth=1):
    """Attempts to guess the keylength for the given ciphertext `c`

    Arguments:
        c {bytes} -- The ciphertext

    Keyword Arguments:
        start {int} -- Minimal key length to check (inclusive) (default: {2})
        stop {int} -- Maximum key length to check (exclusive) (default: {40})
        depth {int} -- Scoring is done by comparing consecutive blocks. This argument specifies the number of consecutive blocks to use. -1 for all available. (default: {1})

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
