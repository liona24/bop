from bop.utils import time_it, argmax


def guess_sequence_insecure_compare(sequence_length, insecure_comparer, n=1):
    """Guess a sequence of bytes based on timing leaks of the given comparer.

    This is a generic attack which leverages the fact that a comparer is insecure if it is exiting early if sequence-missmatches occur at the beginning of the input sequences.\
    This can also be used to guess HMACs or the like.

    Consider the simple example below:
    ```python
    >>> import time
    >>> def cmp(password):
    ...     for a, b in zip(password, b'SECRET'):
    ...         if a != b:
    ...             return False
    ...         time.sleep(0.002)
    ...     return True
    >>> guess_sequence_insecure_compare(6, cmp, n=5)
    b'SECRET'

    ```

    Arguments:
        sequence_length {int} -- The length of the sequence to guess
        insecure_comparer {callable} -- A function which performs the insecure comparison. Only one argument is passed, the currently guessed sequence.

    Keyword Arguments:
        n {int} -- The number of trials per byte guessed. (default: {1})

    Returns:
        bytes -- The sequence of bytes guessed.
    """

    sequence = bytearray([0] * sequence_length)

    for i in range(sequence_length):
        timings = [0] * 255

        for _ in range(n):
            for value in range(255):
                sequence[i] = value
                delay, _ = time_it(insecure_comparer, sequence)
                timings[value] += delay

        sequence[i] = argmax(timings)

    return bytes(sequence)
