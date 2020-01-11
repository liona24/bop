from collections import namedtuple

__all__ = [ 'seed', 'P32', 'P64', 'from_observed_sequence' ]


Params = namedtuple('Params', ['w', 'n', 'm', 'r', 'a', 'u', 'd', 's', 'b', 't', 'c', 'i', 'f'])


P32 = Params(
    w=32,
    n=624,
    m=397,
    r=31,

    a=0x9908b0df,

    u=11,
    d=0xffffffff,

    s=7,
    b=0x9d2c5680,

    t=15,
    c=0xefc60000,

    i=18,

    f=1812433253,
)

P64 = Params(
    w=64,
    n=312,
    m=156,
    r=31,

    a=0xB5026F5AA96619E9,

    u=29,
    d=0x5555555555555555,

    s=17,
    b=0x71D67FFFEDA60000,

    t=37,
    c=0xFFF7EEE000000000,

    i=43,

    f=1812433253,
)


class MersenneTwisterRng(object):
    def __init__(self, mt, index, seed, params):
        self.mt = mt
        self.index = index
        self.seed = seed
        self.params = params

    def _twist(self):
        n = self.params.n
        m = self.params.m
        w = self.params.w
        r = self.params.r
        a = self.params.a

        l_mask = (1 << r) - 1
        u_mask = ((1 << w) - 1) & ~l_mask

        mt = self.mt
        for i in range(n):
            x = (mt[i] & u_mask) + (mt[(i+1) % n] & l_mask)
            xA = x >> 1
            if x % 2 != 0:
                xA = xA ^ a
            mt[i] = mt[(i+m) % n] ^ xA

        self.index = 0

    def skip_ahead(self, n):
        for _ in range(n):
            next(self)

    def to_std_random(self):
        import random
        rv = random.Random()
        mt = self.mt.copy()
        rv.setstate((3, mt + [self.index], None))

        return rv

    def __iter__(self):
        return self

    def __next__(self):
        if self.index >= self.params.n:
            self._twist()

        y = self.mt[self.index]

        y = y ^ ((y >> self.params.u) & self.params.d)
        y = y ^ ((y << self.params.s) & self.params.b)
        y = y ^ ((y << self.params.t) & self.params.c)
        y = y ^ (y >> self.params.i)

        self.index += 1

        return ((1 << self.params.w) - 1) & y


def seed(seed, params=P32):
    """Return a new MersenneTwister Pseudo RNG seeded with the given value.

    Arguments:
        seed {int} -- The seed value to use

    Keyword Arguments:
        params {Params} -- Params to use for the MersenneTwister algorithm (default: {P32})

    Returns:
        MersenneTwisterRng -- The seeded random number generator
    """

    mask = (1 << params.w) - 1

    seed &= mask

    mt = [ seed ]

    for i in range(1, params.n + 1):
        x_i = mask & (params.f * ( mt[-1] ^ (mt[-1] >> (params.w - 2))) + i)

        mt.append(x_i)

    return MersenneTwisterRng(mt, params.n, seed, params)


def inv_left_shift(x, n, mask, bitcount=32):
    rv = x
    for _ in range(bitcount):
        rv = x ^ ((rv << n) & mask)
    return rv


def inv_right_shift(x, n, mask, bitcount=32):
    rv = x
    for _ in range(bitcount):
        rv = x ^ ((rv >> n) & mask)
    return rv


def from_observed_sequence(sequence, params=P32):
    """Recover a rng state from a given observed sequence

    Note that the sequence is required to be at least `params.n` elements long.
    The returned RNG's first element generated will be the next one after the given
    sequence ends.

    Example:
    ```python
    >>> rng1 = seed(1010101)
    >>> sequence = [ next(rng1) for _ in range(1929) ]
    >>> rng2 = from_observed_sequence(sequence)
    >>> assert (next(rng1) == next(rng2))

    ```

    Arguments:
        sequence {list} -- List of integers, the observed random numbers

    Keyword Arguments:
        params {Params} -- The parameters for the Mt19937 algorithm to use (default: {P32})

    Raises:
        ValueError: If the sequence is not large enough

    Returns:
        MersenneTwisterRng -- A random number generator with same sequence as the one generating sequence
    """
    if len(sequence) < params.n:
        raise ValueError(f'sequence: Invalid length! Should be >= {params.n} (is {len(sequence)})')

    w = params.w

    mt = []

    for x in sequence[-params.n:]:

        x = inv_right_shift(x, params.i, (1 << w) - 1, bitcount=w)
        x = inv_left_shift(x, params.t, params.c, bitcount=w)
        x = inv_left_shift(x, params.s, params.b, bitcount=w)
        x = inv_right_shift(x, params.u, params.d, bitcount=w)

        mt.append(x)

    rng = MersenneTwisterRng(mt, params.n, None, params)

    return rng
