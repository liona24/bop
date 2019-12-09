from ..src.utils import analyze_frequency, to_distribution
import json
import re
import sys

pat_punctuation = re.compile(r'[^A-Z a-z]')


def only_ascii(text):
    for c in text:
        if not pat_punctuation.match(c):
            yield c


def lower(iterable):
    for c in iterable:
        yield c.lower()


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <FILE> <N>")
        print("\tSpecify a text file to generate frequencies from and the depth, i.e. N=1 for single letter frequencies, N=2 for single letter frequencies and two letter frequencies etc.")
        sys.exit(1)

    n = int(sys.argv[2])

    with open(sys.argv[1], 'r') as f:
        text = f.read()

    text = list(lower(only_ascii(text)))
    for i in range(n):
        print(f"Analyzing {i+1}-grams ..")
        f = analyze_frequency(text, n=i+1)
        dist = to_distribution(f)

        with open(sys.argv[1] + f'.f{i+1}.json', 'w') as dst_f:
            json.dump(dist, dst_f)

    print("Done.")
