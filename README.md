bop
===

# Introduction

**bop** is a collection of (historical) cryptographic attack-vectors and associated utilities.
It loosely follows the Cryptopals Challenges put together [here](https://cryptopals.com/).

It is meant for anyone who is willing to learn something about cryptographic attacks.
This library is meant to be explored by browsing through the code.
Pretty much every function is documented and provides an example alongside.

The library has also proven valuable for solving simple CTF-like tasks.

# Quickstart

In order to run the code you may want to install the dependencies:
```bash
$ pip3 install -r requirements.txt
```

Or you can also install the package to your current environment:
```bash
$ pip3 install .
```

Then simply import anything along the way:
```python3
>>> from bop.attacks.sym.xor import brute_xor
>>> possible_keys = brute_xor(b'_r{{x7|~ys7dcevypre6')
>>> # each of them is a tuple of the form (confidence, key)
>>> possible_keys[0][1]
23
```

# Development Setup

Running the tests requires installation of `pytest` (install through `requirements-dev.txt` or via `pip install -e '.[debug]'`)

```bash
$ pytest --doctest-modules --doctest-continue-on-failure --ignore=scripts
```
