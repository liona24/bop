import binascii

from rng.mt19937 import seed


def _int_from_bytes(byteslike):
    return int(binascii.hexlify(byteslike), 16)


def encrypt(key, plaintext):
    keystream = seed(_int_from_bytes(key))

    cipher = []
    for (x, byte) in zip(keystream, plaintext):
        cipher.append(bytes([(x % 256) ^ int(byte)]))

    return b''.join(cipher)


def decrypt(key, ciphertext):
    return encrypt(key, ciphertext)
