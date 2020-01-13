import struct
from bop.hash.sha1 import Sha1Hash, sha1_padding


def sha1_length_extension(original_message_length, original_message_hash, payload):
    r"""Performs a length extension attack on a signature (MAC) created using SHA1

    This attack allows (nearly) arbitrary data to be appended to a signed
    message and still generate a (falsely) trusted signature.

    Example:
    ```python
    >>> import secrets
    >>> from bop.hash.sha1 import sha1
    >>> key = secrets.token_bytes(12)
    >>> msg = b'Hello. This is trusted data.'
    >>> signature = sha1(key + msg)
    >>> # Note that the secret key is not required to forge the signature
    >>> forged_signature, extension = sha1_length_extension(len(msg) + 12, signature, b'Quite easy, right?')
    >>> msg + extension
    b'Hello. This is trusted data.\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01@Quite easy, right?'
    >>> assert (forged_signature == sha1(key + msg + extension))

    ```

    Arguments:
        original_message_length {int} -- The length of the originally signed message. Might need to guessed.
        original_message_hash {bytes} -- The signature of the original message. This should be 20 bytes for SHA1.
        payload {bytes} -- The data to append to the message.

    Returns:
        (bytes, bytes) -- The new signature and the actual data to append to the original message.
    """
    padding = sha1_padding(original_message_length)

    h0 = struct.unpack('>I', original_message_hash[0:4])[0]
    h1 = struct.unpack('>I', original_message_hash[4:8])[0]
    h2 = struct.unpack('>I', original_message_hash[8:12])[0]
    h3 = struct.unpack('>I', original_message_hash[12:16])[0]
    h4 = struct.unpack('>I', original_message_hash[16:20])[0]

    h = Sha1Hash(h0=h0, h1=h1, h2=h2, h3=h3, h4=h4)
    h.message_length = original_message_length + len(padding)

    h.update(payload)
    digest = h.digest()

    return digest, padding + payload
