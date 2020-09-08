import hashlib


def sha256(data=None):
    r"""Initialize a new SHA256 hash object or quickly generate a SHA1 hash

    Example:
    ```python
    >>> h = sha256()
    >>> h.update(b'Hello World!')
    >>> h.digest()
    b'\x7f\x83\xb1e\x7f\xf1\xfcS\xb9-\xc1\x81H\xa1\xd6]\xfc-K\x1f\xa3\xd6w(J\xdd\xd2\x00\x12m\x90i'

    ```
    Or quickly generate a SHA256 hash if the hash object is not needed:
    ```python
    >>> sha256(b'Hello World!')
    b'\x7f\x83\xb1e\x7f\xf1\xfcS\xb9-\xc1\x81H\xa1\xd6]\xfc-K\x1f\xa3\xd6w(J\xdd\xd2\x00\x12m\x90i'

    ```

    Returns:
        hashlib.sha256 or bytes-- A new SHA256 hash object or a SHA256 digest if data was provided
    """
    h = hashlib.sha256()
    if data is None:
        return h

    h.update(data)
    return h.digest()
