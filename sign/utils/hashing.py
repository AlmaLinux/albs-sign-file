import hashlib


def hash_file(file_path, hasher=None, buff_size=1048576):
    """
    Returns checksum (hexadecimal digest) of the file.

    Parameters
    ----------
    file_path : str or file-like
        File to hash. It could be either a path or a file descriptor.
    hasher : hashlib.Hasher
        Any hash algorithm from hashlib.
    buff_size : int
        Number of bytes to read at once.

    Returns
    -------
    str
        Checksum (hexadecimal digest) of the file.
    """
    if hasher is None:
        hasher = get_hasher()

    def feed_hasher(_fd):
        buff = _fd.read(buff_size)
        while len(buff):
            if not isinstance(buff, bytes):
                buff = buff.encode('utf')
            hasher.update(buff)
            buff = _fd.read(buff_size)

    if isinstance(file_path, str):
        with open(file_path, "rb") as fd:
            feed_hasher(fd)
    else:
        file_path.seek(0)
        feed_hasher(file_path)
    return hasher.hexdigest()


def get_hasher():
    """
    Returns a corresponding hashlib hashing function for the specified checksum
    type.

    Returns
    -------
    _hashlib.HASH
        Hashlib hashing function.
    """
    return hashlib.new('sha256')
