"""File hashing with a bounded-memory fallback for older Python versions."""

import hashlib


def sha256_file(fileobj):
    file_digest = getattr(hashlib, 'file_digest', None)
    if file_digest is not None:
        return file_digest(fileobj, 'sha256').hexdigest()

    digest = hashlib.sha256()
    while True:
        chunk = fileobj.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()
