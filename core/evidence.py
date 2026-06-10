import hashlib

def generate_sha256_hash(file_bytes):
    """
    Takes raw file bytes and returns a SHA-256 hash to legally prove 
    the digital evidence wasn't tampered with during the automated triage.
    """
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_bytes)
    return sha256_hash.hexdigest()