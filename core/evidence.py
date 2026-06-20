import hashlib

def generate_sha256_hash(file_bytes):
    """
    Generates a cryptographically secure SHA-256 hash of the uploaded PDF 
    to prove the evidence was not tampered with.
    """
    return hashlib.sha256(file_bytes).hexdigest()