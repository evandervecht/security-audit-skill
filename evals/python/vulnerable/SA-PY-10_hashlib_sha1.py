# SA-PY-10: Weak hash algorithm SHA1 (VULNERABLE)
import hashlib

def verify_integrity(data: bytes, expected: str) -> bool:
    return hashlib.sha1(data).hexdigest() == expected
