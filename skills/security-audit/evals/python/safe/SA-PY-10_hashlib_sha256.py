# SA-PY-10: Strong hash algorithm SHA-256 with HMAC (SAFE)
import hashlib
import hmac

def verify_integrity(data: bytes, key: bytes, expected: str) -> bool:
    computed = hmac.new(key, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, expected)
