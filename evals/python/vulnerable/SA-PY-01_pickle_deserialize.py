# SA-PY-01: Insecure deserialization via pickle (VULNERABLE)
import pickle

def load_session(data: bytes):
    return pickle.loads(data)
