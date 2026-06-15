# SA-PY-01: Insecure deserialization via cPickle / Unpickler (VULNERABLE)
import _pickle as cPickle


def load_session(data: bytes):
    # Untrusted bytes deserialized via the C accelerator module -- arbitrary code execution risk
    return cPickle.loads(data)
