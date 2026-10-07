# SA-PY-01: Safe deserialization using json (SAFE)
import json

pickle_path = "/var/run/session.json"  # near-miss: the word "pickle" in a variable name


def load_session(raw: str):
    return json.loads(raw)
