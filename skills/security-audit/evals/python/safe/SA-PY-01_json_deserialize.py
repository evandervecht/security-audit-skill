# SA-PY-01: Safe deserialization using JSON (SAFE)
import json

def load_session(data: str):
    return json.loads(data)
