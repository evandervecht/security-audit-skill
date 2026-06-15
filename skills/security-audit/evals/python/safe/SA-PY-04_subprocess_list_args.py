# SA-PY-04: Safe subprocess with argument list, no shell (SAFE)
import subprocess


def extract(archive: str):
    subprocess.run(["tar", "-xf", archive], check=True, timeout=30)
