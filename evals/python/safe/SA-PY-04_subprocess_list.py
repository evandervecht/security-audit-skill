# SA-PY-04: Safe subprocess with argument list, no shell (SAFE)
import subprocess

def ping_host(hostname: str):
    subprocess.run(["ping", "-c", "1", hostname], capture_output=True, timeout=10)
