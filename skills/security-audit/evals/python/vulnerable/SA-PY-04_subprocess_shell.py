# SA-PY-04: Command injection via subprocess shell=True (VULNERABLE)
import subprocess

def ping_host(hostname: str):
    subprocess.call(f"ping -c 1 {hostname}", shell=True)
