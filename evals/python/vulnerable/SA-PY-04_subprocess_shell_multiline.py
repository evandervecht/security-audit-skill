# SA-PY-04: Command injection via subprocess shell=True split across lines (VULNERABLE)
import subprocess


def extract(archive: str):
    subprocess.Popen(
        f"tar -xf {archive}",
        shell=True,
    )
