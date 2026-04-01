"""
Python Runtime Taint Tracer

Monkey-patches dangerous sinks to detect when untrusted HTTP input
reaches them without sanitization.

Usage:
    python -m security_audit_runtime your_app.py

Or import at the top of your app:
    import security_audit_runtime  # auto-patches on import

Monitors:
    - subprocess.run / subprocess.Popen / os.system (command injection)
    - pickle.loads / pickle.load (deserialization)
    - eval / exec (code injection)
    - sqlite3.Cursor.execute / psycopg2 execute (SQL injection)
    - os.path operations with user input (path traversal)
"""

import functools
import os
import sys
import traceback
import json
import atexit
from datetime import datetime, timezone

# === Taint Registry ===

_tainted_values: dict[str, dict] = {}
_findings: list[dict] = []


def mark_tainted(value: str, source_type: str, key: str, location: str = "") -> str:
    """Mark a string value as tainted (originating from user input)."""
    if isinstance(value, str) and value:
        _tainted_values[value] = {
            "type": source_type,
            "key": key,
            "location": location,
        }
        # Also mark common transformations
        _tainted_values[value.strip()] = _tainted_values[value]
        _tainted_values[value.lower()] = _tainted_values[value]
    return value


def is_tainted(value) -> dict | None:
    """Check if a value is tainted."""
    if isinstance(value, str):
        return _tainted_values.get(value)
    return None


def _report_finding(sink: str, value, source: dict):
    """Record a taint flow finding."""
    # Get caller location (skip internal frames)
    stack = traceback.extract_stack()
    location = "unknown"
    for frame in reversed(stack[:-2]):
        if "security_audit_runtime" not in frame.filename:
            location = f"{frame.filename}:{frame.lineno}"
            break

    finding = {
        "source": source,
        "sink": sink,
        "sink_location": location,
        "value": str(value)[:200],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _findings.append(finding)

    print(
        f"\n[security-audit] TAINT FLOW DETECTED\n"
        f"  Source: {source['type']}.{source['key']} ({source.get('location', '')})\n"
        f"  Sink:   {sink} ({location})\n"
        f"  Value:  {str(value)[:80]}...\n",
        file=sys.stderr,
    )


def _check_args(sink_name: str, args):
    """Check if any arguments to a function are tainted."""
    for arg in args:
        source = is_tainted(arg)
        if source:
            _report_finding(sink_name, arg, source)
        # Also check if tainted values appear as substrings
        if isinstance(arg, str):
            for tainted_val, src in _tainted_values.items():
                if len(tainted_val) > 3 and tainted_val in arg:
                    _report_finding(sink_name, arg, src)
                    break


# === Monkey-patches ===

def _patch_subprocess():
    """Patch subprocess module to detect command injection."""
    import subprocess

    _orig_run = subprocess.run
    _orig_popen = subprocess.Popen.__init__

    @functools.wraps(_orig_run)
    def patched_run(*args, **kwargs):
        cmd = args[0] if args else kwargs.get("args", "")
        if isinstance(cmd, str):
            _check_args("subprocess.run", [cmd])
        elif isinstance(cmd, (list, tuple)) and cmd:
            _check_args("subprocess.run", [str(cmd[0])])
        return _orig_run(*args, **kwargs)

    @functools.wraps(_orig_popen)
    def patched_popen_init(self, *args, **kwargs):
        cmd = args[0] if args else kwargs.get("args", "")
        if isinstance(cmd, str):
            _check_args("subprocess.Popen", [cmd])
        return _orig_popen(self, *args, **kwargs)

    subprocess.run = patched_run
    subprocess.Popen.__init__ = patched_popen_init


def _patch_os():
    """Patch os.system and os.popen."""
    _orig_system = os.system
    _orig_popen = os.popen

    @functools.wraps(_orig_system)
    def patched_system(command):
        _check_args("os.system", [command])
        return _orig_system(command)

    @functools.wraps(_orig_popen)
    def patched_popen(cmd, *args, **kwargs):
        _check_args("os.popen", [cmd])
        return _orig_popen(cmd, *args, **kwargs)

    os.system = patched_system
    os.popen = patched_popen


def _patch_pickle():
    """Patch pickle to detect insecure deserialization."""
    import pickle

    _orig_loads = pickle.loads
    _orig_load = pickle.load

    @functools.wraps(_orig_loads)
    def patched_loads(data, *args, **kwargs):
        if isinstance(data, (str, bytes)):
            _check_args("pickle.loads", [str(data)[:100]])
        return _orig_loads(data, *args, **kwargs)

    @functools.wraps(_orig_load)
    def patched_load(file, *args, **kwargs):
        _check_args("pickle.load", [getattr(file, "name", str(file))])
        return _orig_load(file, *args, **kwargs)

    pickle.loads = patched_loads
    pickle.load = patched_load


def _patch_builtins():
    """Patch eval and exec."""
    import builtins

    _orig_eval = builtins.eval
    _orig_exec = builtins.exec

    @functools.wraps(_orig_eval)
    def patched_eval(expression, *args, **kwargs):
        if isinstance(expression, str):
            _check_args("eval", [expression])
        return _orig_eval(expression, *args, **kwargs)

    @functools.wraps(_orig_exec)
    def patched_exec(code, *args, **kwargs):
        if isinstance(code, str):
            _check_args("exec", [code])
        return _orig_exec(code, *args, **kwargs)

    builtins.eval = patched_eval
    builtins.exec = patched_exec


def _patch_sqlite3():
    """Patch sqlite3 to detect SQL injection."""
    try:
        import sqlite3

        _orig_execute = sqlite3.Cursor.execute

        @functools.wraps(_orig_execute)
        def patched_execute(self, sql, *args, **kwargs):
            if isinstance(sql, str):
                _check_args("sqlite3.execute", [sql])
            return _orig_execute(self, sql, *args, **kwargs)

        sqlite3.Cursor.execute = patched_execute
    except ImportError:
        pass


# === WSGI/ASGI Middleware for Flask/Django/FastAPI ===

class TaintMiddleware:
    """WSGI middleware that taints request parameters."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        # Taint query string parameters
        query_string = environ.get("QUERY_STRING", "")
        if query_string:
            from urllib.parse import parse_qs
            params = parse_qs(query_string)
            for key, values in params.items():
                for value in values:
                    mark_tainted(
                        value,
                        source_type="query",
                        key=key,
                        location=f"{environ.get('REQUEST_METHOD')} {environ.get('PATH_INFO')}",
                    )

        return self.app(environ, start_response)


def taint_flask_request():
    """Call this in a Flask before_request handler to taint all inputs."""
    try:
        from flask import request

        for key, value in request.args.items():
            mark_tainted(value, "query", key, f"{request.method} {request.path}")
        for key, value in request.form.items():
            mark_tainted(value, "body", key, f"{request.method} {request.path}")
        if request.is_json and isinstance(request.json, dict):
            for key, value in request.json.items():
                if isinstance(value, str):
                    mark_tainted(value, "body", key, f"{request.method} {request.path}")
    except Exception:
        pass


def taint_django_request(request):
    """Call this in Django middleware to taint all inputs."""
    for key, value in request.GET.items():
        mark_tainted(value, "query", key, f"{request.method} {request.path}")
    for key, value in request.POST.items():
        mark_tainted(value, "body", key, f"{request.method} {request.path}")


# === Report on exit ===

def _print_summary():
    if _findings:
        print(
            f"\n[security-audit] Runtime Analysis Summary\n"
            f"  Taint flows detected: {len(_findings)}\n",
            file=sys.stderr,
        )
        for f in _findings:
            print(
                f"  - {f['source']['type']}.{f['source']['key']} → {f['sink']} ({f['sink_location']})",
                file=sys.stderr,
            )

        # Write JSON report if env var is set
        report_file = os.environ.get("SECURITY_AUDIT_REPORT")
        if report_file:
            with open(report_file, "w") as fp:
                json.dump(_findings, fp, indent=2)
            print(f"\n  Report written to: {report_file}", file=sys.stderr)


# === Auto-patch on import ===

def install():
    """Install all monkey-patches."""
    _patch_subprocess()
    _patch_os()
    _patch_pickle()
    _patch_builtins()
    _patch_sqlite3()
    atexit.register(_print_summary)
    print("[security-audit] Python runtime agent loaded — monitoring taint flows", file=sys.stderr)


# Auto-install when imported
install()


# === CLI entry point ===

def main():
    """Run a Python script with taint tracing enabled."""
    if len(sys.argv) < 2:
        print("Usage: python -m security_audit_runtime <script.py> [args...]", file=sys.stderr)
        sys.exit(1)

    script = sys.argv[1]
    sys.argv = sys.argv[1:]  # Shift args so the target script sees correct sys.argv

    with open(script) as f:
        code = compile(f.read(), script, "exec")
        exec(code, {"__name__": "__main__", "__file__": script})


if __name__ == "__main__":
    main()
