#!/usr/bin/env python3
"""Validate detection regex patterns against eval fixtures.

For each language/framework directory under evals/:
  - vulnerable/ contains code samples that MUST match their checkpoint's regex
  - safe/ contains code samples that MUST NOT match

Fixture filenames follow the pattern: {CHECKPOINT_ID}_{description}.{ext}
The checkpoint ID maps to a regex pattern in checkpoints.yaml.
"""

import os
import re
import sys

import yaml

EVALS_DIR = "skills/security-audit/evals"
CHECKPOINTS_FILE = "skills/security-audit/checkpoints.yaml"


def load_checkpoint_patterns() -> dict[str, str]:
    """Load checkpoint ID -> regex pattern mapping from checkpoints.yaml."""
    with open(CHECKPOINTS_FILE) as f:
        data = yaml.safe_load(f)

    patterns = {}
    for checkpoint in data.get("mechanical", []):
        cid = checkpoint["id"]
        pattern = checkpoint.get("pattern")
        if pattern:
            patterns[cid] = pattern
    return patterns


def extract_checkpoint_id(filename: str) -> str | None:
    """Extract checkpoint ID from fixture filename like SA-04_hardcoded_password.php."""
    match = re.match(r"(SA-[A-Z]*-?\d+)", filename)
    return match.group(1) if match else None


def test_fixture(filepath: str, pattern: str, should_match: bool) -> tuple[bool, str]:
    """Test a single fixture file against a regex pattern.

    Returns (passed, message).
    """
    with open(filepath) as f:
        content = f.read()

    try:
        found = bool(re.search(pattern, content))
    except re.error as e:
        return False, f"Invalid regex '{pattern}': {e}"

    if should_match and not found:
        return False, f"FALSE NEGATIVE: vulnerable fixture did not match pattern"
    if not should_match and found:
        return False, f"FALSE POSITIVE: safe fixture matched pattern"

    return True, "OK"


def main() -> int:
    if not os.path.isdir(EVALS_DIR):
        print(f"No evals directory found at {EVALS_DIR}, skipping")
        return 0

    patterns = load_checkpoint_patterns()
    total = 0
    passed = 0
    failed = 0
    skipped = 0

    # Walk each language/framework directory
    for lang_dir in sorted(os.listdir(EVALS_DIR)):
        lang_path = os.path.join(EVALS_DIR, lang_dir)
        if not os.path.isdir(lang_path) or lang_dir.startswith("."):
            continue

        for fixture_type in ["vulnerable", "safe"]:
            fixture_dir = os.path.join(lang_path, fixture_type)
            if not os.path.isdir(fixture_dir):
                continue

            should_match = fixture_type == "vulnerable"

            for filename in sorted(os.listdir(fixture_dir)):
                filepath = os.path.join(fixture_dir, filename)
                if not os.path.isfile(filepath):
                    continue

                checkpoint_id = extract_checkpoint_id(filename)
                if not checkpoint_id:
                    print(f"SKIP {filepath}: could not extract checkpoint ID from filename")
                    skipped += 1
                    continue

                if checkpoint_id not in patterns:
                    print(f"SKIP {filepath}: no pattern found for checkpoint {checkpoint_id}")
                    skipped += 1
                    continue

                total += 1
                ok, message = test_fixture(filepath, patterns[checkpoint_id], should_match)
                if ok:
                    passed += 1
                    print(f"PASS {filepath}: {message}")
                else:
                    failed += 1
                    print(f"FAIL {filepath}: {message} (pattern: {patterns[checkpoint_id]})")

    print(f"\nResults: {passed} passed, {failed} failed, {skipped} skipped out of {total} tests")

    if failed > 0:
        return 1
    if total == 0:
        print("No fixture tests found — this is OK during initial setup")
    return 0


if __name__ == "__main__":
    sys.exit(main())
