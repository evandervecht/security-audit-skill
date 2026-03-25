#!/usr/bin/env python3
"""Validate checkpoints.yaml structure and check for duplicate IDs."""

import os
import sys

import yaml


def main() -> int:
    with open("skills/security-audit/checkpoints.yaml") as f:
        data = yaml.safe_load(f)

    if "mechanical" not in data:
        print("ERROR: missing mechanical section")
        return 1
    if "llm_reviews" not in data:
        print("ERROR: missing llm_reviews section")
        return 1

    mech_ids = [r["id"] for r in data["mechanical"]]
    llm_ids = [r["id"] for r in data["llm_reviews"]]
    all_ids = mech_ids + llm_ids
    dupes = [x for x in all_ids if all_ids.count(x) > 1]
    if dupes:
        print(f"ERROR: duplicate checkpoint IDs: {set(dupes)}")
        return 1

    print(f"Valid: {len(mech_ids)} mechanical + {len(llm_ids)} LLM review checkpoints")

    # Check that expected reference files exist
    ref_dir = "skills/security-audit/references"
    ref_files = os.listdir(ref_dir) if os.path.isdir(ref_dir) else []
    expected_refs = [
        "owasp-top10.md", "cwe-top25.md", "xxe-prevention.md", "cvss-scoring.md",
        "api-key-encryption.md", "authentication-patterns.md", "security-headers.md",
        "security-logging.md", "cryptography-guide.md", "framework-security.md",
        "modern-attacks.md", "cve-patterns.md", "php-security-features.md",
        "ci-security-pipeline.md", "supply-chain-security.md", "automated-scanning.md",
        "input-validation.md", "path-traversal-prevention.md",
        "supply-chain-incident-response.md",
        "iac-security.md", "api-security.md", "frontend-security.md", "llm-security.md",
    ]
    missing = [ref for ref in expected_refs if ref not in ref_files]
    if missing:
        print(f"WARNING: missing reference files: {missing}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
