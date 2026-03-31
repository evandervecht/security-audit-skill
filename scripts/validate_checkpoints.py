#!/usr/bin/env python3
"""Validate checkpoints.yaml structure, check for duplicate IDs, and validate namespace prefixes."""

import os
import re
import sys

import yaml

# Valid checkpoint namespace prefixes for language/framework-specific checkpoints.
# Legacy checkpoints use SA-{NN} (no language prefix).
VALID_PREFIXES = [
    "SA-",         # Legacy (non-namespaced)
    "SA-PHP-",     # PHP
    "SA-JS-",      # JavaScript/TypeScript
    "SA-PY-",      # Python
    "SA-JAVA-",    # Java
    "SA-CS-",      # C#
    "SA-GO-",      # Go
    "SA-RS-",      # Rust
    "SA-RB-",      # Ruby
    "SA-NODE-",    # Node.js
    "SA-KT-",      # Kotlin
    "SA-SWIFT-",   # Swift
    "SA-DART-",    # Dart
    "SA-EX-",      # Elixir
    "SA-SCALA-",   # Scala
    "SA-SH-",      # Shell
    "SA-REACT-",   # React
    "SA-NEXT-",    # Next.js
    "SA-VUE-",     # Vue
    "SA-ANG-",     # Angular
    "SA-NUXT-",    # Nuxt
    "SA-DJANGO-",  # Django
    "SA-FLASK-",   # Flask
    "SA-FASTAPI-", # FastAPI
    "SA-SPRING-",  # Spring
    "SA-DOTNET-",  # .NET
    "SA-BLAZOR-",  # Blazor
    "SA-GIN-",     # Gin
    "SA-RAILS-",   # Rails
    "SA-EXPRESS-", # Express
    "SA-NEST-",    # NestJS
    "SA-KTOR-",    # Ktor
    "SA-VAPOR-",   # Vapor
    "SA-IOS-",     # iOS
    "SA-FLUTTER-", # Flutter
    "SA-PHOENIX-", # Phoenix
    "SA-PLAY-",    # Play
    "SA-ACTIX-",   # Actix
    "SA-AXUM-",    # Axum
    "SA-FE-LLM-",  # Frontend LLM security (legacy)
    "SA-AI-LLM-",  # AI/LLM security (legacy)
    "SA-FE-",      # Frontend (legacy)
    "SA-AI-",      # AI (legacy)
    "SA-IAC-",     # Infrastructure-as-Code (legacy)
]

# Pattern: SA-{PREFIX}-{NN}, SA-{NN}, or legacy formats like SA-08b, SA-FE-LLM-01
CHECKPOINT_ID_PATTERN = re.compile(r"^SA-([A-Z]+-)*(\d+[a-z]?)$")


def validate_checkpoint_id(checkpoint_id: str) -> str | None:
    """Validate a checkpoint ID matches a known namespace prefix. Returns error message or None."""
    if not CHECKPOINT_ID_PATTERN.match(checkpoint_id):
        return f"Invalid checkpoint ID format: {checkpoint_id} (expected SA-{{PREFIX}}-{{NN}} or SA-{{NN}})"

    # Check if the ID starts with any valid prefix
    for prefix in VALID_PREFIXES:
        if checkpoint_id.startswith(prefix):
            return None

    return f"Unknown namespace prefix in checkpoint ID: {checkpoint_id}"


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

    # Validate checkpoint ID namespace prefixes
    invalid_ids = []
    for checkpoint_id in all_ids:
        error = validate_checkpoint_id(checkpoint_id)
        if error:
            invalid_ids.append(error)

    if invalid_ids:
        for error in invalid_ids:
            print(f"ERROR: {error}")
        return 1

    print(f"Valid: {len(mech_ids)} mechanical + {len(llm_ids)} LLM review checkpoints")

    # Check that expected reference files exist
    ref_dir = "skills/security-audit/references"
    ref_files = os.listdir(ref_dir) if os.path.isdir(ref_dir) else []
    expected_refs = [
        "owasp-top10.md", "cwe-top25.md", "xxe-prevention.md", "cvss-scoring.md",
        "api-key-encryption.md", "authentication-patterns.md", "security-headers.md",
        "security-logging.md", "cryptography-guide.md",
        "typo3-security.md", "symfony-security.md", "laravel-security.md",
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
