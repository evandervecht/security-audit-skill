#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["pyyaml"]
# ///
"""Validate Claude skill manifests (SKILL.md) in this repo.

Self-contained replacement for the former external "Skill Validation" workflow.
Checks each skills/**/SKILL.md for:
  - well-formed YAML frontmatter
  - required keys (name, description)
  - name is a valid slug, <= 64 chars, and matches its directory
  - description is present and within the 1024-char skill limit
  - a non-empty body
  - that reference files it links to (references/*.md) actually exist
"""
import re
import sys
from pathlib import Path

import yaml

NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
MAX_NAME = 64
MAX_DESC = 1024
SKILLS_DIR = Path("skills")


def parse_frontmatter(text: str):
    """Return (frontmatter_dict, body) or raise ValueError."""
    m = re.match(r"^---\n(.*?)\n---\n?(.*)$", text, re.S)
    if not m:
        raise ValueError("missing or malformed YAML frontmatter (must be delimited by '---')")
    fm = yaml.safe_load(m.group(1))
    if not isinstance(fm, dict):
        raise ValueError("frontmatter is not a key/value mapping")
    return fm, m.group(2)


def validate_skill(path: Path) -> list[str]:
    errs: list[str] = []
    try:
        fm, body = parse_frontmatter(path.read_text())
    except (ValueError, yaml.YAMLError) as e:
        return [f"{path}: {e}"]

    name = fm.get("name")
    if not name:
        errs.append(f"{path}: missing required 'name'")
    else:
        name = str(name)
        if not NAME_RE.match(name):
            errs.append(f"{path}: name '{name}' must be a lowercase slug (a-z, 0-9, hyphens)")
        if len(name) > MAX_NAME:
            errs.append(f"{path}: name exceeds {MAX_NAME} chars")
        if name != path.parent.name:
            errs.append(f"{path}: name '{name}' does not match directory '{path.parent.name}'")

    desc = fm.get("description")
    if not desc:
        errs.append(f"{path}: missing required 'description'")
    elif len(str(desc)) > MAX_DESC:
        errs.append(f"{path}: description is {len(str(desc))} chars (limit {MAX_DESC})")

    if not body.strip():
        errs.append(f"{path}: empty body after frontmatter")

    # Dead-reference check: backtick-quoted *.md tokens must resolve under references/.
    refs_dir = path.parent / "references"
    if refs_dir.is_dir():
        for ref in set(re.findall(r"`([\w./-]+\.md)`", body)):
            target = (refs_dir / Path(ref).name)
            if not target.exists() and not (path.parent / ref).exists():
                errs.append(f"{path}: references missing file '{ref}'")
    return errs


def main() -> int:
    skills = sorted(SKILLS_DIR.rglob("SKILL.md"))
    if not skills:
        print(f"ERROR: no SKILL.md found under {SKILLS_DIR}/")
        return 1

    all_errs: list[str] = []
    for p in skills:
        all_errs += validate_skill(p)

    if all_errs:
        print("Skill validation FAILED:")
        for e in all_errs:
            print(f"  - {e}")
        return 1

    print(f"Valid: {len(skills)} skill manifest(s) OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
