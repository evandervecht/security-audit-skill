# Review rules

What the review lanes hold a PR in this repo to. CLAUDE.md has the house rules; this file says what is worth raising.

## Important (blocker or major)
- `skills/security-audit/SKILL.md` frontmatter that breaks `scripts/validate_skill.py`: name not a slug matching its directory, description over 1024 chars, empty body, or a backticked `*.md` reference that does not exist under `references/`.
- A `description` or trigger edit that no longer matches what the skill does; other workspaces pin this skill by hash in `skills-lock.json`, so every byte of `skills/security-audit/` ships to them.
- Skill text, references or scripts that make the skill fetch or execute remote content, or run tools beyond `allowed-tools` (grep, jq, gh, Read, Glob, Grep), without the user asking.
- A change to `hooks/hooks.json` or `scripts/check_risky_command.py` that widens what the PreToolUse hook lets through, or has no case in `scripts/test_risky_patterns.py`.
- A checkpoint added or changed in `checkpoints.yaml` without its eval fixtures (vulnerable and safe) in `evals/`, a valid `SA-` prefix in `scripts/validate_checkpoints.py`, or a scanner in `scripts/scanners/`.
- A test or fixture changed to pass instead of the detector or checkpoint being fixed.
- A secret, token or real credential in the diff, fixtures included unless clearly a dummy.
- A workflow change that drops pinned action SHAs, widens `permissions:` beyond `contents: read`, or edits `release.yml` (it calls an external reusable workflow `@main`).

## Minor
- Counts that drifted (565 checkpoints, 85 references, 552 fixtures, 15 languages, 26 frameworks) in README, CLAUDE.md or SKILL.md.
- `version` in `SKILL.md` metadata and `.claude-plugin/plugin.json` changed in one place only.
- A new reference file not listed in SKILL.md's Reference Files or `stack-detection.md`.
- `AGENTS.md` links or commands that no longer exist (`harness-verify.yml` checks them).
- A new helper in `scripts/` that duplicates `scripts/scanners/common.sh` or an existing script.

## Skip
- Formatting that markdownlint (`.markdownlint-cli2.jsonc`) or yamllint (`.yamllint.yml`) already owns.
- Dependency bumps from Renovate or Dependabot that pass CI.
- Asking for abstractions, options or config nobody asked for.
- More than three nits per lane.
