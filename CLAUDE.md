# CLAUDE.md — Security Audit Skill

## Project Overview

Security vulnerability detection skill for AI agents and IDEs. 408 checkpoints across 9 languages, 18 frameworks, 3 cloud providers, 4 CMS platforms, 2 mobile SDKs, with compliance mapping to 6 frameworks.

## Key Commands

```bash
# Run all tests
python3 scripts/test_risky_patterns.py && python3 scripts/validate_checkpoints.py && python3 scripts/test_eval_fixtures.py

# Multi-language security scan (auto-detects stack)
./scripts/security-audit-dispatcher.sh /path/to/project

# Dependency sandbox
./scripts/dependency-sandbox.sh npm lodash@4.17.21
./scripts/dependency-sandbox.sh pip requests==2.31.0

# Build TypeScript packages
cd packages/core && npm run build
cd packages/mcp-server && npm run build
cd packages/lsp-server && npm run build
```

## Repository Structure

- `skills/security-audit/` — Skill entry point, checkpoints, references, evals
- `skills/security-audit/references/` — 64 security reference files
- `skills/security-audit/checkpoints.yaml` — 408 checkpoints (372 mechanical + 36 LLM)
- `skills/security-audit/evals/` — 182 eval fixture tests (vulnerable + safe pairs)
- `scripts/scanners/` — 18 per-language/framework scanner modules
- `scripts/sandbox/` — Docker sandbox Dockerfiles and strace analyzer
- `packages/core/` — TypeScript detection engine
- `packages/mcp-server/` — MCP server (7 tools) for AI IDEs
- `packages/lsp-server/` — LSP server for traditional editors
- `packages/vscode-ext/` — VS Code extension
- `packages/jetbrains-plugin/` — JetBrains IDE plugin (Kotlin/Gradle)
- `packages/runtime-agent/` — Node.js + Python taint tracing
- `docs/editor-configs/` — Setup configs for 15 editors

## Checkpoint Naming

- Legacy PHP: `SA-{NN}` (e.g., SA-01)
- Language: `SA-{LANG}-{NN}` (e.g., SA-PY-01, SA-JS-06)
- Framework: `SA-{FRAMEWORK}-{NN}` (e.g., SA-REACT-01, SA-DJANGO-01)
- Cloud: `SA-{PROVIDER}-{NN}` (e.g., SA-AWS-01)
- CMS: `SA-{CMS}-{NN}` (e.g., SA-WP-01)
- Mobile: `SA-{PLATFORM}-{NN}` (e.g., SA-ANDROID-01)
- Runtime: `LIVE-{CHECK}-{ID}` (e.g., LIVE-HDR-HSTS)

## Adding a New Language/Framework

See `docs/CONTRIBUTING-REFERENCES.md` for the full guide. Summary:
1. Create reference file from template in `docs/templates/`
2. Add checkpoints to `checkpoints.yaml` (before `llm_reviews:`)
3. Create scanner module in `scripts/scanners/`
4. Add eval fixtures in `skills/security-audit/evals/`
5. Update SKILL.md detection mapping table
6. Add prefix to `scripts/validate_checkpoints.py`

## CI

Tests run on push/PR to main:
- `test_risky_patterns.py` — hook pattern tests
- `validate_checkpoints.py` — checkpoint YAML + namespace validation
- `test_eval_fixtures.py` — regex fixture tests (182 tests)

## GitHub Issues

- #3 — Multi-language security references
- #4 — Extended capabilities (IDE, runtime, CVE, cloud, CMS, mobile)
- #5 — Main PR (all implementation)
- #6 — Security governance
- #7 — Contribution governance
- #8 — Scan governance
- #9 — Compliance governance
- #10 — JetBrains IDE plugin
