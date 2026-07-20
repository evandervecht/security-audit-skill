# Contributing Security References

Guide for adding new language or framework security references to the security-audit skill.

## Overview

The security-audit skill uses two types of reference files:

- **Language references** (`{language}-security-features.md`) — organized by language version, covering security-relevant features
- **Framework references** (`{framework}-security.md`) — organized by vulnerability category, covering framework-specific patterns

Each reference is paired with checkpoints in `checkpoints.yaml`, a scanner module in `scripts/scanners/`, and eval test fixtures in `skills/security-audit/evals/`.

## Step-by-Step: Adding a New Language

1. **Create the reference file** using `docs/templates/language-security-features-template.md`
   - Save to `skills/security-audit/references/{language}-security-features.md`
   - Target size: 15-25KB
   - Cover top 10-15 vulnerability patterns for the language
   - Organize by language version where applicable

2. **Add checkpoints** to `skills/security-audit/checkpoints.yaml`
   - Use the naming convention `SA-{LANG}-{NN}` (see table below)
   - Add 10-20 checkpoints per language
   - Each checkpoint needs: `id`, `type`, `target`, `pattern`, `severity`, `desc`

3. **Create a scanner module** at `scripts/scanners/{language}.sh`
   - Make it executable (`chmod +x`)
   - Accept `PROJECT_DIR` as first argument
   - Exit with the error count (0 = clean)
   - Source `scripts/scanners/common.sh` for shared helpers

4. **Add eval fixtures**
   - Create `skills/security-audit/evals/{language}/vulnerable/` with code samples that MUST trigger each checkpoint
   - Create `skills/security-audit/evals/{language}/safe/` with similar-looking safe code that MUST NOT trigger
   - One file per detection pattern, named after the checkpoint (e.g., `SA-PY-01_pickle_loads.py`)

5. **Update the detection mapping** in `skills/security-audit/SKILL.md`
   - Add indicator files to the detection mapping table

6. **Register in validate_checkpoints.py**
   - Add the language prefix to the valid namespace list

## Step-by-Step: Adding a New Framework

Same as above, but:
- Use `docs/templates/framework-security-template.md` as template
- Naming: `SA-{FRAMEWORK}-{NN}` for checkpoints
- Target size: 10-20KB, 5-15 checkpoints per framework

## Checkpoint Naming Convention

| Language/Framework | Prefix | Example |
|-------------------|--------|---------|
| PHP | `SA-PHP-` | `SA-PHP-01` |
| JavaScript/TypeScript | `SA-JS-` | `SA-JS-01` |
| Python | `SA-PY-` | `SA-PY-01` |
| Java | `SA-JAVA-` | `SA-JAVA-01` |
| C# | `SA-CS-` | `SA-CS-01` |
| Go | `SA-GO-` | `SA-GO-01` |
| Rust | `SA-RS-` | `SA-RS-01` |
| Ruby | `SA-RB-` | `SA-RB-01` |
| Node.js | `SA-NODE-` | `SA-NODE-01` |
| Kotlin | `SA-KT-` | `SA-KT-01` |
| Swift | `SA-SWIFT-` | `SA-SWIFT-01` |
| Dart | `SA-DART-` | `SA-DART-01` |
| Elixir | `SA-EX-` | `SA-EX-01` |
| Scala | `SA-SCALA-` | `SA-SCALA-01` |
| Shell | `SA-SH-` | `SA-SH-01` |
| React | `SA-REACT-` | `SA-REACT-01` |
| Next.js | `SA-NEXT-` | `SA-NEXT-01` |
| Vue | `SA-VUE-` | `SA-VUE-01` |
| Angular | `SA-ANG-` | `SA-ANG-01` |
| Nuxt | `SA-NUXT-` | `SA-NUXT-01` |
| Django | `SA-DJANGO-` | `SA-DJANGO-01` |
| Flask | `SA-FLASK-` | `SA-FLASK-01` |
| FastAPI | `SA-FASTAPI-` | `SA-FASTAPI-01` |
| Spring | `SA-SPRING-` | `SA-SPRING-01` |
| .NET | `SA-DOTNET-` | `SA-DOTNET-01` |
| Blazor | `SA-BLAZOR-` | `SA-BLAZOR-01` |
| Gin | `SA-GIN-` | `SA-GIN-01` |
| Rails | `SA-RAILS-` | `SA-RAILS-01` |
| Express | `SA-EXPRESS-` | `SA-EXPRESS-01` |
| NestJS | `SA-NEST-` | `SA-NEST-01` |
| Ktor | `SA-KTOR-` | `SA-KTOR-01` |
| Vapor | `SA-VAPOR-` | `SA-VAPOR-01` |
| Flutter | `SA-FLUTTER-` | `SA-FLUTTER-01` |
| Play | `SA-PLAY-` | `SA-PLAY-01` |
| Actix | `SA-ACTIX-` | `SA-ACTIX-01` |
| Axum | `SA-AXUM-` | `SA-AXUM-01` |

Existing (non-namespaced) checkpoints use `SA-{NN}` for backward compatibility.

## Quality Checklist

Every pattern in a reference file MUST include:

- [ ] **Vulnerable code example** — realistic, not contrived
- [ ] **Secure code example** — using the recommended approach
- [ ] **Security implication** — explains what vulnerability this prevents and why
- [ ] **Detection regex** — grep-compatible pattern for automated scanning
- [ ] **Eval fixture (vulnerable)** — code sample that triggers the detection regex
- [ ] **Eval fixture (safe)** — similar code that does NOT trigger (false positive test)

## File Size Guidelines

| Type | Target Size | Patterns |
|------|-------------|----------|
| Language reference | 15-25KB | 10-15 vulnerability patterns |
| Framework reference | 10-20KB | 8-12 vulnerability patterns |

## Changelog Convention

Every reference file must have a changelog table at the bottom:

```markdown
## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-04-01 | Initial release | Phase 1 |
| 2026-06-15 | Added Python 3.13 features | New version release |
```

## CI Validation

On every PR, CI automatically validates:

- Checkpoint YAML structure and no duplicate IDs
- Checkpoint namespace prefixes match valid languages/frameworks
- Eval fixtures: vulnerable samples trigger their regex, safe samples do not
- Reference files referenced by checkpoints exist
