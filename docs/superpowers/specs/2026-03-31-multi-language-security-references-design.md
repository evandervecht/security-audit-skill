# Multi-Language & Framework Security References — PRD

**Date:** 2026-03-31
**Author:** Evan de Recht
**Status:** Draft

---

## Problem Statement

The security-audit skill currently provides deep security reference coverage for PHP (8.0-8.4) and three PHP frameworks (TYPO3, Symfony, Laravel), but offers no language-specific security references for the vast majority of languages and frameworks used in modern software development. When auditing a Python, JavaScript, Go, Java, Rust, or .NET project, the AI agent has access to generic OWASP/CWE patterns but lacks the language-specific vulnerability patterns, secure coding idioms, and detection regexes needed for effective automated scanning.

This means the skill is only truly actionable for PHP projects, despite the security audit methodology being language-agnostic.

## Solution

Expand the security-audit skill with comprehensive, per-language and per-framework security references, automated checkpoints, modular scanner scripts, and regression test fixtures — covering all major programming languages and frameworks used in production software today.

Each new reference follows proven patterns established by `php-security-features.md` (version-based language features) and `framework-security.md` (pattern-based framework coverage), adapted to the two distinct templates described below.

## User Stories

1. As a security auditor, I want language-specific vulnerability detection patterns for Python, so that I can identify `pickle` deserialization, `eval()` injection, and SSTI risks automatically.
2. As a security auditor, I want JavaScript/TypeScript security references, so that I can detect prototype pollution, unsafe `eval()`, and type confusion vulnerabilities.
3. As a security auditor, I want framework-specific references for React, so that I can identify `dangerouslySetInnerHTML` misuse, XSS in JSX, and insecure state management.
4. As a security auditor, I want Next.js security references, so that I can audit server actions, API routes, and middleware for auth bypass and data exposure.
5. As a security auditor, I want Vue security references, so that I can detect `v-html` XSS, insecure directive usage, and client-side auth bypass.
6. As a security auditor, I want Angular security references, so that I can identify `bypassSecurityTrust*` misuse, template injection, and DomSanitizer bypass.
7. As a security auditor, I want Python framework references (Django, Flask, FastAPI), so that I can audit ORM injection, CSRF misconfig, and insecure serialization per framework.
8. As a security auditor, I want Java security references, so that I can detect insecure deserialization, JNDI injection, and reflection abuse.
9. As a security auditor, I want Spring security references, so that I can audit Spring Security misconfigurations, SpEL injection, and actuator exposure.
10. As a security auditor, I want C#/.NET security references, so that I can detect insecure deserialization (`BinaryFormatter`), SQL injection in Entity Framework, and CORS misconfigurations.
11. As a security auditor, I want Go security references, so that I can identify goroutine race conditions, unsafe pointer usage, and `text/template` injection.
12. As a security auditor, I want Rust security references, so that I can audit `unsafe` blocks, FFI boundary issues, and `panic` in library code.
13. As a security auditor, I want Ruby/Rails security references, so that I can detect mass assignment, `html_safe` misuse, and insecure `send()` calls.
14. As a security auditor, I want Node.js security references, so that I can identify `child_process` injection, event loop blocking, and insecure `require()` patterns.
15. As a security auditor, I want Express/NestJS security references, so that I can audit middleware ordering, CORS config, and input validation patterns.
16. As a security auditor, I want automated checkpoints for every new language, so that the skill can run grep-based detection without manual review.
17. As a security auditor, I want the scanner to auto-detect which languages are present in a project, so that only relevant checks run.
18. As a security auditor, I want detection regex patterns validated against test fixtures, so that I can trust the results don't have excessive false positives or false negatives.
19. As a security auditor, I want a changelog in each reference, so that I can track when patterns were added or updated.
20. As a security auditor, I want automated GitHub Actions that detect new language/framework releases, so that I'm prompted to review references when security-relevant features ship.
21. As a contributor, I want clear reference templates and naming conventions, so that I can add new language/framework coverage following a consistent pattern.
22. As a contributor, I want CI validation of checkpoint namespaces and reference structure, so that my contributions are automatically checked for correctness.
23. As a security auditor, I want Kotlin/Ktor security references, so that I can audit Android and server-side Kotlin projects.
24. As a security auditor, I want Swift/iOS security references, so that I can detect insecure keychain usage, ATS bypass, and unsafe pointer patterns.
25. As a security auditor, I want Dart/Flutter security references, so that I can audit mobile app security patterns.
26. As a security auditor, I want Elixir/Phoenix security references, so that I can detect EEx template injection and insecure Ecto queries.
27. As a security auditor, I want Scala/Play security references, so that I can audit JVM-based web applications.
28. As a security auditor, I want Shell/Bash security references, so that I can detect command injection, unquoted variables, and insecure temp file handling in scripts.
29. As a security auditor, I want Nuxt security references, so that I can audit server routes, middleware, and SSR-specific vulnerabilities.
30. As a security auditor, I want Blazor security references, so that I can audit WebAssembly and server-side Blazor auth patterns.
31. As a security auditor, I want Gin (Go) security references, so that I can audit Go web framework-specific middleware and binding patterns.

## Implementation Decisions

### Two Reference Templates

**Language references** (`{language}-security-features.md`):
- Organized by language version (e.g., Python 3.9, 3.10, 3.11, 3.12, 3.13)
- Each version section covers security-relevant features introduced in that version
- Every feature includes: vulnerable code, secure code, security implication, detection regex
- Target size: 15-25KB per file
- Includes a changelog table at the bottom

**Framework references** (`{framework}-security.md`):
- Organized by vulnerability category (XSS, injection, auth, CSRF, etc.)
- Each category covers framework-specific APIs, common misconfigurations, remediation
- Includes remediation priority table with timelines
- Target size: 10-20KB per file
- Includes a changelog table at the bottom

### JavaScript and TypeScript Merged

A single `javascript-typescript-security-features.md` covers both, with a dedicated TypeScript section for type-safety-specific patterns (branded types, `unknown` vs `any`, strict mode, etc.). Framework references (React, Vue, Angular, Next.js) assume TypeScript usage.

### Checkpoint Naming Convention

- Language checkpoints: `SA-{LANG}-{NN}` (e.g., `SA-PY-01`, `SA-JS-01`, `SA-GO-01`, `SA-JAVA-01`, `SA-CS-01`, `SA-RB-01`, `SA-RS-01`, `SA-NODE-01`)
- Framework checkpoints: `SA-{FRAMEWORK}-{NN}` (e.g., `SA-REACT-01`, `SA-DJANGO-01`, `SA-SPRING-01`, `SA-RAILS-01`)
- 10-20 checkpoints per language, 5-15 per framework
- Focus on top 10-15 vulnerability patterns per language (real-world audit frequency)

### Modular Scanner Architecture

- **Dispatcher** (`security-audit.sh`): detects languages/frameworks via indicator files (`package.json`, `requirements.txt`, `go.mod`, `Cargo.toml`, etc.) and invokes relevant scanner modules
- **Per-language scanners** (`scripts/scanners/{language}.sh`): focused, testable scripts running language-specific detection patterns
- Existing PHP scanner logic extracted to `scripts/scanners/php.sh`

### Language/Framework Detection in SKILL.md

A detection mapping table in SKILL.md that maps indicator files to references:
- `requirements.txt` / `pyproject.toml` / `setup.py` -> Python references
- `package.json` with `react` -> React + JS/TS references
- `go.mod` -> Go references
- etc.

This tells the AI agent which references to load, reducing context window usage.

### Refactor Existing `framework-security.md`

Split the existing bundled `framework-security.md` (TYPO3/Symfony/Laravel) into three separate files: `typo3-security.md`, `symfony-security.md`, `laravel-security.md`. Mechanical split, no content changes. Establishes consistency with the new per-framework pattern.

### Changelog and Version Tracking

- Each reference file includes a changelog table at the bottom tracking additions and updates
- A GitHub Action monitors language/framework release RSS feeds and opens issues when new major/minor versions ship, prompting reference review

### Contributing Infrastructure

- Reference templates (blank language and framework templates) for contributors
- Documented checkpoint naming convention
- Quality checklist: every pattern must have vulnerable code, secure code, detection regex, and a test fixture
- CI validation extended to cover new checkpoint namespaces

### Three-Phase Delivery

**Phase 1 — Core Languages (PR #1):**
- Language references: `javascript-typescript-security-features.md`, `python-security-features.md`, `java-security-features.md`, `csharp-security-features.md`, `go-security-features.md`, `ruby-security-features.md`, `rust-security-features.md`, `nodejs-security-features.md`
- Refactor: split `framework-security.md` into `typo3-security.md`, `symfony-security.md`, `laravel-security.md`
- Scanner architecture: dispatcher + per-language scanner modules
- Checkpoints: ~120-160 new checkpoints across 8 languages
- Eval fixtures for all language references
- Contributing templates and CI validation
- SKILL.md detection mapping

**Phase 2 — Tier 1 Frameworks (PR #2):**
- Framework references: `react-security.md`, `nextjs-security.md`, `vue-security.md`, `angular-security.md`, `nuxt-security.md`, `django-security.md`, `flask-security.md`, `fastapi-security.md`, `spring-security.md`, `dotnet-security.md`, `blazor-security.md`, `gin-security.md`, `rails-security.md`, `express-security.md`, `nestjs-security.md`
- Checkpoints: ~75-225 new checkpoints across 15 frameworks
- Eval fixtures for all framework references

**Phase 3 — Tier 2+3 Languages & Frameworks (PR #3):**
- Language references: `kotlin-security-features.md`, `swift-security-features.md`, `dart-security-features.md`, `elixir-security-features.md`, `scala-security-features.md`, `perl-security-features.md`, `lua-security-features.md`, `r-security-features.md`, `shell-security-features.md`
- Framework references: `ktor-security.md`, `vapor-security.md`, `ios-security.md`, `flutter-security.md`, `phoenix-security.md`, `play-security.md`, `actix-security.md`, `axum-security.md`
- Checkpoints and eval fixtures for all
- GitHub Action for version release monitoring

### Complete File Inventory

**Phase 1 (new files):**
- `skills/security-audit/references/javascript-typescript-security-features.md`
- `skills/security-audit/references/python-security-features.md`
- `skills/security-audit/references/java-security-features.md`
- `skills/security-audit/references/csharp-security-features.md`
- `skills/security-audit/references/go-security-features.md`
- `skills/security-audit/references/ruby-security-features.md`
- `skills/security-audit/references/rust-security-features.md`
- `skills/security-audit/references/nodejs-security-features.md`
- `skills/security-audit/references/typo3-security.md` (extracted from framework-security.md)
- `skills/security-audit/references/symfony-security.md` (extracted from framework-security.md)
- `skills/security-audit/references/laravel-security.md` (extracted from framework-security.md)
- `scripts/scanners/python.sh`
- `scripts/scanners/javascript.sh`
- `scripts/scanners/java.sh`
- `scripts/scanners/csharp.sh`
- `scripts/scanners/go.sh`
- `scripts/scanners/ruby.sh`
- `scripts/scanners/rust.sh`
- `scripts/scanners/nodejs.sh`
- `scripts/scanners/php.sh` (extracted from security-audit.sh)
- `skills/security-audit/evals/{language}/vulnerable/*.{ext}` (per language)
- `skills/security-audit/evals/{language}/safe/*.{ext}` (per language)
- `docs/CONTRIBUTING-REFERENCES.md` (or section in existing docs)
- Reference templates (language + framework)

**Phase 2 (new files):**
- 15 framework reference files in `skills/security-audit/references/`
- Eval fixtures per framework

**Phase 3 (new files):**
- 9 language + 8 framework reference files
- Eval fixtures
- `.github/workflows/version-monitor.yml`

## Testing Decisions

### What Makes a Good Test

Tests should validate the **external behavior** of detection patterns — does this regex correctly match vulnerable code and correctly skip safe code? Tests should NOT test implementation details of the scanner scripts.

### Test Structure

For each language/framework:
- `evals/{name}/vulnerable/` — small code snippets that MUST trigger the corresponding checkpoint (true positive validation)
- `evals/{name}/safe/` — similar-looking but secure code that MUST NOT trigger (false positive validation)
- A test runner script that validates every detection regex against its fixtures

### CI Integration

- Extend existing CI pipeline to run eval fixture validation on every PR
- Extend `validate_checkpoints.py` to validate new checkpoint namespace prefixes
- All scanner modules must pass ShellCheck linting (existing `lint.yml` workflow)

### Prior Art

- `scripts/test_risky_patterns.py` — existing pattern testing for hook regexes
- `scripts/validate_checkpoints.py` — existing checkpoint YAML validation

## Out of Scope

- **Runtime analysis tools** — this skill provides static detection patterns only, not dynamic analysis
- **IDE integrations** — references are consumed by AI agents, not by IDE plugins directly
- **Vulnerability databases** — the skill does not replicate CVE databases; it focuses on code patterns
- **Auto-remediation** — the skill identifies and documents patterns but does not auto-fix code
- **Mobile-specific platform APIs** (Android SDK, iOS UIKit internals) — covered at language level (Kotlin, Swift) but not at platform SDK level
- **Cloud provider security** (AWS, GCP, Azure) — already partially covered by `iac-security.md`, not expanded here
- **CMS-specific security** beyond TYPO3 — WordPress, Drupal, Joomla are not included

## Further Notes

- The total estimated new content is ~800KB-1.2MB across all three phases
- Phase 1 alone delivers coverage for ~90% of real-world security audits
- The modular scanner architecture future-proofs the skill for additional languages without touching the dispatcher
- Contributors can add a new language by following the template, adding checkpoints, writing eval fixtures, and adding a scanner module — all validated by CI
- The version monitoring GitHub Action should check: Python (python.org RSS), Node.js (nodejs.org releases), Go (go.dev/dl), Rust (releases.rs), Java (jdk.java.net), .NET (dotnet.microsoft.com/download), Ruby (ruby-lang.org/news), and framework-specific release feeds
