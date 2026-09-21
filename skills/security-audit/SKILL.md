---
name: security-audit
description: "Use when conducting security assessments, running OWASP Top 10 or CWE Top 25 audits, scoring vulnerabilities with CVSS v4.0, auditing PHP/TYPO3/Symfony/Laravel, Elixir/Phoenix, Kotlin/Ktor, Swift/Vapor, Scala/Play, Dart/Flutter, or Rust Actix/Axum projects for XSS/SQLi/XXE/CSRF, auditing shell scripts for injection and TLS bypass, checking for leaked secrets, scanning dependencies for CVEs, reviewing code for any security concern, auditing Infrastructure-as-Code (Dockerfile/Terraform), Kubernetes manifests and GitHub Actions workflows, API security (OWASP API Top 10) including GraphQL, frontend/client-side security (DOM XSS/CORS/SRI) including React/Vue/Svelte, or auditing AI agent skills and configurations against the OWASP LLM Top 10 (2025)."
license: "MIT. See LICENSE-MIT"
compatibility: "Requires grep, jq, gh CLI."
metadata:
  author: E van der Vecht
  version: "3.2.0"
  repository: https://github.com/evandervecht/security-audit-skill
allowed-tools: Bash(grep:*) Bash(jq:*) Bash(gh:*) Read Glob Grep
---

# Security Audit Skill

Security audit patterns (OWASP Top 10, CWE Top 25 2025, CVSS v4.0) and GitHub project security checks for any project. Deep automated code scanning across 15 languages and 26 frameworks, Infrastructure-as-Code, Kubernetes and GitHub Actions workflow scanning, API and GraphQL security, frontend security, and AI/LLM agent security with 565+ checkpoints and 82 reference guides.

## Expertise Areas

- **Vulnerabilities**: XXE, SQL injection, XSS, CSRF, command injection, path traversal, file upload, deserialization, SSRF, type juggling, SSTI, JWT flaws
- **Risk Scoring**: CVSS v3.1 and v4.0 methodology
- **Secure Coding**: Input validation, output encoding, cryptography, session management, authentication
- **Standards**: OWASP Top 10, CWE Top 25, OWASP ASVS, Proactive Controls
- **Infrastructure**: Dockerfile, Docker Compose, Kubernetes, Terraform, GitHub Actions workflow security scanning
- **API Security**: OWASP API Top 10 (2025), GraphQL security, REST API hardening
- **Frontend**: DOM XSS, Subresource Integrity, CORS, postMessage, client-side storage security
- **AI/LLM Security**: OWASP LLM Top 10 (2025), agent permission auditing, MCP security, prompt injection defense

## Reference Files

- **Core**: `owasp-top10.md`, `cwe-top25.md`, `xxe-prevention.md`, `cvss-scoring.md`, `api-key-encryption.md`
- **Vulnerability Prevention**: `deserialization-prevention.md`, `path-traversal-prevention.md`, `file-upload-security.md`, `input-validation.md`
- **Secure Architecture**: `authentication-patterns.md`, `security-headers.md`, `security-logging.md`, `cryptography-guide.md`
- **Framework Security**: `typo3-security.md`, `symfony-security.md`, `laravel-security.md`, `ktor-security.md`, `vapor-security.md`, `play-security.md`, `actix-security.md`, `axum-security.md`, `flutter-security.md`
- **Language Security**: `php-security-features.md` (PHP 8.0-8.4), `kotlin-security-features.md`, `swift-security-features.md`, `scala-security-features.md`, `dart-security-features.md`, `shell-security-features.md`
- **Modern Threats**: `modern-attacks.md`, `cve-patterns.md`
- **DevSecOps**: `ci-security-pipeline.md`, `supply-chain-security.md`, `automated-scanning.md`
- **Incident Response**: `supply-chain-incident-response.md` (detection, triage, remediation playbooks for GitHub Actions supply chain compromises)
- **Infrastructure**: `iac-security.md` (Dockerfile, Docker Compose, Kubernetes, Terraform), `github-actions-security.md` (CI workflows)
- **API Security**: `api-security.md` (OWASP API Top 10, GraphQL, REST)
- **Frontend**: `frontend-security.md` (DOM XSS, SRI, CORS, postMessage, client-side storage)
- **AI/LLM Security**: `llm-security.md` (OWASP LLM Top 10 2025, agent/skill auditing)
- **Compliance**: `compliance-gdpr.md`, `compliance-hipaa.md`, `compliance-iso27001.md`, `compliance-nist-csf.md`, `compliance-pci-dss.md`, `compliance-soc2.md`, `compliance-eu-ai-act.md`

All files located in `references/`.

## Language/Framework Detection

When auditing a project, load only the references relevant to the detected stack. Check for these indicator files:

| Indicator | Language/Framework | References to Load |
|-----------|-------------------|-------------------|
| `composer.json`, `*.php` | PHP | `php-security-features.md` |
| `composer.json` with `typo3/*` | TYPO3 | `typo3-security.md` |
| `composer.json` with `symfony/*` | Symfony | `symfony-security.md` |
| `composer.json` with `laravel/*` | Laravel | `laravel-security.md` |
| `package.json` | JavaScript/TypeScript | `javascript-typescript-security-features.md`, `frontend-security.md` |
| `package.json` with `express`/`fastify`/`koa`/`nestjs` | Node.js | `nodejs-security-features.md` |
| `package.json` with `react` | React | `react-security.md` |
| `package.json` with `next` | Next.js | `nextjs-security.md` |
| `package.json` with `vue` | Vue | `vue-security.md` |
| `package.json` with `@angular/core` | Angular | `angular-security.md` |
| `package.json` with `nuxt` | Nuxt | `nuxt-security.md` |
| `requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile` | Python | `python-security-features.md` |
| Python with `django` | Django | `django-security.md` |
| Python with `flask` | Flask | `flask-security.md` |
| Python with `fastapi` | FastAPI | `fastapi-security.md` |
| `pom.xml`, `build.gradle` | Java | `java-security-features.md` |
| Java with `spring` | Spring | `spring-security.md` |
| `*.csproj`, `*.sln` | C#/.NET | `csharp-security-features.md`, `dotnet-security.md` |
| .NET with `Blazor` | Blazor | `blazor-security.md` |
| `go.mod` | Go | `go-security-features.md` |
| Go with `gin-gonic` | Gin | `gin-security.md` |
| `Cargo.toml` | Rust | `rust-security-features.md` |
| `Gemfile` | Ruby | `ruby-security-features.md` |
| Ruby with `rails` | Rails | `rails-security.md` |
| `Dockerfile`, `docker-compose.yml` | Docker | `iac-security.md` |
| `*.tf` | Terraform | `iac-security.md` |
| `*.graphql`/`*.gql`, `apollo-server` | graphql | `graphql-security.md` |
| `*.yaml` with `apiVersion:`+`kind:`, `kustomization.yaml`, `Chart.yaml` | kube | `kubernetes-security.md` |
| `.github/workflows/*.yml`, `.github/actions/*/action.yml` | GitHub Actions | `github-actions-security.md` |
| `package.json` with `svelte`/`@sveltejs/kit`, `*.svelte`, `svelte.config.js` | Svelte | `svelte-security.md` |
| `mix.exs`, `*.ex`/`*.exs`, `*.heex` | elixir | `elixir-phoenix-security.md` |
| `build.gradle.kts`, `settings.gradle.kts`, `*.kt` | Kotlin | `kotlin-security-features.md` |
| Gradle/Maven build with `io.ktor` | Ktor | `ktor-security.md` |
| `Package.swift`, `*.xcodeproj`, `*.swift` | Swift | `swift-security-features.md` |
| `Package.swift` with `vapor` | Vapor | `vapor-security.md` |
| `build.sbt`, `*.scala` | Scala | `scala-security-features.md` |
| `build.sbt` with `PlayScala`/`org.playframework` | Play | `play-security.md` |
| `pubspec.yaml`, `*.dart` | Dart | `dart-security-features.md` |
| `pubspec.yaml` with `flutter` | Flutter | `flutter-security.md` |
| `*.sh`, `*.bash` | Shell | `shell-security-features.md` |
| `Cargo.toml` with `actix-web` | Actix | `actix-security.md` |
| `Cargo.toml` with `axum` | Axum | `axum-security.md` |

Always load core references (`owasp-top10.md`, `cwe-top25.md`) regardless of stack.

## Quick Patterns

**XML parsing (prevent XXE):**
```php
$doc->loadXML($input, LIBXML_NONET);
```

**SQL (prevent injection):**
```php
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$id]);
```

**Output (prevent XSS):**
```php
echo htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
```

**API keys (encrypt at rest):**
```php
$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$encrypted = 'enc:' . base64_encode($nonce . sodium_crypto_secretbox($apiKey, $nonce, $key));
```

**Password hashing:**
```php
$hash = password_hash($password, PASSWORD_ARGON2ID);
```

For automated scanning tools (semgrep, trivy, gitleaks), see `references/automated-scanning.md`.

## Security Checklist

- [ ] `semgrep --config auto` passes with no high-severity findings
- [ ] `trivy fs --severity HIGH,CRITICAL` reports no unpatched CVEs
- [ ] `gitleaks detect` finds no leaked secrets
- [ ] bcrypt/Argon2 for passwords, CSRF tokens on state changes
- [ ] All input validated server-side, parameterized SQL
- [ ] XML external entities disabled (LIBXML_NONET only)
- [ ] Context-appropriate output encoding, CSP configured
- [ ] API keys encrypted at rest (sodium_crypto_secretbox)
- [ ] TLS 1.2+, secrets not in VCS, audit logging
- [ ] No unserialize() with user input, use json_decode()
- [ ] File uploads validated, renamed, stored outside web root
- [ ] Security headers: HSTS, CSP, X-Content-Type-Options
- [ ] Dependencies scanned (composer audit), Dependabot enabled
- [ ] Dockerfiles use non-root USER, no secrets in layers or ARGs
- [ ] Kubernetes pods have securityContext, NetworkPolicy, RBAC least-privilege
- [ ] GitHub Actions: no pull_request_target head checkout, untrusted context via env:, actions SHA-pinned, least-privilege permissions
- [ ] Terraform resources not publicly accessible, storage encrypted
- [ ] API endpoints enforce object-level and function-level authorization
- [ ] GraphQL introspection disabled in production, depth/complexity limits set
- [ ] Frontend scripts use SRI, no sensitive data in localStorage
- [ ] CORS configured with specific origins, not wildcards
- [ ] postMessage handlers validate origin
- [ ] AI agent skills follow least-privilege for tool permissions
- [ ] MCP server versions pinned, no secrets in system prompts
- [ ] LLM output validated before shell execution or code generation
- [ ] Agent safety hooks cover high-impact operations

## Verification

```bash
# Multi-language security audit (auto-detects stack)
./scripts/security-audit-dispatcher.sh /path/to/project

# PHP-only project security audit (legacy)
./skills/security-audit/scripts/security-audit.sh /path/to/project

# GitHub repository security audit
./skills/security-audit/scripts/github-security-audit.sh owner/repo
```

---

> **Contributing:** https://github.com/evandervecht/security-audit-skill
