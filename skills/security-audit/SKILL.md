---
name: security-audit
description: "Use when conducting security assessments, running OWASP Top 10 or CWE Top 25 audits, scoring vulnerabilities with CVSS v4.0, auditing PHP/TYPO3/Symfony/Laravel projects for XSS/SQLi/XXE/CSRF, checking for leaked secrets, scanning dependencies for CVEs, reviewing code for any security concern, auditing Infrastructure-as-Code (Dockerfile/K8s/Terraform), API security (OWASP API Top 10), frontend/client-side security (DOM XSS/CORS/SRI), or auditing AI agent skills and configurations against the OWASP LLM Top 10 (2025)."
license: "(MIT AND CC-BY-SA-4.0). See LICENSE-MIT and LICENSE-CC-BY-SA-4.0"
compatibility: "Requires grep, jq, gh CLI."
metadata:
  author: Evan de Recht
  version: "3.0.0"
  repository: https://github.com/evandervecht/security-audit-skill
allowed-tools: Bash(grep:*) Bash(jq:*) Bash(gh:*) Read Glob Grep
---

# Security Audit Skill

Security audit patterns (OWASP Top 10, CWE Top 25 2025, CVSS v4.0) and GitHub project security checks for any project. Deep automated PHP/TYPO3 code scanning, Infrastructure-as-Code scanning, API security, frontend security, and AI/LLM agent security with 119+ checkpoints and 23 reference guides.

## Expertise Areas

- **Vulnerabilities**: XXE, SQL injection, XSS, CSRF, command injection, path traversal, file upload, deserialization, SSRF, type juggling, SSTI, JWT flaws
- **Risk Scoring**: CVSS v3.1 and v4.0 methodology
- **Secure Coding**: Input validation, output encoding, cryptography, session management, authentication
- **Standards**: OWASP Top 10, CWE Top 25, OWASP ASVS, Proactive Controls
- **Infrastructure**: Dockerfile, Docker Compose, Kubernetes, Terraform security scanning
- **API Security**: OWASP API Top 10 (2023), GraphQL security, REST API hardening
- **Frontend**: DOM XSS, Subresource Integrity, CORS, postMessage, client-side storage security
- **AI/LLM Security**: OWASP LLM Top 10 (2025), agent permission auditing, MCP security, prompt injection defense

## Reference Files

- **Core**: `owasp-top10.md`, `cwe-top25.md`, `xxe-prevention.md`, `cvss-scoring.md`, `api-key-encryption.md`
- **Vulnerability Prevention**: `deserialization-prevention.md`, `path-traversal-prevention.md`, `file-upload-security.md`, `input-validation.md`
- **Secure Architecture**: `authentication-patterns.md`, `security-headers.md`, `security-logging.md`, `cryptography-guide.md`
- **Framework Security**: `framework-security.md` (TYPO3, Symfony, Laravel)
- **Modern Threats**: `modern-attacks.md`, `cve-patterns.md`, `php-security-features.md`
- **DevSecOps**: `ci-security-pipeline.md`, `supply-chain-security.md`, `automated-scanning.md`
- **Incident Response**: `supply-chain-incident-response.md` (detection, triage, remediation playbooks for GitHub Actions supply chain compromises)
- **Infrastructure**: `iac-security.md` (Dockerfile, Docker Compose, Kubernetes, Terraform)
- **API Security**: `api-security.md` (OWASP API Top 10, GraphQL, REST)
- **Frontend**: `frontend-security.md` (DOM XSS, SRI, CORS, postMessage, client-side storage)
- **AI/LLM Security**: `llm-security.md` (OWASP LLM Top 10 2025, agent/skill auditing)

All files located in `references/`.

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
# PHP project security audit
./scripts/security-audit.sh /path/to/project

# GitHub repository security audit
./scripts/github-security-audit.sh owner/repo
```

---

> **Contributing:** https://github.com/evandervecht/security-audit-skill
