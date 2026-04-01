# Security Audit Skill — Usage Guide

How to apply the security audit skill to any project. Supports 9 languages, 18 frameworks, 3 cloud providers, 4 CMS platforms, 2 mobile SDKs, with 408 automated checkpoints, runtime analysis, CVE correlation, and compliance mapping.

---

## Installation

### Claude Code (CLI, Desktop, or IDE)

Install the skill as a plugin from GitHub:

```bash
claude plugin add evandervecht/security-audit-skill
```

Or clone it locally and point to it:

```bash
git clone https://github.com/evandervecht/security-audit-skill.git
# In your project, reference the skill directory in .claude/settings.json
```

### Other AI Agents (Cursor, GitHub Copilot, etc.)

Copy the `skills/security-audit/` directory into your agent's skill path. The skill is compatible with any Agent Skills-compatible platform.

---

## Quick Start

### 1. Audit a Software Project

Navigate to your software project directory and ask your AI agent:

> "Run a security audit on this project"

Or run the automated scanner directly:

```bash
# Multi-language scan (auto-detects your stack)
./scripts/security-audit-dispatcher.sh /path/to/your/project

# Scan a live URL for runtime security
# (via MCP tool or directly in packages/core)

# Sandbox a dependency install
./scripts/dependency-sandbox.sh npm suspicious-package@1.0.0
```

The dispatcher auto-detects languages via indicator files (`package.json`, `requirements.txt`, `go.mod`, `Cargo.toml`, etc.) and runs only relevant scanners plus the secrets scanner.
- Insecure password hashing
- Path traversal
- Type juggling
- SSRF, IDOR, and more

### 2. Audit a GitHub Repository's Security Settings

```bash
./skills/security-audit/scripts/github-security-audit.sh owner/repo
```

This checks: secret scanning, branch protection, Dependabot, CodeQL, workflow permissions, SECURITY.md, and more.

### 3. Ask Your AI Agent Directly

When the skill is installed, your AI agent will automatically use it when you ask security-related questions. Examples:

```
"Check this project for XSS vulnerabilities"
"Audit the Kubernetes manifests for security issues"
"Is this API endpoint vulnerable to BOLA?"
"Review this Dockerfile for security best practices"
"Audit this AI skill for prompt injection risks"
```

---

## Auditing Different Project Types

The skill auto-detects your project's stack and runs relevant checkpoints. 408 checkpoints across 36 technologies.

### PHP / TYPO3 / Symfony / Laravel

References: `php-security-features.md`, `typo3-security.md`, `symfony-security.md`, `laravel-security.md`

- **OWASP Top 10**: Injection, XSS, CSRF, SSRF, XXE, broken access control
- **CWE Top 25**: Type juggling, deserialization, path traversal, command injection
- **Framework-specific**: TYPO3 QueryBuilder/Extbase, Symfony voters/firewall, Laravel Eloquent/gates

```
"Run the OWASP Top 10 audit on this PHP project"
"Check for XXE vulnerabilities in the XML parsing code"
"Audit the TYPO3 extension for CWE Top 25 issues"
```

### JavaScript / TypeScript / Node.js

References: `javascript-typescript-security-features.md`, `nodejs-security-features.md`

- Prototype pollution, `eval()`/`Function()` injection, DOM XSS (innerHTML, document.write)
- `postMessage` origin validation, regex DoS, `Math.random()` for security tokens
- Node.js: `child_process` injection, `fs` path traversal, `vm` sandbox escape, `Buffer` misuse
- TypeScript: `any` vs `unknown`, type assertion abuse, branded types

```
"Check for prototype pollution vulnerabilities"
"Audit the Node.js code for command injection via child_process"
"Are there any eval() calls with user input?"
```

### React / Next.js / Vue / Angular / Nuxt

References: `react-security.md`, `nextjs-security.md`, `vue-security.md`, `angular-security.md`, `nuxt-security.md`

- React: `dangerouslySetInnerHTML`, `javascript:` hrefs, sensitive state exposure
- Next.js: Server Action auth bypass, `NEXT_PUBLIC_*` secret leaks, image SSRF, open redirects
- Vue: `v-html` XSS, template injection, Pinia/Vuex state exposure
- Angular: `bypassSecurityTrust*` misuse, `DomSanitizer` bypass, `innerHTML` binding
- Nuxt: Server route auth, `runtimeConfig` secrets, SSR XSS

```
"Check the React components for XSS vulnerabilities"
"Audit Next.js server actions for missing auth checks"
"Are there any v-html directives with user input in the Vue templates?"
```

### Python / Django / Flask / FastAPI

References: `python-security-features.md`, `django-security.md`, `flask-security.md`, `fastapi-security.md`

- `pickle`/`marshal` deserialization, `eval()`/`exec()`, Jinja2 SSTI, `subprocess` injection
- `yaml.load()` vs `yaml.safe_load()`, SQL injection via f-strings, `hashlib` weak algorithms
- Django: ORM raw injection, `@csrf_exempt`, `mark_safe` XSS, `DEBUG=True`
- Flask: SSTI, `send_file` traversal, debug mode, session tampering
- FastAPI: Missing auth dependencies, Pydantic bypass, CORS wildcard

```
"Audit this Python project for pickle deserialization issues"
"Check the Django views for CSRF exemptions"
"Are there any Flask routes with SSTI vulnerabilities?"
```

### Java / Spring

References: `java-security-features.md`, `spring-security.md`

- `ObjectInputStream` deserialization, JNDI injection (Log4Shell), reflection abuse
- JDBC SQL injection, XXE via `DocumentBuilderFactory`, `Runtime.exec` command injection
- Spring: `permitAll` overreach, SpEL injection, actuator exposure, Thymeleaf SSTI

```
"Check for JNDI injection patterns (Log4Shell)"
"Audit the Spring Security configuration"
"Are there any ObjectInputStream usages with untrusted data?"
```

### C# / .NET / Blazor

References: `csharp-security-features.md`, `dotnet-security.md`, `blazor-security.md`

- `BinaryFormatter` deserialization, Entity Framework `FromSqlRaw`, LDAP injection
- `Process.Start` command injection, `XmlDocument` XXE, CORS misconfiguration
- .NET: Middleware ordering, `[AllowAnonymous]` overreach, Razor `Html.Raw` XSS
- Blazor: WASM client-side auth bypass, JS interop injection, render mode security

```
"Check for BinaryFormatter usage in the C# code"
"Audit the ASP.NET Core middleware ordering"
"Are there any Blazor components with client-side auth checks?"
```

### Go / Gin

References: `go-security-features.md`, `gin-security.md`

- Race conditions, `unsafe` pointer usage, `text/template` vs `html/template` injection
- SQL string concatenation, `os/exec` command injection, `InsecureSkipVerify`
- `math/rand` vs `crypto/rand`, HTTP header injection, SSRF
- Gin: Middleware ordering, `c.Bind` mass assignment, template injection

```
"Check for InsecureSkipVerify in the TLS configuration"
"Audit the Go code for SQL injection via string concatenation"
"Are there any goroutine race conditions?"
```

### Rust

Reference: `rust-security-features.md`

- `unsafe` blocks, FFI boundary issues, `panic!` in library code
- `.unwrap()`/`.expect()` in production paths, integer overflow (debug vs release)
- SQL injection in Diesel/sqlx, `Command` injection, `serde` deserialization pitfalls
- Timing side-channels, `mem::forget` leaks

```
"Audit the unsafe blocks in the Rust code"
"Check for unwrap() calls in production error paths"
"Are there any serde deserialization issues with untrusted input?"
```

### Ruby / Rails

References: `ruby-security-features.md`, `rails-security.md`

- `eval`/`send` injection, `system`/`exec` command injection, `Marshal.load` deserialization
- `YAML.load` vs `YAML.safe_load`, ERB template injection, `html_safe`/`raw` XSS
- Rails: Mass assignment, `find_by_sql` injection, CSRF config, `send_file` traversal

```
"Check for Marshal.load with user input"
"Audit the Rails controllers for mass assignment"
"Are there any html_safe calls with unsanitized data?"
```

### Infrastructure-as-Code (Docker, Kubernetes, Terraform)

Reference: `iac-security.md`

- Dockerfiles running as root, secrets in layers, unpinned base images
- Docker Compose privileged mode, Docker socket mounts
- Kubernetes pods without securityContext, missing NetworkPolicy, overly permissive RBAC
- Terraform public resources, open security groups, unencrypted storage

```
"Audit the Dockerfile for security issues"
"Check the Kubernetes manifests for misconfigurations"
"Review the Terraform files for public access risks"
```

### Cloud Providers (AWS, GCP, Azure)

References: `aws-security.md`, `gcp-security.md`, `azure-security.md`

- AWS: IAM wildcard policies, public S3 buckets, open Security Groups, missing KMS rotation, CloudTrail disabled
- GCP: Primitive IAM roles, `allUsers` bindings, public Cloud Storage, missing audit logs
- Azure: Owner role at subscription scope, public Blob Storage, open NSGs, missing Key Vault

```
"Audit the Terraform files for AWS IAM misconfigurations"
"Check for public S3 buckets in the CloudFormation templates"
"Are there any overly permissive Azure RBAC assignments?"
```

### CMS (WordPress, Drupal, Joomla)

References: `wordpress-security.md`, `drupal-security.md`, `joomla-security.md`

- WordPress: `$wpdb->query()` without `prepare()`, missing nonces, unescaped output, REST API permissions
- Drupal: `db_query` without placeholders, `#markup` XSS, entity access, Form API
- Joomla: `JInput` without filtering, `JDatabaseQuery` injection, ACL checks

```
"Audit this WordPress plugin for SQL injection"
"Check the Drupal module for XSS via render arrays"
"Are there any Joomla controllers missing ACL checks?"
```

### Mobile (Android, iOS)

References: `android-sdk-security.md`, `ios-sdk-security.md`

- Android: Exported components, ContentProvider injection, WebView JS bridge, SharedPreferences, manifest flags (`debuggable`, `allowBackup`)
- iOS: Keychain `kSecAttrAccessibleAlways`, ATS bypass (`NSAllowsArbitraryLoads`), UIWebView, UIPasteboard leaks, URL scheme hijacking

```
"Audit the AndroidManifest.xml for exported components"
"Check for insecure Keychain accessibility settings"
"Are there any UIWebView usages that should be WKWebView?"
```

### APIs (REST, GraphQL)

Reference: `api-security.md`

Covers the OWASP API Top 10 (2025):
- Broken Object-Level Authorization (BOLA/IDOR)
- Mass assignment and excessive data exposure
- Missing rate limiting and pagination
- Function-level authorization gaps
- GraphQL introspection, depth limits, batching attacks

```
"Audit the API endpoints for BOLA vulnerabilities"
"Check if GraphQL introspection is disabled in production"
"Review the API rate limiting configuration"
```

### Frontend / Client-Side

Reference: `frontend-security.md`

- DOM-based XSS (innerHTML, document.write, eval)
- Missing Subresource Integrity (SRI) on CDN scripts
- CORS misconfiguration (wildcard origins)
- Sensitive data in localStorage/sessionStorage
- postMessage without origin validation

```
"Check the JavaScript files for DOM XSS vulnerabilities"
"Audit the CORS configuration"
"Are there any sensitive tokens stored in localStorage?"
```

### Secrets Detection

Scanner: `scripts/scanners/secrets.sh` (runs automatically on every project)

- TruffleHog filesystem + git history scan (when installed)
- 19 regex patterns: AWS keys, GitHub/GitLab/Slack tokens, private keys, JWTs, database URLs
- `.env` file detection, `.gitignore` validation

```
"Scan this project for leaked secrets"
"Check the git history for accidentally committed API keys"
```

---

## Auditing AI Agent Skills and Configurations

This is the unique capability: using the security audit skill to audit **other** AI agent skills, MCP servers, and agent configurations against the **OWASP LLM Top 10 (2025)**.

Reference: `references/llm-security.md`

### What It Audits

| File / Config | What It Checks |
|---|---|
| `SKILL.md` | Hardcoded secrets, excessive tool permissions, missing input validation instructions, prompt injection defenses |
| `AGENTS.md` / `CLAUDE.md` | Embedded credentials, overly permissive directives, missing security instructions |
| `mcp.json` / `.claude/mcp*.json` | MCP server version pinning, embedded credentials, server source verification |
| `hooks.json` / `.claude/hooks/` | Safety hook coverage, bypass potential, dangerous command detection |
| `.claude/settings*.json` | Tool permission scope, least-privilege compliance |

### How to Audit a Downloaded Skill

**Example: You download a new AI skill from GitHub and want to verify it's safe before using it.**

```bash
# 1. Clone the skill you want to audit
git clone https://github.com/someone/their-cool-skill.git /tmp/skill-to-audit

# 2. Navigate to the skill directory
cd /tmp/skill-to-audit

# 3. Ask your AI agent (with security-audit-skill installed) to audit it
```

Then ask:

```
"Audit this AI skill for security issues using the OWASP LLM Top 10"
```

The skill will check for:

**Prompt Injection (LLM01):**
- Does the skill ingest external content (WebFetch, WebSearch) without segregation instructions?
- Are there instructions to treat tool output as data, not commands?
- Is user input validated before being processed?

**Sensitive Information Disclosure (LLM02):**
- Are there API keys, tokens, or credentials hardcoded in SKILL.md or config files?
- Does the skill load `.env` files or private keys into context?

**Supply Chain (LLM03):**
- Are MCP server versions pinned or using `latest`?
- Does the skill come from a verified/trusted source?

**Improper Output Handling (LLM05):**
- Can the LLM's output reach a shell (Bash tool) without validation?
- Is generated code auto-executed without review gates?

**Excessive Agency (LLM06):**
- Does the skill grant `Bash(*)` (unrestricted shell access)?
- Are tool permissions scoped to what's actually needed?
- Are there human approval gates for destructive operations?

**System Prompt Leakage (LLM07):**
- Are security controls only enforced in prompt text (not externally)?
- Are there internal URLs, infrastructure details, or business logic that shouldn't leak?

### Specific Audit Commands

```
# Audit a specific SKILL.md file
"Review skills/my-skill/SKILL.md for prompt injection and excessive agency risks"

# Audit MCP server configuration
"Check the MCP server config in .claude/mcp.json for supply chain risks"

# Audit hook definitions
"Are the safety hooks in hooks.json sufficient to prevent dangerous operations?"

# Audit tool permissions
"Check if the allowed-tools in this skill follow the principle of least privilege"

# Full OWASP LLM Top 10 audit
"Run a complete OWASP LLM Top 10 (2025) security audit on this agent configuration"
```

### Example: Auditing an MCP Server Config

Given an `mcp.json`:

```json
{
  "servers": {
    "my-tool": {
      "command": "npx",
      "args": ["-y", "some-mcp-server"],
      "env": {
        "API_KEY": "sk-live-abc123"
      }
    }
  }
}
```

The audit would flag:
1. **SA-AI-01** (error): Hardcoded API key `sk-live-` in MCP config
2. **SA-AI-04** (warning): MCP server not pinned to a specific version (uses `-y` with no version)
3. **SA-AI-LLM-02** (error): Credentials embedded in agent configuration
4. **SA-AI-LLM-05** (warning): MCP server source not verified, no version pinning

### Example: Auditing a SKILL.md

Given a skill with:

```markdown
---
allowed-tools: Bash, Read, Write, WebFetch, Edit
---
You are a helpful coding assistant. Fetch any URL the user asks for and execute their code.
```

The audit would flag:
1. **SA-AI-03** (warning): Unrestricted Bash access (should scope to specific commands)
2. **SA-AI-LLM-01** (error): WebFetch without content segregation instructions
3. **SA-AI-LLM-03** (error): Excessive permissions (Bash, Write, Edit all granted without scoping)
4. **SA-AI-LLM-04** (warning): "execute their code" suggests LLM output goes to shell without validation

---

## Reference Docs

All 64 reference docs are in `skills/security-audit/references/`.

**Standards & Scoring:**

| Reference | Coverage |
|---|---|
| `owasp-top10.md` | OWASP Top 10 (2021) |
| `cwe-top25.md` | CWE Top 25 (2025) |
| `cvss-scoring.md` | CVSS v3.1 and v4.0 scoring methodology |
| `cve-database.md` | 113 CVEs mapped to checkpoints |

**Language Security Features:**

| Reference | Coverage |
|---|---|
| `php-security-features.md` | PHP 8.0-8.4 |
| `javascript-typescript-security-features.md` | JS/TS + ES2020+ |
| `nodejs-security-features.md` | Node.js 16-22 |
| `python-security-features.md` | Python 3.9-3.13 |
| `java-security-features.md` | Java 11-21 |
| `csharp-security-features.md` | C# 9-12 |
| `go-security-features.md` | Go 1.18-1.22 |
| `rust-security-features.md` | Rust editions |
| `ruby-security-features.md` | Ruby 3.0-3.3 |

**Framework Security:**

| Reference | Coverage |
|---|---|
| `react-security.md` | React (dangerouslySetInnerHTML, JSX injection) |
| `nextjs-security.md` | Next.js (Server Actions, NEXT_PUBLIC_ leaks) |
| `vue-security.md` | Vue (v-html, template injection) |
| `angular-security.md` | Angular (bypassSecurityTrust, DomSanitizer) |
| `nuxt-security.md` | Nuxt (server routes, runtimeConfig) |
| `django-security.md` | Django (ORM injection, CSRF, mark_safe) |
| `flask-security.md` | Flask (SSTI, debug mode, session tampering) |
| `fastapi-security.md` | FastAPI (auth deps, Pydantic, CORS) |
| `spring-security.md` | Spring (SpEL, actuator, permitAll) |
| `dotnet-security.md` | ASP.NET Core (middleware, EF, Razor) |
| `blazor-security.md` | Blazor (WASM auth, JS interop) |
| `gin-security.md` | Gin (middleware, template injection) |
| `rails-security.md` | Rails (mass assignment, html_safe) |
| `express-security.md` | Express (helmet, sendFile, sessions) |
| `nestjs-security.md` | NestJS (guards, DTOs, @Public) |
| `typo3-security.md` | TYPO3 (QueryBuilder, Extbase) |
| `symfony-security.md` | Symfony (voters, firewall, CSRF) |
| `laravel-security.md` | Laravel (Eloquent, gates, Crypt) |

**Cloud, CMS & Mobile:**

| Reference | Coverage |
|---|---|
| `aws-security.md` | AWS IAM, S3, Lambda, Security Groups, KMS |
| `gcp-security.md` | GCP IAM, Cloud Storage, Cloud Functions, VPC |
| `azure-security.md` | Azure RBAC, Blob Storage, NSGs, Key Vault |
| `wordpress-security.md` | WordPress ($wpdb, nonces, REST API) |
| `drupal-security.md` | Drupal (db_query, #markup, entity access) |
| `joomla-security.md` | Joomla (JInput, JDatabaseQuery, ACL) |
| `android-sdk-security.md` | Android (Intents, WebView, manifest flags) |
| `ios-sdk-security.md` | iOS (Keychain, ATS, UIWebView, URL schemes) |

**Infrastructure, APIs & AI:**

| Reference | Coverage |
|---|---|
| `iac-security.md` | Dockerfile, K8s, Terraform, Docker Compose |
| `api-security.md` | OWASP API Top 10 (2025), GraphQL, REST |
| `frontend-security.md` | DOM XSS, SRI, CORS, postMessage |
| `llm-security.md` | OWASP LLM Top 10 (2025), agent/skill auditing |

**Vulnerability Prevention:**

| Reference | Coverage |
|---|---|
| `xxe-prevention.md` | XML External Entity prevention |
| `path-traversal-prevention.md` | Path traversal prevention |
| `input-validation.md` | Input validation patterns |
| `authentication-patterns.md` | Auth, sessions, JWT |
| `cryptography-guide.md` | Encryption, hashing, key management |
| `security-headers.md` | HSTS, CSP, CORS headers |
| `security-logging.md` | Audit logging patterns |
| `api-key-encryption.md` | API key encryption at rest |

**DevSecOps & Supply Chain:**

| Reference | Coverage |
|---|---|
| `ci-security-pipeline.md` | CI/CD security integration |
| `automated-scanning.md` | Semgrep, Trivy, Gitleaks setup |
| `supply-chain-security.md` | SLSA, SBOM, dependency security |
| `supply-chain-incident-response.md` | Incident response playbooks |
| `modern-attacks.md` | SSRF, prototype pollution, cache poisoning |
| `cve-patterns.md` | CVE pattern references |

**Compliance Mappings:**

| Reference | Coverage |
|---|---|
| `compliance-soc2.md` | SOC 2 Trust Services Criteria → checkpoints |
| `compliance-iso27001.md` | ISO 27001:2022 Annex A → checkpoints |
| `compliance-pci-dss.md` | PCI DSS v4.0 → checkpoints |
| `compliance-hipaa.md` | HIPAA Security Rule → checkpoints |
| `compliance-gdpr.md` | GDPR Article 32 → checkpoints |
| `compliance-nist-csf.md` | NIST CSF 2.0 → checkpoints |

---

## CVSS Scoring

When findings are reported, severity follows CVSS v4.0 methodology:

| Severity | CVSS Score | Action |
|---|---|---|
| Critical | 9.0 - 10.0 | Fix immediately |
| Error / High | 7.0 - 8.9 | Fix before merge |
| Warning / Medium | 4.0 - 6.9 | Fix in next sprint |
| Info / Low | 0.1 - 3.9 | Track and review |

See `references/cvss-scoring.md` for detailed scoring methodology.
