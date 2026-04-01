# Security Audit Skill - Usage Guide

How to apply the security audit skill to any project: PHP applications, Infrastructure-as-Code, APIs, frontend code, and AI agent skills/configurations.

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

Or run the automated script directly:

```bash
# From within the security-audit-skill directory
./skills/security-audit/scripts/security-audit.sh /path/to/your/project
```

This scans `src/` and `Classes/` directories for:
- Hardcoded secrets
- SQL injection patterns
- XXE vulnerabilities
- Command injection
- XSS patterns
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

### PHP / TYPO3 / Symfony / Laravel

The skill's core strength. Covers 80+ checkpoints including:

- **OWASP Top 10**: Injection, XSS, CSRF, SSRF, XXE, broken access control
- **CWE Top 25**: Type juggling, deserialization, path traversal, command injection
- **Framework-specific**: TYPO3 Extbase, Symfony components, Laravel Eloquent

```
"Run the OWASP Top 10 audit on this PHP project"
"Check for XXE vulnerabilities in the XML parsing code"
"Audit the TYPO3 extension for CWE Top 25 issues"
```

### Infrastructure-as-Code (Dockerfiles, Kubernetes, Terraform)

Reference: `references/iac-security.md`

The skill detects:
- Dockerfiles running as root, secrets in layers, unpinned base images
- Docker Compose privileged mode, Docker socket mounts
- Kubernetes pods without securityContext, missing NetworkPolicy, overly permissive RBAC
- Terraform public S3 buckets, open security groups, unencrypted storage

```
"Audit the Dockerfile for security issues"
"Check the Kubernetes manifests in k8s/ for misconfigurations"
"Review the Terraform files for public access risks"
```

### APIs (REST, GraphQL)

Reference: `references/api-security.md`

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

Reference: `references/frontend-security.md`

Detects:
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

All reference docs are in `skills/security-audit/references/`. Read them for deep-dive patterns:

| Reference | Coverage |
|---|---|
| `owasp-top10.md` | OWASP Top 10 (2021) with PHP patterns |
| `cwe-top25.md` | CWE Top 25 (2025) |
| `api-security.md` | OWASP API Top 10 (2025), GraphQL, REST |
| `iac-security.md` | Dockerfile, K8s, Terraform, Docker Compose |
| `frontend-security.md` | DOM XSS, SRI, CORS, postMessage |
| `llm-security.md` | OWASP LLM Top 10 (2025), agent/skill auditing |
| `xxe-prevention.md` | XML External Entity prevention |
| `authentication-patterns.md` | Auth, sessions, JWT |
| `cryptography-guide.md` | Encryption, hashing, key management |
| `supply-chain-security.md` | SLSA, SBOM, dependency security |
| `ci-security-pipeline.md` | CI/CD security integration |
| `automated-scanning.md` | Semgrep, Trivy, Gitleaks setup |
| `modern-attacks.md` | SSRF, prototype pollution, cache poisoning |
| `security-headers.md` | HSTS, CSP, CORS headers |
| `security-logging.md` | Audit logging patterns |
| `typo3-security.md` | TYPO3 security patterns |
| `symfony-security.md` | Symfony security patterns |
| `laravel-security.md` | Laravel security patterns |
| `cvss-scoring.md` | CVSS v3.1 and v4.0 scoring methodology |

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
