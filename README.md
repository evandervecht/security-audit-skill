# Security Audit Skill

Security audit patterns (OWASP Top 10, CWE Top 25 2025, CVSS v4.0) and GitHub project security checks for **any project**. Deep scanning across PHP/TYPO3, Infrastructure-as-Code, APIs, frontend code, and AI agent skills/configurations with 119+ checkpoints, 23 reference guides, and PreToolUse warnings.

## Compatibility

This is an **Agent Skill** following the [open standard](https://agentskills.io) originally developed by Anthropic and released for cross-platform use.

**Supported Platforms:**
- Claude Code (Anthropic)
- Cursor
- GitHub Copilot
- Other skills-compatible AI agents

> Skills are portable packages of procedural knowledge that work across any AI agent supporting the Agent Skills specification.


## Features

- **Vulnerability Assessment**: XXE injection, SQL injection, XSS, CSRF, command injection, path traversal, file upload vulnerabilities, insecure deserialization, SSRF, type juggling, SSTI, JWT flaws, LDAP injection, email header injection, session fixation
- **Risk Scoring**: CVSS v3.1 and v4.0 scoring methodology, risk matrix assessment, impact and likelihood analysis, prioritization frameworks
- **Secure Coding**: Input validation, output encoding, cryptographic best practices (sodium), session management, authentication patterns, security headers
- **Standards Compliance**: OWASP Top 10, CWE Top 25 (2025), OWASP ASVS v4.0, Proactive Controls — applicable to any project
- **PHP/TYPO3 Deep Scanning**: 80+ automated checkpoints, PHP 8.x security features, framework patterns (TYPO3, Symfony, Laravel)
- **Infrastructure-as-Code**: Dockerfile security (root user, secrets in layers, unpinned images), Docker Compose (privileged mode, socket mounts), Kubernetes (RBAC, NetworkPolicy, pod security), Terraform (public access, encryption)
- **API Security**: OWASP API Top 10 (2023), GraphQL (introspection, depth limits, batching), REST hardening, BOLA/IDOR, mass assignment, rate limiting
- **Frontend Security**: DOM-based XSS, Subresource Integrity (SRI), CORS misconfiguration, postMessage validation, localStorage secrets, client-side open redirects
- **AI/LLM Agent Security**: OWASP LLM Top 10 (2025), prompt injection defense, excessive agency detection, MCP server auditing, system prompt leakage, agent permission least-privilege analysis
- **DevSecOps**: CI/CD security pipeline, SAST, dependency scanning, supply chain security, SLSA

## Installation

### npx ([skills.sh](https://skills.sh))

Install with any [Agent Skills](https://agentskills.io)-compatible agent:

```bash
npx skills add https://github.com/evandervecht/security-audit-skill --skill security-audit
```

### Download Release

Download the [latest release](https://github.com/evandervecht/security-audit-skill/releases/latest) and extract to your agent's skills directory.

### Git Clone

```bash
git clone https://github.com/evandervecht/security-audit-skill.git
```

## Usage

> For detailed usage instructions, step-by-step guides for each project type, and examples of auditing AI agent skills, see **[docs/USAGE.md](docs/USAGE.md)**.

This skill is automatically triggered when:

- Conducting security assessments on any project type
- Identifying vulnerabilities (XXE, SQL injection, XSS, CSRF, command injection)
- Scoring security risks with CVSS v3.1 or v4.0
- Auditing PHP, Dockerfile, Kubernetes, Terraform, or frontend code
- Reviewing API endpoints for OWASP API Top 10 issues
- Auditing AI agent skills, MCP servers, or agent configurations
- Setting up CI/CD security pipelines

### Example Queries

**PHP / Application Security:**
- "Audit this code for XXE vulnerabilities"
- "Check for SQL injection risks"
- "Score this vulnerability using CVSS v4.0"
- "Review authentication implementation for security flaws"

**Infrastructure-as-Code:**
- "Review this Dockerfile for security best practices"
- "Check the Kubernetes manifests for misconfigurations"
- "Audit the Terraform files for public access risks"

**API Security:**
- "Audit the API endpoints for BOLA vulnerabilities"
- "Check if GraphQL introspection is disabled in production"
- "Review the API rate limiting configuration"

**Frontend:**
- "Check the JavaScript files for DOM XSS vulnerabilities"
- "Audit the CORS configuration"
- "Are there any sensitive tokens stored in localStorage?"

**AI Agent / LLM Security:**
- "Audit this AI skill for prompt injection risks"
- "Check if the MCP server config has supply chain issues"
- "Run an OWASP LLM Top 10 audit on this agent configuration"
- "Review the allowed-tools for least-privilege violations"

### Auditing a Downloaded AI Skill

You can use this skill to audit any AI agent skill or configuration downloaded from GitHub:

```bash
# 1. Clone the skill you want to audit
git clone https://github.com/someone/their-cool-skill.git /tmp/skill-to-audit
cd /tmp/skill-to-audit

# 2. Ask your AI agent (with security-audit-skill installed):
#    "Audit this AI skill for security issues using the OWASP LLM Top 10"
```

The skill checks SKILL.md, AGENTS.md, CLAUDE.md, mcp.json, hooks.json, and settings files for:

| Check | What It Detects |
|---|---|
| Prompt Injection (LLM01) | External content ingested without segregation, missing input validation |
| Sensitive Disclosure (LLM02) | Hardcoded API keys/secrets in skill configs, sensitive files loaded into context |
| Supply Chain (LLM03) | Unpinned MCP server versions, unverified skill sources |
| Improper Output (LLM05) | LLM output passed to shell without validation, auto-executed code |
| Excessive Agency (LLM06) | Unrestricted Bash access, missing human approval gates, over-permissioned tools |
| Prompt Leakage (LLM07) | Credentials in system prompts, security controls only in prompt text |

See [docs/USAGE.md](docs/USAGE.md) for complete examples with sample findings.

### Automated Scripts

```bash
# PHP project security audit
./skills/security-audit/scripts/security-audit.sh /path/to/project

# GitHub repository security audit
./skills/security-audit/scripts/github-security-audit.sh owner/repo
```

## Structure

```
security-audit-skill/
├── SKILL.md                              # Skill metadata and core patterns
├── SECURITY.md                           # Security policy
├── docs/
│   ├── USAGE.md                          # Detailed usage guide
│   └── ARCHITECTURE.md                   # System architecture
├── hooks/
│   └── hooks.json                        # PreToolUse hook configuration
├── scripts/
│   ├── check_risky_command.py            # Risky command detection hook
│   └── validate_checkpoints.py           # Checkpoint YAML validator
├── skills/security-audit/
│   ├── SKILL.md                          # Skill definition (v3.0.0)
│   ├── checkpoints.yaml                  # 119+ automated security checkpoints
│   ├── scripts/
│   │   ├── security-audit.sh             # PHP project security audit
│   │   └── github-security-audit.sh      # GitHub repo security audit
│   └── references/
│       ├── owasp-top10.md                # OWASP Top 10 patterns
│       ├── cwe-top25.md                  # CWE Top 25 (2025) coverage map
│       ├── api-security.md               # OWASP API Top 10 (2023), GraphQL, REST
│       ├── iac-security.md               # Dockerfile, K8s, Terraform, Compose
│       ├── frontend-security.md          # DOM XSS, SRI, CORS, postMessage
│       ├── llm-security.md               # OWASP LLM Top 10 (2025), agent auditing
│       ├── xxe-prevention.md             # XXE detection and prevention
│       ├── cvss-scoring.md               # CVSS v3.1 & v4.0 scoring
│       ├── api-key-encryption.md         # API key encryption (sodium)
│       ├── authentication-patterns.md    # Auth, session, JWT, MFA
│       ├── security-headers.md           # HTTP security headers
│       ├── security-logging.md           # Security logging & monitoring
│       ├── input-validation.md           # Input validation & encoding
│       ├── cryptography-guide.md         # Cryptographic best practices
│       ├── framework-security.md         # TYPO3/Symfony/Laravel security
│       ├── modern-attacks.md             # SSRF, mass assignment, race conditions
│       ├── cve-patterns.md               # CVE-derived patterns
│       ├── php-security-features.md      # PHP 8.x security features
│       ├── ci-security-pipeline.md       # CI/CD security tooling
│       ├── supply-chain-security.md      # SLSA, signing, OpenSSF
│       ├── supply-chain-incident-response.md  # Incident response playbooks
│       ├── path-traversal-prevention.md  # Path traversal prevention
│       └── automated-scanning.md         # Semgrep, Trivy, Gitleaks setup
└── .github/
    ├── dependabot.yml                    # Automated dependency updates
    └── workflows/
        ├── release.yml                   # Release automation
        └── ci.yml                        # ShellCheck, Python lint, tests
```

## Expertise Areas

### Vulnerability Assessment
- XXE (XML External Entity) injection detection
- SQL injection pattern recognition
- XSS (Cross-Site Scripting) analysis
- CSRF protection verification
- Command injection detection
- Path traversal prevention
- File upload security
- Insecure deserialization
- SSRF detection
- Authentication/authorization flaws

### Infrastructure-as-Code
- Dockerfile: root user, secrets in layers, unpinned base images, ADD vs COPY
- Docker Compose: privileged mode, Docker socket mounts, exposed ports
- Kubernetes: RBAC, NetworkPolicy, pod security contexts, host namespaces
- Terraform: public S3 buckets, open security groups, unencrypted storage

### API Security
- OWASP API Top 10 (2023): BOLA, mass assignment, rate limiting, function-level auth
- GraphQL: introspection, query depth/complexity limits, batching attacks
- REST: versioning security, content-type validation, CORS configuration

### Frontend Security
- DOM-based XSS: sinks (innerHTML, document.write, eval) and sources (location, postMessage)
- Subresource Integrity (SRI) for CDN assets
- CORS misconfiguration detection
- Client-side storage (localStorage/sessionStorage) sensitive data exposure
- postMessage origin validation

### AI/LLM Agent Security
- OWASP LLM Top 10 (2025) mapped to agent/skill auditing
- Prompt injection defense (direct, indirect, tool output)
- Excessive agency detection (tool permissions, human approval gates)
- MCP server supply chain verification (version pinning, source trust)
- System prompt leakage (secrets, infrastructure details)
- Improper output handling (LLM output to shell/code without validation)

### Risk Scoring
- CVSS v3.1 scoring methodology
- CVSS v4.0 scoring methodology
- Risk matrix assessment
- Impact and likelihood analysis
- Prioritization frameworks

### Secure Coding
- Input validation patterns
- Output encoding strategies
- Secure configuration
- Cryptographic best practices (sodium)
- Session management
- Authentication patterns (Argon2, JWT, MFA)
- Security headers (HSTS, CSP)

### DevSecOps
- SAST integration (PHPStan, Semgrep, CodeQL)
- Dependency scanning (composer audit, Trivy, npm audit)
- Supply chain security (SLSA, Sigstore)
- Container security (Hadolint, Trivy)
- SBOM generation (CycloneDX)

## Security Audit Checklist

### Authentication & Authorization
- Password hashing uses bcrypt/Argon2 (PASSWORD_ARGON2ID)
- Session tokens are cryptographically random (random_bytes)
- Session fixation protection enabled (session_regenerate_id)
- CSRF tokens on all state-changing operations
- Authorization checks on all protected resources
- Rate limiting on authentication endpoints

### Input Handling
- All input validated server-side
- Parameterized queries for all SQL
- XML parsing with external entities disabled (LIBXML_NONET only)
- File uploads restricted by type (MIME validation) and size
- Path traversal prevention on file operations
- No unserialize() with user input

### Output Handling
- Context-appropriate output encoding (htmlspecialchars)
- Content-Type headers set correctly
- X-Content-Type-Options: nosniff
- Content-Security-Policy configured
- X-Frame-Options or CSP frame-ancestors set
- Strict-Transport-Security (HSTS) enabled

### Data Protection
- Sensitive data encrypted at rest (sodium_crypto_secretbox)
- TLS 1.2+ for data in transit
- Secrets not in version control
- PII handling compliant with regulations
- Audit logging for sensitive operations

### Infrastructure-as-Code
- Dockerfiles use non-root USER, no secrets in layers or ARGs
- Docker Compose avoids privileged mode and Docker socket mounts
- Kubernetes pods have securityContext, NetworkPolicy, least-privilege RBAC
- Terraform resources not publicly accessible, storage encrypted

### API Endpoints
- Object-level authorization (BOLA) on all data-access endpoints
- Function-level authorization on admin endpoints
- Rate limiting and pagination enforced
- GraphQL introspection disabled in production
- API error responses don't leak internal details

### Frontend
- No sensitive data in localStorage/sessionStorage
- SRI attributes on CDN-hosted scripts
- CORS configured with specific origins (not wildcards)
- postMessage handlers validate origin
- No DOM XSS sinks with user-controlled input

### AI Agent Security
- Agent skills follow least-privilege for tool permissions
- MCP server versions pinned (not "latest")
- No secrets in system prompts or skill definitions
- LLM output validated before shell execution or code generation
- Safety hooks cover high-impact operations
- External content treated as untrusted data

## Related Skills

- **enterprise-readiness-skill**: References this skill for security assessment
- **php-modernization-skill**: Type safety enhances security
- **typo3-testing-skill**: Security test patterns

## License

[MIT](LICENSE-MIT)

## Credits

Developed and maintained by [E van der Vecht](https://github.com/evandervecht).
