# Security Audit Skill

Security vulnerability detection for AI agents and IDEs. 408 checkpoints across 9 languages, 18 frameworks, 3 cloud providers, 4 CMS platforms, 2 mobile SDKs, with compliance mapping to 6 frameworks.

## Compatibility

This is an **Agent Skill** following the [open standard](https://agentskills.io) originally developed by Anthropic and released for cross-platform use.

**Supported Platforms:**
- Claude Code (Anthropic)
- Cursor
- GitHub Copilot
- Other skills-compatible AI agents

> Skills are portable packages of procedural knowledge that work across any AI agent supporting the Agent Skills specification.

## What It Does

### Static Analysis (408 Checkpoints)

| Category | Checkpoints | Languages/Frameworks |
|---|---|---|
| **Languages** | SA-PY, SA-JS, SA-NODE, SA-JAVA, SA-CS, SA-GO, SA-RS, SA-RB, SA-PHP | Python, JavaScript, Node.js, Java, C#, Go, Rust, Ruby, PHP |
| **Frameworks** | SA-REACT, SA-NEXT, SA-VUE, SA-ANG, SA-DJANGO, SA-FLASK, SA-SPRING, SA-LARAVEL, SA-SYMFONY | React, Next.js, Vue, Angular, Django, Flask, Spring, Laravel, Symfony |
| **Cloud** | SA-AWS, SA-GCP, SA-AZURE | AWS, GCP, Azure |
| **CMS** | SA-WP, SA-DRUPAL, SA-JOOMLA, SA-TYPO3 | WordPress, Drupal, Joomla, TYPO3 |
| **Mobile** | SA-ANDROID, SA-IOS | Android SDK, iOS SDK |
| **Infrastructure** | SA-01..SA-20 | Dockerfile, Kubernetes, Terraform, Compose |
| **Runtime** | LIVE-HDR, LIVE-TLS, LIVE-CORS | Headers, TLS, CORS |

### Dependency Sandbox

Installs packages in a hardened Docker container with strace monitoring. Detects supply chain attacks: unauthorized network connections, file writes, process spawning, credential harvesting.

```bash
# Single package
./scripts/dependency-sandbox.sh npm lodash
./scripts/dependency-sandbox.sh pip requests

# Full project (from lockfile)
./scripts/dependency-sandbox.sh pnpm-project ./pnpm-lock.yaml
./scripts/dependency-sandbox.sh uv-project ./uv.lock
./scripts/dependency-sandbox.sh go-project ./go.sum
./scripts/dependency-sandbox.sh rust-project ./Cargo.lock
./scripts/dependency-sandbox.sh dotnet-project ./packages.lock.json
```

**Output artifacts:**
- `audit.json` — CVE audit from the package manager (pnpm audit, pip-audit, govulncheck, cargo-audit)
- `sbom.json` — CycloneDX 1.5 SBOM (full transitive dependency tree)
- `deps.json` — Raw dependency tree with metadata
- `ips.txt` — Public IPs contacted (for reverse DNS)
- `strace.log` — Raw syscall trace

**Container security:**
- Read-only root filesystem
- Non-root user (UID 10001)
- All capabilities dropped (`--cap-drop=ALL`)
- No new privileges (`--security-opt=no-new-privileges`)
- Memory and PID limits
- Network monitored via strace (not blocked — so postinstall scripts are observed)

### Multi-Language Scanner

Auto-detects project stack and runs language-specific scanners:

```bash
./scripts/security-audit-dispatcher.sh /path/to/project
```

19 scanner modules: Python, JavaScript, Node.js, Java, C#, Go, Rust, Ruby, PHP, React, Django, Flask, Spring, WordPress, Drupal, Joomla, AWS, GCP, Azure.

### IDE Integration

| Package | Description |
|---|---|
| `packages/core` | TypeScript detection engine (loads checkpoints, runs regex matching) |
| `packages/mcp-server` | MCP server with 7 tools for AI IDEs |
| `packages/lsp-server` | LSP server for traditional editors |
| `packages/vscode-ext` | VS Code extension (sidebar, quick-fix, status bar) |
| `packages/jetbrains-plugin` | JetBrains plugin (IntelliJ, PyCharm, WebStorm) |
| `packages/runtime-agent` | Node.js + Python taint tracing |

### CVE Enrichment

Correlates findings with real CVEs via NVD and OSV APIs. Maps checkpoint CWE IDs to known vulnerabilities with CVSS scores and advisory links.

### Compliance Mapping

Checkpoints mapped to 6 compliance frameworks:
- SOC 2 Type II
- ISO 27001:2022
- PCI DSS v4.0
- HIPAA Security Rule
- GDPR Article 32
- NIST CSF 2.0

## Installation

### npx ([skills.sh](https://skills.sh))

```bash
npx skills add https://github.com/evandervecht/security-audit-skill --skill security-audit
```

### Git Clone

```bash
git clone https://github.com/evandervecht/security-audit-skill.git
```

## Usage

> For detailed usage instructions, see **[docs/USAGE.md](docs/USAGE.md)**.

### Example Queries

```
"Audit this code for security vulnerabilities"
"Check my pnpm-lock.yaml for CVEs"
"Score this vulnerability using CVSS v4.0"
"Run an OWASP Top 10 audit on this project"
"Audit this Dockerfile for security best practices"
"Check the API endpoints for BOLA vulnerabilities"
"Audit this AI skill for prompt injection risks"
```

### Automated Scripts

```bash
# Multi-language security scan
./scripts/security-audit-dispatcher.sh /path/to/project

# Dependency sandbox
./scripts/dependency-sandbox.sh pnpm-project ./pnpm-lock.yaml

# PHP project audit
./skills/security-audit/scripts/security-audit.sh /path/to/project

# GitHub repository audit
./skills/security-audit/scripts/github-security-audit.sh owner/repo
```

## Repository Structure

```
security-audit-skill/
├── skills/security-audit/
│   ├── SKILL.md                        # Skill entry point
│   ├── checkpoints.yaml                # 408 checkpoints (372 mechanical + 36 LLM)
│   ├── evals/                          # 154 eval fixture tests
│   └── references/                     # 63 security reference files
│       ├── owasp-top10.md
│       ├── cwe-top25.md
│       ├── compliance-soc2.md          # + 5 more compliance frameworks
│       ├── aws-security.md             # + gcp, azure
│       ├── wordpress-security.md       # + drupal, joomla
│       ├── android-sdk-security.md     # + ios
│       └── ...                         # 63 files total
├── scripts/
│   ├── security-audit-dispatcher.sh    # Multi-language scanner
│   ├── dependency-sandbox.sh           # Sandboxed dependency audit
│   ├── scanners/                       # 19 language/framework scanner modules
│   └── sandbox/                        # Docker sandbox (7 ecosystems)
│       ├── Dockerfile.pnpm             # + npm, pip, uv, go, rust, dotnet
│       ├── entrypoint-pnpm.sh          # Install + audit + SBOM generation
│       └── analyze-strace.sh           # Supply chain behavior analysis
├── packages/
│   ├── core/                           # TypeScript detection engine
│   ├── mcp-server/                     # MCP server (7 tools)
│   ├── lsp-server/                     # LSP server
│   ├── vscode-ext/                     # VS Code extension
│   ├── jetbrains-plugin/               # JetBrains IDE plugin (Kotlin)
│   └── runtime-agent/                  # Node.js + Python taint tracing
├── docs/
│   ├── USAGE.md
│   ├── ARCHITECTURE.md
│   └── CONTRIBUTING-REFERENCES.md
├── SECURITY.md
└── CLAUDE.md
```

## Numbers

| | |
|---|---|
| Checkpoints | 408 (372 mechanical + 36 LLM review) |
| Reference files | 63 |
| Scanner modules | 19 |
| Eval fixtures | 154 |
| Languages | 9 |
| Frameworks | 18 |
| Cloud providers | 3 (AWS, GCP, Azure) |
| CMS platforms | 4 (WordPress, Drupal, Joomla, TYPO3) |
| Mobile SDKs | 2 (Android, iOS) |
| Compliance frameworks | 6 |
| Sandbox ecosystems | 7 (npm/pnpm, pip/uv, Go, Rust, .NET) |
| IDE integrations | 4 (VS Code, JetBrains, MCP, LSP) |

## CI

Tests run on push/PR to main:
- `test_risky_patterns.py` — hook pattern tests
- `validate_checkpoints.py` — checkpoint YAML + namespace validation
- `test_eval_fixtures.py` — regex fixture tests (182 tests)

## License

[MIT](LICENSE-MIT)

## Credits

Developed and maintained by [E van der Vecht](https://github.com/evandervecht).
