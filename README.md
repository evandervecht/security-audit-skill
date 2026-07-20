# Security Audit Skill

Security vulnerability detection for AI agents and IDEs. 557 checkpoints across 15 languages, 26 frameworks, 3 cloud providers, 4 CMS platforms, 2 mobile SDKs, plus GraphQL API and Kubernetes manifest scanning, with compliance mapping to 7 frameworks.

## Original Owners 
[Netsearch]https://github.com/netresearch/security-audit-skill

## Compatibility

This is an **Agent Skill** following the [open standard](https://agentskills.io) originally developed by Anthropic and released for cross-platform use.

**Supported Platforms:**
- Claude Code (Anthropic)
- Cursor
- GitHub Copilot
- Other skills-compatible AI agents

> Skills are portable packages of procedural knowledge that work across any AI agent supporting the Agent Skills specification.

## What It Does

### Static Analysis (557 Checkpoints)

| Category | Checkpoints | Languages/Frameworks |
|---|---|---|
| **Languages** | SA-PY, SA-JS, SA-NODE, SA-JAVA, SA-CS, SA-GO, SA-RS, SA-RB, SA-PHP, SA-EX, SA-KT, SA-SWIFT, SA-SCALA, SA-DART, SA-SH | Python, JavaScript, Node.js, Java, C#, Go, Rust, Ruby, PHP, Elixir, Kotlin, Swift, Scala, Dart, Shell |
| **Frameworks** | SA-REACT, SA-NEXT, SA-VUE, SA-ANG, SA-NUXT, SA-SVELTE, SA-DJANGO, SA-FLASK, SA-FASTAPI, SA-SPRING, SA-DOTNET, SA-BLAZOR, SA-GIN, SA-RAILS, SA-EXPRESS, SA-NEST, SA-LARAVEL, SA-SYMFONY, SA-PHOENIX, SA-KTOR, SA-VAPOR, SA-PLAY, SA-ACTIX, SA-AXUM, SA-FLUTTER | React, Next.js, Vue, Angular, Nuxt, Svelte, Django, Flask, FastAPI, Spring, .NET, Blazor, Gin, Rails, Express, NestJS, Laravel, Symfony, Phoenix, Ktor, Vapor, Play, Actix, Axum, Flutter |
| **Cloud** | SA-AWS, SA-GCP, SA-AZURE | AWS, GCP, Azure |
| **CMS** | SA-WP, SA-DRUPAL, SA-JOOMLA, SA-TYPO3 | WordPress, Drupal, Joomla, TYPO3 |
| **Mobile** | SA-ANDROID, SA-IOS | Android SDK, iOS SDK |
| **API** | SA-GRAPHQL, SA-API | GraphQL, REST (OWASP API Top 10) |
| **Infrastructure** | SA-01..SA-20, SA-IAC, SA-KUBE | Dockerfile, Kubernetes, Terraform, Compose |
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

31 scanner modules: Python, JavaScript, Node.js, Java, C#, Go, Rust, Ruby, PHP, Kotlin, Swift, Scala, Dart/Flutter, Shell, Elixir, Ktor, Vapor, Play, Actix/Axum, GraphQL, Kubernetes, Svelte, WordPress, Drupal, Joomla, Android, iOS, AWS, GCP, Azure, plus a cross-cutting secrets scanner.

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

Checkpoints mapped to 7 compliance frameworks:
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
│   ├── checkpoints.yaml                # 557 checkpoints (517 mechanical + 40 LLM)
│   ├── evals/                          # 536 eval fixture tests
│   └── references/                     # 81 security reference files
│       ├── owasp-top10.md
│       ├── cwe-top25.md
│       ├── compliance-soc2.md          # + 6 more compliance frameworks
│       ├── aws-security.md             # + gcp, azure
│       ├── wordpress-security.md       # + drupal, joomla
│       ├── android-sdk-security.md     # + ios
│       └── ...                         # 81 files total
├── scripts/
│   ├── security-audit-dispatcher.sh    # Multi-language scanner
│   ├── dependency-sandbox.sh           # Sandboxed dependency audit
│   ├── scanners/                       # 31 language/framework scanner modules
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
| Checkpoints | 557 (517 mechanical + 40 LLM review) |
| Reference files | 81 |
| Scanner modules | 31 |
| Eval fixtures | 536 |
| Languages | 15 |
| Frameworks | 26 |
| Cloud providers | 3 (AWS, GCP, Azure) |
| CMS platforms | 4 (WordPress, Drupal, Joomla, TYPO3) |
| Mobile SDKs | 2 (Android, iOS) |
| Compliance frameworks | 7 |
| Sandbox ecosystems | 7 (npm/pnpm, pip/uv, Go, Rust, .NET) |
| IDE integrations | 4 (VS Code, JetBrains, MCP, LSP) |

## Expertise Areas

### Vulnerability Detection

**Injection Attacks:**
SQL injection (parameterized queries, ORM misuse), command injection (shell exec, subprocess), XSS (reflected, stored, DOM-based), XXE (XML external entities, LIBXML_NONET), SSTI (server-side template injection), LDAP injection, email header injection, log injection.

**Authentication & Session:**
Weak password hashing (MD5/SHA1 vs Argon2/bcrypt), session fixation, JWT algorithm confusion (none/HS256 forgery), insecure token storage, missing MFA enforcement, credential stuffing exposure, session timeout misconfigurations.

**Data Exposure:**
Insecure deserialization (pickle, ObjectInputStream, BinaryFormatter, Marshal.load, YAML.load), path traversal (directory escape, symlink attacks), file upload bypass (MIME spoofing, double extensions, polyglots), SSRF (internal network scanning, cloud metadata), information leakage (stack traces, verbose errors, directory listings).

**Logic Flaws:**
CSRF (missing tokens, SameSite cookie bypass), IDOR/BOLA (direct object references without authorization), mass assignment (unprotected model binding), race conditions (TOCTOU, double-spend), type juggling (PHP loose comparison), open redirects.

### Language-Specific Patterns

| Language | Key Checks |
|---|---|
| **Python** | pickle/yaml.load deserialization, eval/exec injection, subprocess shell=True, Django raw SQL, Flask SSTI, assert in production |
| **JavaScript** | eval/Function constructor, innerHTML/document.write XSS, prototype pollution, regex DoS, postMessage origin bypass |
| **Node.js** | child_process injection, path traversal (path.join with user input), vm sandbox escape, Express session secrets |
| **Java** | ObjectInputStream deserialization, JNDI injection (Log4Shell pattern), SpEL injection, SQL concatenation, XXE in DocumentBuilder |
| **C#** | BinaryFormatter deserialization, FromSqlRaw injection, Regex DoS, LDAP injection, XML resolver XXE |
| **Go** | SQL string concatenation, InsecureSkipVerify TLS bypass, unsafe pointer use, template injection, goroutine race conditions |
| **Rust** | Unsafe blocks (memory safety bypass), unchecked unwrap on user input, SQL format strings, command injection via std::process |
| **Ruby** | Marshal.load/YAML.load deserialization, ERB injection, send/public_send with user input, open() command injection |
| **PHP** | unserialize() with user input, extract() variable overwrite, preg_e modifier code execution, type juggling in auth, include with user path |
| **Kotlin** | Runtime.exec/ProcessBuilder injection, SQL string templates, java.util.Random tokens, trust-all TrustManager, ObjectInputStream deserialization, ECB mode |
| **Swift** | NSKeyedUnarchiver without secure coding, Process /bin/sh -c, ATS bypass, blanket URLCredential trust, UserDefaults secrets, kSecAttrAccessibleAlways |
| **Scala** | ObjectInputStream deserialization, sys.process interpolation, anorm SQL interpolation, scala.util.Random tokens, XXE via factory defaults, Class.forName reflection |
| **Dart** | Process.run shell injection, badCertificateCallback bypass, Random() secrets, sqflite rawQuery interpolation, Isolate.spawnUri remote code, http:// endpoints |
| **Shell** | eval on variables, curl-pipe-to-shell, curl -k/--insecure, StrictHostKeyChecking=no, predictable temp files, chmod 777, unquoted rm -rf, secrets in ps/logs |

### Framework Security

| Framework | Key Checks |
|---|---|
| **React** | dangerouslySetInnerHTML XSS, href="javascript:" injection, unescaped user content in JSX |
| **Next.js** | NEXT_PUBLIC_ secret exposure, getServerSideProps data leaks, API route auth bypass, middleware edge cases |
| **Vue** | v-html XSS, dynamic component injection, SSR hydration mismatches |
| **Angular** | bypassSecurityTrust* misuse, template injection, innerHTML binding |
| **Django** | raw() SQL injection, |safe template filter XSS, CSRF_COOKIE_HTTPONLY, DEBUG=True in production |
| **Flask** | Jinja2 SSTI via user templates, secret_key hardcoding, missing CSRF protection, debug mode |
| **Spring** | SpEL injection, actuator exposure, CSRF disabled on state-changing endpoints, mass assignment via ModelAttribute |
| **Laravel** | Blade {!! !!} unescaped output, DB::raw injection, mass assignment ($guarded vs $fillable), APP_DEBUG=true |
| **Ktor** | CORS anyHost() (esp. with credentials), JWT Algorithm.none / hardcoded HMAC secrets, HTML respondText XSS, path traversal from call.parameters, insecure session cookies |
| **Vapor** | CORSMiddleware .all origin, raw SQL interpolation, certificateVerification: .none, hardcoded Environment fallbacks, streamFile traversal, isSecure: false cookies |
| **Play** | CSRF filter disabled, @Html() raw output, anorm interpolation, wildcard CORS/hosts config, session secure=false |
| **Actix** | Cors::permissive(), allow_any_origin + credentials, NamedFile traversal, format! SQL, HTML body XSS, insecure cookies |
| **Axum** | CorsLayer::permissive(), Html(format!()) XSS, sqlx format! queries, Command from extractors, fs reads from extractors, insecure cookies |
| **Flutter** | Unrestricted WebView JavaScript, SharedPreferences secrets, global HttpOverrides cert bypass, unvalidated launchUrl/deep links, hardcoded API keys, secret logging |

### Cloud Provider Security

| Provider | Checks |
|---|---|
| **AWS** (SA-AWS-01..12) | IAM wildcard policies, public S3 buckets, unencrypted EBS/RDS, open security groups, Lambda environment secrets, CloudTrail disabled, root account usage |
| **GCP** (SA-GCP-01..13) | Overprivileged service accounts, public Cloud Storage, unencrypted disks, firewall 0.0.0.0/0 rules, Cloud Function env secrets, audit logging disabled |
| **Azure** (SA-AZURE-01..13) | Excessive RBAC roles, public blob containers, unencrypted managed disks, NSG any/any rules, Function App secrets in config, Activity Log gaps |

### CMS Security

| CMS | Checks |
|---|---|
| **WordPress** (SA-WP-01..10) | SQL without $wpdb->prepare(), missing nonce verification, unescaped output (esc_html/esc_attr), REST API without permission_callback, direct file access without ABSPATH check |
| **Drupal** (SA-DRUPAL-01..06) | Direct SQL without db_select/db_query, unfiltered render arrays, missing CSRF tokens on forms, Xss::filter* bypass, permissions in routing |
| **Joomla** (SA-JOOMLA-01..04) | Raw input without JInput filtering, SQL without JDatabase::quote, missing ACL checks, unescaped output |

### Mobile SDK Security

| Platform | Checks |
|---|---|
| **Android** (SA-ANDROID-01..10) | Exported components without permissions, content provider SQL injection, WebView JavaScript bridge (addJavascriptInterface), SharedPreferences for secrets, cleartext traffic (usesCleartextTraffic), intent redirection, insecure broadcast receivers |
| **iOS** (SA-IOS-01..10) | ATS bypass (NSAllowsArbitraryLoads), Keychain missing access control, WKWebView JavaScript enabled without validation, UIPasteboard sensitive data exposure, URL scheme hijacking, insecure data in UserDefaults, missing jailbreak detection |

### Infrastructure-as-Code

| Target | Checks |
|---|---|
| **Dockerfile** | Running as root (missing USER), secrets in ENV/ARG/COPY, unpinned base images (:latest), ADD instead of COPY for remote URLs, apt cache in final image |
| **Kubernetes** | Missing securityContext (runAsNonRoot, readOnlyRootFilesystem), no NetworkPolicy, privileged containers, hostNetwork/hostPID, RBAC wildcards, secrets in pod spec |
| **Terraform** | Public S3/GCS/Blob access, unencrypted storage, open security groups (0.0.0.0/0), hardcoded credentials, missing logging/monitoring |
| **Docker Compose** | privileged: true, Docker socket mount (/var/run/docker.sock), capability additions (SYS_ADMIN), host network mode |

### API Security

**OWASP API Top 10 (2023):** BOLA (broken object-level auth), broken authentication, excessive data exposure, lack of rate limiting, function-level auth bypass, mass assignment, SSRF, security misconfiguration, improper inventory management, unsafe consumption of APIs.

**GraphQL:** Introspection enabled in production, no query depth limits, no complexity limits, batching attacks (alias-based brute force), field suggestion information leak.

**REST:** Missing Content-Type validation, CORS wildcard origins, verbose error responses, unversioned APIs exposing deprecated endpoints, missing pagination (DoS via large result sets).

### Frontend Security

**DOM XSS:** Sinks (innerHTML, document.write, eval, setTimeout with strings, location.href assignment) combined with sources (location.hash, postMessage data, URL parameters, document.referrer).

**Subresource Integrity:** CDN-hosted scripts/styles without SRI hashes, dynamic script injection without integrity verification.

**CORS:** Wildcard origins, null origin allowance, credential-inclusive wildcards, origin reflection without validation.

**Client-Side Storage:** Secrets/tokens in localStorage (accessible via XSS), sensitive PII in sessionStorage, unencrypted IndexedDB data.

### AI/LLM Agent Security

**OWASP LLM Top 10 (2025):** Prompt injection (direct + indirect), sensitive information disclosure, supply chain vulnerabilities, data/model poisoning, improper output handling, excessive agency, system prompt leakage, vector/embedding weaknesses, misinformation, unbounded consumption.

**Agent-Specific:** Unrestricted Bash tool access, missing human approval gates for destructive operations, MCP server version pinning, secrets in system prompts or CLAUDE.md, LLM output piped to shell without validation, over-permissioned tool configurations, skill supply chain verification.

### Supply Chain Security

**Dependency Sandbox:** Behavioral analysis during package installation — monitors network connections (DNS, TCP), file system writes outside package directory, unexpected process spawning, environment variable harvesting, credential file exfiltration. PID-to-package attribution traces suspicious activity back to the specific package responsible.

**SBOM Generation:** CycloneDX 1.5 format with package name, version, purl, license. Full transitive dependency tree.

**CVE Auditing:** Package manager native audit (pnpm audit, pip-audit, govulncheck, cargo-audit, dotnet list --vulnerable) run inside the sandbox container.

### Risk Scoring

**CVSS v3.1:** Attack vector, complexity, privileges required, user interaction, scope, confidentiality/integrity/availability impact. Base, temporal, and environmental score calculation.

**CVSS v4.0:** Adds attack requirements, provider urgency, supplemental metrics. Updated scope handling with vulnerable/subsequent system impact separation.

### Compliance Mapping

Each checkpoint is mapped to relevant controls across 7 frameworks:

| Framework | Coverage |
|---|---|
| **SOC 2 Type II** | Trust Services Criteria (CC6, CC7, CC8) |
| **ISO 27001:2022** | Annex A controls (A.8 Technology, A.5 Organizational) |
| **PCI DSS v4.0** | Requirements 2, 3, 4, 6, 7, 8, 10, 11 |
| **HIPAA** | Security Rule (Access Control, Audit Controls, Integrity, Transmission) |
| **GDPR Article 32** | Security of processing (encryption, resilience, testing) |
| **NIST CSF 2.0** | Identify, Protect, Detect, Respond, Recover functions |
| **EU AI Act** | Article 15 (accuracy, robustness, cybersecurity), Article 9 (risk management) |

## CI

Tests run on push/PR to main:
- `test_risky_patterns.py` — hook pattern tests
- `validate_checkpoints.py` — checkpoint YAML + namespace validation
- `test_eval_fixtures.py` — regex fixture tests (536 tests)

## License

Dual-licensed:

| Component | License |
|---|---|
| Code (scripts, workflows, TypeScript/Kotlin packages, configs) | [MIT](LICENSE-MIT) |
| Content (skill definitions, checkpoints, references, docs, evals) | [CC-BY-SA-4.0](LICENSE-CC-BY-SA-4.0) |

## Credits

Forked from [netresearch/security-audit-skill](https://github.com/netresearch/security-audit-skill) by [Netresearch DTT GmbH](https://www.netresearch.de).

Extended and maintained by [E van der Vecht](https://github.com/evandervecht).
