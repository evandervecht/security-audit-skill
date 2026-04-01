# Extended Capabilities — PRD

**Date:** 2026-03-31
**Author:** E van der Vecht
**Status:** Draft

---

## Problem Statement

The security-audit skill provides comprehensive static detection patterns for code vulnerabilities, but lacks several capabilities needed for a complete security toolchain:

1. **No IDE integration** — findings are only accessible via AI agent conversations and bash scripts, not surfaced inline in editors
2. **No runtime analysis** — the skill only detects patterns in source code, not misconfigurations or vulnerabilities observable at runtime (missing headers, TLS issues, CORS misconfig)
3. **No CVE correlation** — findings aren't mapped to known CVEs, making it harder to prioritize and communicate risk
4. **No cloud provider coverage** — AWS/GCP/Azure-specific misconfigurations in IaC templates aren't detected
5. **No CMS coverage beyond TYPO3** — WordPress (43% of the web), Drupal, and Joomla are not covered
6. **No mobile SDK coverage** — Android and iOS platform-specific security patterns (Intents, Keychain, WebView) are not detected

## Solution

Extend the security-audit skill with six new capability areas, delivered in 16 phases across the existing repository. IDE integrations use a TypeScript monorepo under `packages/`, while content additions follow the established reference/checkpoint/scanner/eval pattern.

## User Stories

### IDE Integrations
1. As a developer, I want security findings surfaced in my IDE via MCP, so that AI agents (Claude Code, Cursor, Copilot) can detect vulnerabilities as I code.
2. As a developer, I want an MCP tool to scan a project and return structured JSON findings, so that agent workflows can programmatically act on security issues.
3. As a developer, I want an MCP tool to explain a finding with vulnerable/secure code examples, so that I can fix issues without leaving my editor.
4. As a developer, I want security findings as LSP diagnostics (squiggly underlines), so that I see issues inline in any LSP-compatible editor.
5. As a VS Code user, I want a dedicated extension that shows security findings with severity icons, quick-fix suggestions, and links to reference docs.
6. As a developer, I want the detection engine shared between MCP, LSP, and VS Code, so that findings are consistent across all integration points.

### Runtime/Dynamic Analysis
7. As a security auditor, I want to scan a live URL for missing security headers (HSTS, CSP, X-Content-Type-Options), so that I can detect runtime misconfigurations.
8. As a security auditor, I want to check a URL's TLS configuration (version, cipher suites, certificate validity), so that I can verify transport security.
9. As a security auditor, I want to detect CORS misconfigurations on live endpoints, so that I can identify overly permissive cross-origin policies.
10. As a security auditor, I want to check cookie flags (Secure, HttpOnly, SameSite) on a running application.
11. As a security auditor, I want to probe for open redirect vulnerabilities on live endpoints.
12. As a security auditor, I want to detect verbose error pages that leak stack traces or internal paths.
13. As a security auditor, I want instrumented runtime taint tracing for Node.js/Python, so that I can detect actual data flow from sources to sinks.
14. As a security auditor, I want to run dependencies in a sandbox and monitor syscalls/network calls, so that I can detect supply chain threats at runtime.

### CVE Database
15. As a security auditor, I want findings mapped to known CVEs (e.g., Log4Shell, Pickle RCE), so that I can reference authoritative vulnerability identifiers.
16. As a security auditor, I want CVSS scores from the NVD included with CVE-mapped findings, so that I can prioritize remediation.
17. As a security auditor, I want live CVE feed queries during scans, so that newly published CVEs are detected against my codebase.

### Cloud Provider Security
18. As a security auditor, I want to detect AWS IAM policy misconfigurations (`*` actions, missing conditions) in Terraform/CloudFormation.
19. As a security auditor, I want to detect public S3 buckets, open Security Groups, and unencrypted resources in AWS IaC.
20. As a security auditor, I want to detect GCP IAM over-permissioning, public Cloud Storage, and missing audit logging in Terraform.
21. As a security auditor, I want to detect Azure RBAC misconfigurations, public Blob Storage, and missing Key Vault usage in Bicep/ARM templates.
22. As a security auditor, I want cloud-specific checkpoints and scanner modules for each provider.

### CMS Security
23. As a security auditor, I want WordPress security patterns covering `$wpdb->prepare()`, nonce validation, `esc_*` output functions, REST API auth, and plugin/theme vulnerabilities.
24. As a security auditor, I want Drupal security patterns covering render arrays, `db_select`, Form API CSRF, `Xss::filter*`, and entity access.
25. As a security auditor, I want Joomla security patterns covering `JInput` filtering, `JDatabase::quote`, ACL checks, and component routing.

### Mobile SDK Security
26. As a security auditor, I want Android SDK security patterns covering Intent exposure, ContentProvider injection, WebView JavaScript bridge, SharedPreferences, NetworkSecurityConfig, and manifest flags.
27. As a security auditor, I want iOS SDK security patterns covering Keychain `kSecAttrAccessible` misuse, ATS bypass, WKWebView vs UIWebView, UIPasteboard leaks, URL scheme hijacking, and NSUserDefaults.

## Implementation Decisions

### IDE Integration Architecture

**Monorepo under `packages/`** using pnpm workspaces:

```
packages/
  core/          — checkpoint loader, regex engine, finding formatter
  mcp-server/    — MCP transport layer (stdio), wraps core
  lsp-server/    — LSP transport layer, wraps core
  vscode-ext/    — VS Code extension, bundles lsp-server
```

**Core detection engine** (`packages/core`):
- Reads `skills/security-audit/checkpoints.yaml` and `references/*.md`
- Runs regex patterns against file content
- Returns structured findings: `{ checkpointId, severity, line, column, message, reference }`
- Language detection via indicator files (reuses SKILL.md mapping)
- TypeScript, published as `@security-audit/core`

**MCP server** (`packages/mcp-server`):
- Transport: stdio (standard for local MCP servers)
- Tools: `security_scan` (project scan), `check_file` (single file), `explain_finding` (reference lookup)
- Resources: `references/{name}` (reference .md files)
- Prompts: `security_audit` (full audit), `quick_check` (single file)
- Published as `@security-audit/mcp-server`, installable via `npx @security-audit/mcp-server`

**LSP server** (`packages/lsp-server`):
- Diagnostics on file open/save
- Severity mapping: checkpoint `error` -> LSP Error, `warning` -> LSP Warning
- Code actions: "Show secure alternative", "View reference"
- Published as `@security-audit/lsp-server`

**VS Code extension** (`packages/vscode-ext`):
- Bundles LSP server
- Custom sidebar with findings tree view
- Quick-fix code actions
- Status bar showing finding count
- Settings for severity threshold, enabled languages
- Published to VS Code Marketplace

### Runtime/Dynamic Analysis

**Live scanner** (Phase B1):
- New script `scripts/live-scanner.sh` or Node.js module in `packages/core`
- Accepts a URL, performs: HTTP header check, TLS probe, CORS test, cookie flag check, open redirect probe, error page detection
- Returns structured findings in same format as static scanner
- Exposed as MCP tool `security_scan_live`

**Instrumented runtime** (Phase B2):
- Node.js: `--require` hook that wraps dangerous sinks (`child_process.exec`, `fs.readFile`, SQL drivers)
- Python: `sys.settrace` or `import` hook for taint tracking
- Reports when user input reaches a dangerous sink without sanitization
- Separate package: `packages/runtime-agent`

**Dependency sandbox** (Phase B3):
- Docker-based sandbox that runs `npm install` / `pip install` and monitors:
  - Network calls (DNS, HTTP)
  - File system writes outside package directory
  - Process spawning
- Reports suspicious behavior per package
- Separate script: `scripts/dependency-sandbox.sh`

### CVE Database

**Static mapping** (Phase C1):
- New reference file `references/cve-database.md` mapping CVE IDs to checkpoint IDs
- Structure: `| CVE-ID | Checkpoint | CVSS | Description | Affected |`
- Cover top 100 most-exploited CVEs across all supported languages
- GitHub Action to periodically check for new high-severity CVEs

**Live feed** (Phase C2):
- Query NVD API v2 (`services.nvd.nist.gov/rest/json/cves/2.0`) and OSV API (`api.osv.dev`)
- Match findings against live CVE data by CWE ID and keyword
- Add CVE IDs and CVSS scores to finding output
- Network access optional — falls back to static mapping when offline

### Cloud Provider Security

Three reference files following the framework template:
- `aws-security.md` — IAM, S3, Lambda, Security Groups, KMS, CloudTrail, Secrets Manager
- `gcp-security.md` — IAM/service accounts, Cloud Storage, Cloud Functions, VPC, KMS, Audit Logs
- `azure-security.md` — RBAC/Entra ID, Blob Storage, Azure Functions, NSGs, Key Vault, Activity Log

Detection targets: `*.tf`, `*.json` (CloudFormation), `*.bicep`, `*.yaml`

Checkpoint prefixes: `SA-AWS-*`, `SA-GCP-*`, `SA-AZURE-*`

Scanner modules: `scripts/scanners/aws.sh`, `scripts/scanners/gcp.sh`, `scripts/scanners/azure.sh`

### CMS Security

Three reference files:
- `wordpress-security.md` — `$wpdb->prepare()`, nonce validation, `esc_*`, REST API auth, plugin/theme patterns, `wp-config.php` hardening
- `drupal-security.md` — render arrays, `db_select`, Form API, `Xss::filter*`, entity access, `.htaccess` config
- `joomla-security.md` (minimal) — `JInput`, `JDatabase::quote`, ACL, component routing

Checkpoint prefixes: `SA-WP-*`, `SA-DRUPAL-*`, `SA-JOOMLA-*`

Detection targets: PHP files, `wp-config.php`, `settings.php`, `configuration.php`

### Mobile SDK Security

Two reference files:
- `android-sdk-security.md` — Intents, ContentProviders, WebView, SharedPreferences, NetworkSecurityConfig, manifest flags (`android:debuggable`, `android:allowBackup`), root detection
- `ios-sdk-security.md` — Keychain, ATS, WKWebView/UIWebView, UIPasteboard, URL schemes, NSUserDefaults, jailbreak detection

Checkpoint prefixes: `SA-ANDROID-*`, `SA-IOS-*`

Detection targets: `AndroidManifest.xml`, `*.gradle`, `*.kt`, `*.java`, `Info.plist`, `*.swift`, `*.m`

### Checkpoint Namespace Additions

Add to `validate_checkpoints.py`:
- `SA-AWS-`, `SA-GCP-`, `SA-AZURE-`
- `SA-WP-`, `SA-DRUPAL-`, `SA-JOOMLA-`
- `SA-ANDROID-`, `SA-IOS-`

## Testing Decisions

### IDE Integrations
- Unit tests for `packages/core`: detection engine against fixture files
- Integration tests for MCP server: tool invocation and response format
- Integration tests for LSP server: diagnostic publishing on file changes
- E2E tests for VS Code extension: activate, open file, verify diagnostics appear

### Runtime Analysis
- Test against known-vulnerable test servers (OWASP Juice Shop, DVWA)
- Mock HTTP responses for header/TLS/CORS checks
- Sandbox tests against known-malicious npm packages (in isolated environment)

### Content Additions (Cloud, CMS, Mobile)
- Same eval fixture pattern as existing references (vulnerable + safe samples)
- CI validation of all new checkpoints and references

## Out of Scope

- Commercial vulnerability scanner features (authenticated scanning, compliance reporting)
- JetBrains plugin (covered by LSP — JetBrains supports LSP natively)
- Cloud runtime monitoring (CloudWatch, Stackdriver, Azure Monitor integration)
- WAF rule generation from findings
- Bug bounty platform integration

## Further Notes

- The MCP server is the highest-value, lowest-effort IDE integration — it gets the skill into every AI-powered IDE immediately
- Cloud security references (D1-D3) can be built in parallel since they're independent
- CMS security references are direct parallels to the existing TYPO3 reference — same template, same depth
- Mobile SDK references complement the Tier 2 language references (Kotlin/Swift) already planned in the multi-language PRD
