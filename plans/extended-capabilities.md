# Plan: Extended Capabilities

> Source PRD: [evandervecht/security-audit-skill#4](https://github.com/evandervecht/security-audit-skill/issues/4)
> Design Spec: `docs/superpowers/specs/2026-03-31-extended-capabilities-design.md`

## Architectural decisions

- **Same repo**: IDE packages under `packages/` using pnpm workspaces; content additions follow existing reference/checkpoint/scanner/eval pattern
- **Shared detection engine**: `packages/core` reads `checkpoints.yaml` + `references/*.md`, runs regex detection, returns structured JSON findings
- **MCP server**: TypeScript, stdio transport, tools: `security_scan`, `check_file`, `explain_finding`; resources: references; prompts: `security_audit`, `quick_check`
- **LSP server**: Diagnostics on open/save, severity mapping from checkpoints, code actions for remediation
- **VS Code extension**: Bundles LSP server, sidebar tree view, quick-fix actions, status bar
- **Live scanner**: HTTP-based probing — headers, TLS, CORS, cookies, redirects, error pages
- **CVE mapping**: Static `cve-database.md` + optional live NVD/OSV API queries
- **Cloud references**: `aws-security.md`, `gcp-security.md`, `azure-security.md` — detection targets: `*.tf`, `*.json`, `*.bicep`
- **CMS references**: `wordpress-security.md`, `drupal-security.md`, `joomla-security.md`
- **Mobile references**: `android-sdk-security.md`, `ios-sdk-security.md`
- **New checkpoint prefixes**: `SA-AWS-*`, `SA-GCP-*`, `SA-AZURE-*`, `SA-WP-*`, `SA-DRUPAL-*`, `SA-JOOMLA-*`, `SA-ANDROID-*`, `SA-IOS-*`

---

## Phase A1: MCP Server

**User stories**: #1, #2, #3, #6

### What to build

Initialize the pnpm workspace with `packages/core` and `packages/mcp-server`. The core package loads `checkpoints.yaml`, parses checkpoint definitions, runs regex patterns against file content, and returns structured findings (`checkpointId`, `severity`, `line`, `column`, `message`, `referenceFile`). It also provides language detection from indicator files and reference file lookup.

The MCP server wraps core with stdio transport using `@modelcontextprotocol/sdk`. It exposes three tools: `security_scan` (accepts a project path, detects languages, runs relevant checkpoints, returns findings array), `check_file` (accepts a file path, runs relevant checkpoints, returns findings), `explain_finding` (accepts a checkpoint ID, returns the reference documentation with vulnerable/secure examples). It also exposes reference files as MCP resources and two prompts (`security_audit`, `quick_check`).

Installable via `npx @security-audit/mcp-server` or configurable in Claude Code / Cursor MCP settings.

### Acceptance criteria

- [ ] `packages/core` reads checkpoints.yaml and returns structured findings for a given file
- [ ] `packages/core` detects languages from indicator files
- [ ] `packages/core` returns reference documentation for a checkpoint ID
- [ ] `packages/mcp-server` responds to `security_scan` tool with JSON findings
- [ ] `packages/mcp-server` responds to `check_file` tool with per-file findings
- [ ] `packages/mcp-server` responds to `explain_finding` tool with reference content
- [ ] MCP resources expose reference .md files
- [ ] MCP prompts return pre-built audit and quick-check prompts
- [ ] Unit tests for core detection engine against eval fixtures
- [ ] Integration tests for MCP tool invocations
- [ ] `npx @security-audit/mcp-server` starts and responds to MCP initialize

---

## Phase A2: LSP Server

**User stories**: #4, #6

### What to build

Create `packages/lsp-server` that wraps `packages/core` with LSP transport using `vscode-languageserver` and `vscode-languageclient`. On `textDocument/didOpen` and `textDocument/didSave`, run the core detection engine against the file and publish diagnostics. Map checkpoint severity (`error` -> DiagnosticSeverity.Error, `warning` -> DiagnosticSeverity.Warning, `info` -> DiagnosticSeverity.Information).

Provide code actions: "Show secure alternative" (inserts secure code pattern from reference), "View reference" (opens reference URL or displays inline). Support workspace-level scanning via a custom command.

### Acceptance criteria

- [ ] LSP server publishes diagnostics on file open and save
- [ ] Diagnostics include checkpoint ID, severity, message, and line number
- [ ] Code actions show secure alternatives from references
- [ ] Workspace scan command returns findings across all relevant files
- [ ] Works with any LSP-compatible editor (Neovim, Helix, Sublime Text)
- [ ] Integration tests for diagnostic publishing

---

## Phase A3: VS Code Extension

**User stories**: #5, #6

### What to build

Create `packages/vscode-ext` that bundles the LSP server. Add a sidebar tree view showing findings grouped by file and severity. Add a status bar item showing total finding count (click to open findings panel). Add quick-fix code actions from LSP diagnostics. Add extension settings: severity threshold, enabled/disabled languages, checkpoint exclusion list.

Publish to VS Code Marketplace as `security-audit`.

### Acceptance criteria

- [ ] Extension activates on workspace open for supported languages
- [ ] Sidebar shows findings tree grouped by file, then severity
- [ ] Status bar shows finding count, updates on file changes
- [ ] Quick-fix code actions insert secure alternatives
- [ ] Settings for severity threshold and language filtering
- [ ] Extension bundles LSP server (no separate install needed)
- [ ] Published to VS Code Marketplace

---

## Phase B1: Live Scanner (Headers, TLS, CORS, Cookies)

**User stories**: #7, #8, #9, #10, #11, #12

### What to build

Create a live scanner module in `packages/core` (or standalone script) that accepts a URL and performs HTTP-based security checks. Check security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy). Probe TLS configuration (version, certificate validity). Test CORS with crafted Origin headers. Inspect Set-Cookie flags (Secure, HttpOnly, SameSite). Probe for open redirects with common payloads. Detect verbose error pages (stack traces, internal paths) by triggering 404/500 responses.

Return findings in the same structured format as the static scanner. Expose as MCP tool `security_scan_live`.

### Acceptance criteria

- [ ] Checks all six security header categories
- [ ] Detects TLS < 1.2 and certificate issues
- [ ] Detects CORS wildcard (`*`) and overly permissive origins
- [ ] Detects missing Secure/HttpOnly/SameSite cookie flags
- [ ] Probes for open redirect via common redirect parameters
- [ ] Detects verbose error pages with stack traces
- [ ] Returns structured findings (same format as static scanner)
- [ ] Exposed as MCP tool `security_scan_live`
- [ ] Tests against mock HTTP server

---

## Phase B2: Instrumented Runtime (Taint Tracing)

**User stories**: #13

### What to build

Create `packages/runtime-agent` with Node.js and Python instrumentation. For Node.js: a `--require` hook that wraps dangerous sinks (`child_process.exec`, `fs.readFile`, SQL driver query methods) and traces whether input originates from HTTP request objects (`req.query`, `req.params`, `req.body`). For Python: a `sys.settrace` or import hook that wraps dangerous functions (`subprocess.run`, `os.system`, `pickle.loads`, SQL `execute`).

Report findings when untrusted input reaches a sink without sanitization. Output structured findings with source location, sink location, and taint path.

### Acceptance criteria

- [ ] Node.js hook detects tainted input reaching `child_process.exec`
- [ ] Node.js hook detects tainted input reaching `fs.readFile`
- [ ] Python hook detects tainted input reaching `subprocess.run`
- [ ] Python hook detects tainted input reaching `pickle.loads`
- [ ] Findings include source, sink, and taint path
- [ ] Can be enabled via `node --require @security-audit/runtime-agent` or `python -m security_audit.runtime`
- [ ] Tests against vulnerable sample applications

---

## Phase B3: Dependency Sandbox Audit

**User stories**: #14

### What to build

Create `scripts/dependency-sandbox.sh` that runs `npm install` or `pip install` inside a Docker container with restricted networking, monitors syscalls (via `strace`/`ltrace` or eBPF), and reports suspicious behavior: outbound DNS queries, HTTP requests to non-registry URLs, file writes outside the package directory, process spawning, and environment variable reads.

Report findings per package with severity and observed behavior.

### Acceptance criteria

- [ ] Sandbox runs npm install in isolated Docker container
- [ ] Sandbox runs pip install in isolated Docker container
- [ ] Detects outbound network calls to non-registry URLs
- [ ] Detects file writes outside package directory
- [ ] Detects process spawning during install
- [ ] Reports findings per package with behavior description
- [ ] Tests against known-safe and known-suspicious packages

---

## Phase C1: CVE Static Mapping

**User stories**: #15, #16

### What to build

Create `references/cve-database.md` mapping the top 100 most-exploited CVEs to existing checkpoint IDs. Include: CVE ID, CVSS score, affected language/framework, related checkpoint(s), description, and remediation link. Organized by language/framework.

Add a lookup function to `packages/core` that enriches findings with CVE data when a checkpoint has mapped CVEs.

### Acceptance criteria

- [ ] `cve-database.md` maps 100+ CVEs to checkpoints
- [ ] Each entry has: CVE ID, CVSS score, checkpoint ID, description
- [ ] Core engine enriches findings with CVE data when available
- [ ] MCP tools include CVE information in finding output
- [ ] Covers: Log4Shell, Pickle RCE, Prototype Pollution CVEs, Spring4Shell, etc.

---

## Phase C2: CVE Live Feed

**User stories**: #17

### What to build

Add NVD API v2 and OSV API integration to `packages/core`. During scans, query APIs by CWE ID from checkpoint metadata to find matching CVEs. Merge live CVE data with static mapping. Fall back to static mapping when offline.

Add a GitHub Action that weekly queries for new high-severity CVEs and updates `cve-database.md` via automated PR.

### Acceptance criteria

- [ ] Queries NVD API by CWE ID for matching CVEs
- [ ] Queries OSV API for package-specific vulnerabilities
- [ ] Merges live data with static mapping (live takes precedence)
- [ ] Falls back to static mapping when APIs unreachable
- [ ] GitHub Action opens PR weekly with new CVE mappings
- [ ] Tests with mock API responses

---

## Phase D1: AWS Security Reference

**User stories**: #18, #19, #22

### What to build

Create `references/aws-security.md` following the framework reference template. Cover: IAM policies (`*` actions, missing conditions, overly permissive trust policies), S3 (public access, missing encryption, permissive bucket policies), Lambda (environment variable secrets, overly permissive execution roles, missing VPC), Security Groups (0.0.0.0/0 ingress), KMS (missing key rotation), CloudTrail (disabled or missing), Secrets Manager (hardcoded secrets instead of references).

Detection targets: `*.tf`, `*.json` (CloudFormation), `*.yaml`. Add checkpoints `SA-AWS-01` through `SA-AWS-15`. Create scanner module and eval fixtures.

### Acceptance criteria

- [ ] `aws-security.md` is 15-25KB with vulnerable/secure IaC examples
- [ ] 10-15 checkpoints with `SA-AWS-*` prefix
- [ ] Scanner module `scripts/scanners/aws.sh`
- [ ] Eval fixtures for all detection regexes
- [ ] Detection mapping in SKILL.md updated

---

## Phase D2: GCP Security Reference

**User stories**: #20, #22

### What to build

Create `references/gcp-security.md`. Cover: IAM (primitive roles, service account key files, missing conditions), Cloud Storage (public ACLs, missing encryption), Cloud Functions (environment variable secrets, overly permissive invoker), VPC firewall rules (0.0.0.0/0), KMS (missing rotation), Cloud Audit Logs (disabled).

Add checkpoints `SA-GCP-01` through `SA-GCP-15`. Create scanner module and eval fixtures.

### Acceptance criteria

- [ ] `gcp-security.md` is 15-25KB
- [ ] 10-15 checkpoints with `SA-GCP-*` prefix
- [ ] Scanner module and eval fixtures
- [ ] Detection mapping updated

---

## Phase D3: Azure Security Reference

**User stories**: #21, #22

### What to build

Create `references/azure-security.md`. Cover: RBAC (overly permissive role assignments, missing Entra ID conditions), Blob Storage (public access, missing encryption), Azure Functions (app settings secrets, auth level), NSGs (0.0.0.0/0 rules), Key Vault (missing soft-delete, missing RBAC), Activity Log (disabled).

Detection targets: `*.bicep`, `*.json` (ARM), `*.tf`. Add checkpoints `SA-AZURE-01` through `SA-AZURE-15`. Create scanner module and eval fixtures.

### Acceptance criteria

- [ ] `azure-security.md` is 15-25KB
- [ ] 10-15 checkpoints with `SA-AZURE-*` prefix
- [ ] Scanner module and eval fixtures
- [ ] Detection mapping updated

---

## Phase E1: WordPress Security Reference

**User stories**: #23

### What to build

Create `references/wordpress-security.md`. Cover: `$wpdb->prepare()` for SQL safety, nonce validation (`wp_verify_nonce`, `check_ajax_referer`), output escaping (`esc_html`, `esc_attr`, `esc_url`, `wp_kses`), REST API authentication (`permission_callback`), file upload validation, `wp-config.php` hardening (debug mode, table prefix, salts), plugin/theme security (direct file access prevention, capability checks).

Add checkpoints `SA-WP-01` through `SA-WP-15`. Create scanner module and eval fixtures.

### Acceptance criteria

- [ ] `wordpress-security.md` is 15-25KB
- [ ] 10-15 checkpoints with `SA-WP-*` prefix
- [ ] Scanner module `scripts/scanners/wordpress.sh`
- [ ] Eval fixtures for all detection regexes
- [ ] Detection mapping: `wp-config.php`, `functions.php`, `wp-content/` -> WordPress references

---

## Phase E2: Drupal Security Reference

**User stories**: #24

### What to build

Create `references/drupal-security.md`. Cover: render arrays (avoid `#markup` with user input, use `#plain_text`), database abstraction (`db_select`, `db_query` with placeholders), Form API CSRF (built-in token validation), `Xss::filter*` and `Html::escape`, entity access handlers, `.htaccess` security, module permission system.

Add checkpoints `SA-DRUPAL-01` through `SA-DRUPAL-10`. Create scanner module and eval fixtures.

### Acceptance criteria

- [ ] `drupal-security.md` is 10-20KB
- [ ] 8-10 checkpoints with `SA-DRUPAL-*` prefix
- [ ] Scanner module and eval fixtures
- [ ] Detection mapping: `*.module`, `*.install`, `settings.php` -> Drupal references

---

## Phase E3: Joomla Security Reference (Minimal)

**User stories**: #25

### What to build

Create `references/joomla-security.md` with minimal depth. Cover: `JInput` filtering methods, `JDatabase::quote` and `JDatabaseQuery` parameterization, ACL checks (`JFactory::getUser()->authorise`), component routing security, `configuration.php` hardening.

Add checkpoints `SA-JOOMLA-01` through `SA-JOOMLA-05`. Create scanner module and eval fixtures.

### Acceptance criteria

- [ ] `joomla-security.md` is 8-15KB
- [ ] 5 checkpoints with `SA-JOOMLA-*` prefix
- [ ] Scanner module and eval fixtures
- [ ] Detection mapping: `configuration.php`, `components/` -> Joomla references

---

## Phase F1: Android SDK Security Reference

**User stories**: #26

### What to build

Create `references/android-sdk-security.md`. Cover: Intent exposure (`android:exported`, implicit vs explicit Intents), ContentProvider SQL injection and path traversal, WebView `addJavascriptInterface` and `setAllowFileAccess`, SharedPreferences for sensitive data, NetworkSecurityConfig (cleartext traffic, certificate pinning), manifest flags (`android:debuggable`, `android:allowBackup`, `android:usesCleartextTraffic`), root/tamper detection patterns.

Detection targets: `AndroidManifest.xml`, `*.gradle`, `*.kt`, `*.java`. Add checkpoints `SA-ANDROID-01` through `SA-ANDROID-15`. Create scanner module and eval fixtures.

### Acceptance criteria

- [ ] `android-sdk-security.md` is 15-25KB
- [ ] 10-15 checkpoints with `SA-ANDROID-*` prefix
- [ ] Scanner module `scripts/scanners/android.sh`
- [ ] Eval fixtures for all detection regexes
- [ ] Detection mapping: `AndroidManifest.xml`, `build.gradle` -> Android references

---

## Phase F2: iOS SDK Security Reference

**User stories**: #27

### What to build

Create `references/ios-sdk-security.md`. Cover: Keychain `kSecAttrAccessible` values (avoid `kSecAttrAccessibleAlways`), ATS bypass exceptions in `Info.plist` (`NSAllowsArbitraryLoads`), `UIWebView` (deprecated, use `WKWebView`), `UIPasteboard` data leaks, `NSUserDefaults` for sensitive data, URL scheme hijacking (custom scheme registration), jailbreak detection patterns.

Detection targets: `Info.plist`, `*.swift`, `*.m`. Add checkpoints `SA-IOS-01` through `SA-IOS-12`. Create scanner module and eval fixtures.

### Acceptance criteria

- [ ] `ios-sdk-security.md` is 15-25KB
- [ ] 10-12 checkpoints with `SA-IOS-*` prefix
- [ ] Scanner module `scripts/scanners/ios.sh`
- [ ] Eval fixtures for all detection regexes
- [ ] Detection mapping: `Info.plist`, `*.xcodeproj` -> iOS references
