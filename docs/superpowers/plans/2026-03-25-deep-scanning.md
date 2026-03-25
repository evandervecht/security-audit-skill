# Deep Scanning Capabilities Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add IaC, API, Frontend, and AI/LLM security scanning capabilities to the security-audit skill (Phase 1 of GitHub issue #1).

**Architecture:** Each scanning domain gets a reference doc in `references/`, mechanical checkpoints in `checkpoints.yaml` (IaC/Frontend), LLM review checkpoints in `checkpoints.yaml` (API/LLM), and SKILL.md updates. The existing checkpoint ID convention uses `SA-` prefix with sequential numbers (mechanical) or domain prefixes like `SA-LLM-`, `SA-SC-`, `SA-SEC-`, `SA-DEP-`, `SA-SAST-`, `SA-SP-`. New domains use: `SA-IAC-`, `SA-API-`, `SA-FE-`, `SA-AI-`.

**Tech Stack:** YAML (checkpoints), Markdown (reference docs), Bash (audit scripts), Python (validation)

---

### Task 1: IaC Security Reference Doc

**Files:**
- Create: `skills/security-audit/references/iac-security.md`

- [ ] **Step 1: Create the IaC security reference doc**

Create `skills/security-audit/references/iac-security.md` following the format of existing reference docs (vulnerable/secure code examples, detection patterns, prevention checklists). Cover:

1. **Dockerfile Security**
   - Running as root (`USER root` or missing `USER` directive)
   - Secrets in layers (`COPY .env`, `ARG PASSWORD`, secrets in `RUN` commands)
   - Unsigned/unversioned base images (`FROM ubuntu` without tag/digest)
   - `ADD` vs `COPY` (ADD can fetch remote URLs)

2. **Docker Compose Security**
   - `privileged: true`
   - Sensitive host mounts (`/etc`, `/var/run/docker.sock`, `/`)
   - Exposed ports without need (`ports:` when `expose:` suffices)
   - Missing resource limits

3. **Kubernetes Security**
   - Overly permissive RBAC (ClusterRoleBinding to `cluster-admin`)
   - Missing NetworkPolicy
   - `runAsRoot: true` or missing `securityContext`
   - `hostNetwork: true`, `hostPID: true`
   - Missing resource requests/limits

4. **Terraform Security**
   - Public S3 buckets, security groups with `0.0.0.0/0`
   - Unencrypted storage/databases
   - Missing logging/monitoring

Include vulnerable and secure code examples for each. End with a prevention checklist.

- [ ] **Step 2: Commit**

```bash
git add skills/security-audit/references/iac-security.md
git commit -m "docs: add IaC security reference (Dockerfile, K8s, Terraform)"
```

---

### Task 2: API Security Reference Doc

**Files:**
- Create: `skills/security-audit/references/api-security.md`

- [ ] **Step 1: Create the API security reference doc**

Create `skills/security-audit/references/api-security.md` mapping the OWASP API Top 10 (2023) with detection patterns. Cover:

1. **API1 - BOLA** (Broken Object-Level Authorization) - deeper than current IDOR checks, API-specific patterns
2. **API2 - Broken Authentication** - API token/key auth patterns
3. **API3 - Broken Object Property Level Authorization** - mass assignment + excessive data exposure
4. **API4 - Unrestricted Resource Consumption** - rate limiting, pagination, query complexity
5. **API5 - Broken Function-Level Authorization** - admin endpoints accessible to regular users
6. **API6 - Unrestricted Access to Sensitive Business Flows** - anti-automation
7. **API7 - Server-Side Request Forgery** (cross-ref to `modern-attacks.md`)
8. **API8 - Security Misconfiguration** - CORS, error messages, unnecessary HTTP methods
9. **API9 - Improper Inventory Management** - deprecated API versions, undocumented endpoints
10. **API10 - Unsafe Consumption of APIs** - trusting third-party API responses

Include GraphQL-specific section: introspection in production, query depth/complexity limits, batching attacks, field suggestion leakage.

Include REST-specific: versioning security, HATEOAS abuse, content-type validation.

- [ ] **Step 2: Commit**

```bash
git add skills/security-audit/references/api-security.md
git commit -m "docs: add API security reference (OWASP API Top 10, GraphQL)"
```

---

### Task 3: Frontend Security Reference Doc

**Files:**
- Create: `skills/security-audit/references/frontend-security.md`

- [ ] **Step 1: Create the frontend security reference doc**

Create `skills/security-audit/references/frontend-security.md` covering:

1. **DOM-based XSS** - sinks (innerHTML, document.write, eval, setTimeout with string), sources (location.hash, location.search, document.referrer, postMessage data)
2. **Subresource Integrity (SRI)** - when to use, how to generate, crossorigin attribute
3. **postMessage Security** - origin validation, structured clone attack, targetOrigin wildcards
4. **localStorage/sessionStorage** - what never to store (tokens, PII, secrets), alternatives (httpOnly cookies)
5. **CORS Misconfiguration** - wildcard with credentials, origin reflection, null origin
6. **JavaScript Dependency Security** - npm audit, yarn audit, Snyk, lockfile integrity
7. **eval and dynamic code execution** - eval, Function constructor, setTimeout/setInterval with strings
8. **Client-side open redirects** - window.location with user input, meta refresh

Include vulnerable/secure JavaScript code examples for each pattern.

- [ ] **Step 2: Commit**

```bash
git add skills/security-audit/references/frontend-security.md
git commit -m "docs: add frontend security reference (DOM XSS, SRI, CORS)"
```

---

### Task 4: AI/LLM Agent Security Reference Doc

**Files:**
- Create: `skills/security-audit/references/llm-security.md`

- [ ] **Step 1: Create the LLM security reference doc**

Create `skills/security-audit/references/llm-security.md` mapping the OWASP Top 10 for LLM Applications (2025) to AI agent/skill auditing patterns. Cover:

1. **LLM01 - Prompt Injection** - direct (user input altering behavior), indirect (external content with embedded instructions), tool output injection. Detection: skills ingesting unvalidated external content, missing input sanitization instructions.
2. **LLM02 - Sensitive Information Disclosure** - secrets in system prompts/SKILL.md/AGENTS.md, sensitive files loaded into context (.env, private keys), unredacted logging.
3. **LLM03 - Supply Chain** - MCP server provenance (unpinned versions), unverified skill sources, missing SBOM for AI dependencies.
4. **LLM04 - Data and Model Poisoning** - RAG data validation, training data provenance tracking.
5. **LLM05 - Improper Output Handling** - LLM output to shell execution without validation, LLM-generated code without review gates, LLM-generated API calls with string interpolation.
6. **LLM06 - Excessive Agency** - least-privilege violations in tool/MCP permissions, missing human approval gates for high-impact actions, unnecessary dangerous capabilities.
7. **LLM07 - System Prompt Leakage** - credentials in prompts, security controls only in prompt instructions (not enforced externally).
8. **LLM08 - Vector and Embedding Weaknesses** - RAG access controls, embedding injection, multi-tenant data isolation.
9. **LLM09 - Misinformation** - audit findings without verification steps, hallucination guards, cross-referencing LLM output against actual code.
10. **LLM10 - Unbounded Consumption** - token/request limits, context overflow from unbounded content loading.

For each: detection patterns (what to grep/check for in skill definitions, agent configs, MCP configs), vulnerable examples, secure examples, and remediation.

Include sections on:
- Auditing SKILL.md files
- Auditing AGENTS.md / CLAUDE.md
- Auditing MCP server configurations (mcp.json)
- Auditing hook definitions (hooks.json)
- Auditing tool permission settings

- [ ] **Step 2: Commit**

```bash
git add skills/security-audit/references/llm-security.md
git commit -m "docs: add LLM security reference (OWASP LLM Top 10 2025)"
```

---

### Task 5: Add IaC Mechanical Checkpoints

**Files:**
- Modify: `skills/security-audit/checkpoints.yaml` (append to `mechanical:` section before `llm_reviews:`)

- [ ] **Step 1: Add IaC checkpoints to checkpoints.yaml**

Add the following after the last mechanical checkpoint (SA-SP-02) and before `llm_reviews:`:

```yaml
  # === INFRASTRUCTURE-AS-CODE SECURITY ===
  - id: SA-IAC-01
    type: command
    target: "! grep -rqE '^USER\\s+root' Dockerfile* 2>/dev/null || ! grep -rqP '^USER\\s' Dockerfile* 2>/dev/null"
    severity: warning
    desc: "Dockerfile should not run as root - add a USER directive with a non-root user"

  - id: SA-IAC-02
    type: command
    target: "! grep -rqE '(COPY|ADD).*\\.env' Dockerfile* 2>/dev/null"
    severity: error
    desc: "Dockerfile must not copy .env files into image layers (secrets leak)"

  - id: SA-IAC-03
    type: command
    target: "! grep -rqE 'ARG.*(PASSWORD|SECRET|TOKEN|API_KEY)' Dockerfile* 2>/dev/null"
    severity: error
    desc: "Dockerfile ARG must not contain secrets (visible in image history)"

  - id: SA-IAC-04
    type: command
    target: "! grep -rqE '^FROM\\s+\\w+\\s*$' Dockerfile* 2>/dev/null"
    severity: warning
    desc: "Dockerfile base images should be pinned to specific tags or digests, not latest"

  - id: SA-IAC-05
    type: command
    target: "! grep -rqE 'privileged:\\s*true' docker-compose*.yml 2>/dev/null"
    severity: error
    desc: "Docker Compose must not use privileged mode (container escape risk)"

  - id: SA-IAC-06
    type: command
    target: "! grep -rqE '/var/run/docker\\.sock' docker-compose*.yml 2>/dev/null"
    severity: error
    desc: "Docker Compose must not mount Docker socket (container escape risk)"

  - id: SA-IAC-07
    type: command
    target: "! grep -rqE 'runAsUser:\\s*0' k8s/ kubernetes/ deploy/ manifests/ charts/ 2>/dev/null"
    severity: error
    desc: "Kubernetes pods must not run as root (runAsUser: 0)"

  - id: SA-IAC-08
    type: command
    target: "! grep -rqE 'hostNetwork:\\s*true' k8s/ kubernetes/ deploy/ manifests/ charts/ 2>/dev/null"
    severity: error
    desc: "Kubernetes pods should not use host networking"

  - id: SA-IAC-09
    type: command
    target: "! grep -rqE 'cidr_blocks.*0\\.0\\.0\\.0/0' *.tf **/*.tf 2>/dev/null"
    severity: warning
    desc: "Terraform security groups should not allow unrestricted ingress (0.0.0.0/0)"

  - id: SA-IAC-10
    type: command
    target: "! grep -rqE 'acl.*public' *.tf **/*.tf 2>/dev/null"
    severity: warning
    desc: "Terraform S3 buckets should not use public ACLs"
```

- [ ] **Step 2: Run validation**

```bash
python3 scripts/validate_checkpoints.py
```
Expected: Valid checkpoint count increases, no duplicate IDs.

- [ ] **Step 3: Commit**

```bash
git add skills/security-audit/checkpoints.yaml
git commit -m "feat: add IaC mechanical checkpoints (SA-IAC-01 through SA-IAC-10)"
```

---

### Task 6: Add API Security LLM Review Checkpoints

**Files:**
- Modify: `skills/security-audit/checkpoints.yaml` (append to `llm_reviews:` section)

- [ ] **Step 1: Add API security checkpoints**

Append to the `llm_reviews:` section:

```yaml
  # === API SECURITY (OWASP API TOP 10) ===
  - id: SA-API-01
    domain: security
    prompt: |
      Audit API endpoints for Broken Object-Level Authorization (BOLA):
      1. Find all API endpoints that accept resource IDs (path params, query params)
      2. Verify each endpoint checks that the authenticated user owns/has access to the resource
      3. Check for patterns where find($id) is called without scoping to the current user
      4. Verify GraphQL resolvers enforce per-field authorization
      5. Check that batch/list endpoints scope results to the authorized user
    severity: error
    desc: "Verify API endpoints enforce object-level authorization (OWASP API1:2023 BOLA)"

  - id: SA-API-02
    domain: security
    prompt: |
      Audit API endpoints for mass assignment and excessive data exposure:
      1. Check if request body is directly assigned to models without allowlisting fields
      2. Verify API responses don't include sensitive fields (password hashes, internal IDs, tokens)
      3. Check for different response schemas for admin vs regular users
      4. Look for $request->all() or similar patterns that accept all input fields
      5. Verify serialization groups or DTOs control what data is exposed
    severity: error
    desc: "Verify API endpoints prevent mass assignment and excessive data exposure (OWASP API3:2023)"

  - id: SA-API-03
    domain: security
    prompt: |
      Audit API rate limiting and resource consumption controls:
      1. Check if rate limiting middleware is applied to API routes
      2. Verify pagination is enforced on list endpoints (max page size)
      3. Check for query complexity limits on GraphQL endpoints
      4. Look for unbounded file upload sizes on API endpoints
      5. Verify timeout settings exist for long-running API operations
      6. Check that bulk/batch endpoints limit the number of items per request
    severity: warning
    desc: "Verify API rate limiting and resource consumption controls (OWASP API4:2023)"

  - id: SA-API-04
    domain: security
    prompt: |
      Audit API function-level authorization:
      1. Check that admin-only API endpoints have authorization middleware
      2. Verify that changing HTTP method (GET to DELETE) doesn't bypass authorization
      3. Look for API endpoints that lack authentication entirely
      4. Check that role checks cover all CRUD operations (not just read)
      5. Verify that API documentation/spec doesn't expose undocumented admin endpoints
    severity: error
    desc: "Verify API function-level authorization controls (OWASP API5:2023)"

  - id: SA-API-05
    domain: security
    prompt: |
      Audit GraphQL security (if GraphQL is used):
      1. Check if introspection is disabled in production
      2. Verify query depth limits are configured
      3. Check for query complexity/cost analysis
      4. Look for batching attack protection (limit concurrent queries)
      5. Verify field-level authorization in resolvers
      6. Check that error messages don't leak schema details
      If no GraphQL is found, note that and skip.
    severity: warning
    desc: "Verify GraphQL-specific security controls (introspection, depth limits, batching)"

  - id: SA-API-06
    domain: security
    prompt: |
      Audit API error handling and information disclosure:
      1. Check that API error responses use generic messages (not stack traces)
      2. Verify different error codes don't leak information (404 vs 403 for unauthorized resources)
      3. Look for debug/verbose mode that can be enabled via headers or params
      4. Check that validation errors don't reveal internal field names or schema
      5. Verify CORS configuration is restrictive (not wildcard with credentials)
    severity: warning
    desc: "Verify API error handling doesn't disclose sensitive information (OWASP API8:2023)"
```

- [ ] **Step 2: Run validation**

```bash
python3 scripts/validate_checkpoints.py
```

- [ ] **Step 3: Commit**

```bash
git add skills/security-audit/checkpoints.yaml
git commit -m "feat: add API security LLM review checkpoints (SA-API-01 through SA-API-06)"
```

---

### Task 7: Add Frontend Mechanical Checkpoints

**Files:**
- Modify: `skills/security-audit/checkpoints.yaml` (append to `mechanical:` section)

- [ ] **Step 1: Add frontend mechanical checkpoints**

Add after the IaC checkpoints in the `mechanical:` section:

```yaml
  # === FRONTEND/CLIENT-SIDE SECURITY ===
  - id: SA-FE-01
    type: not_contains
    target: "**/*.js"
    pattern: ".innerHTML ="
    severity: warning
    desc: "Direct innerHTML assignment may enable DOM-based XSS - use textContent or sanitize"

  - id: SA-FE-02
    type: not_contains
    target: "**/*.js"
    pattern: "document.write("
    severity: warning
    desc: "document.write() may enable DOM-based XSS - use DOM manipulation methods"

  - id: SA-FE-03
    type: command
    target: "! grep -rqE 'eval\\s*\\(' --include='*.js' --include='*.ts' . 2>/dev/null"
    severity: warning
    desc: "eval() in JavaScript enables code injection - use safer alternatives"

  - id: SA-FE-04
    type: command
    target: "! grep -rqE 'localStorage\\.(set|get)Item.*((token|password|secret|key|credential|session))' --include='*.js' --include='*.ts' . 2>/dev/null"
    severity: error
    desc: "Sensitive data (tokens, passwords, secrets) must not be stored in localStorage"

  - id: SA-FE-05
    type: command
    target: "! grep -rqE 'Access-Control-Allow-Origin.*\\*' --include='*.php' --include='*.js' --include='*.conf' --include='*.yaml' --include='*.yml' . 2>/dev/null"
    severity: warning
    desc: "CORS wildcard (*) origin should be avoided - use specific allowed origins"

  - id: SA-FE-06
    type: command
    target: "! grep -rqE '<script\\s+src=\"https?://' --include='*.html' --include='*.php' --include='*.twig' . 2>/dev/null | grep -vq 'integrity='"
    severity: info
    desc: "External scripts should use Subresource Integrity (SRI) attributes"

  - id: SA-FE-07
    type: command
    target: "! grep -rqE 'new Function\\s*\\(' --include='*.js' --include='*.ts' . 2>/dev/null"
    severity: warning
    desc: "new Function() enables dynamic code execution - use safer alternatives"
```

- [ ] **Step 2: Add frontend LLM review checkpoints**

Append to `llm_reviews:`:

```yaml
  # === FRONTEND/CLIENT-SIDE SECURITY ===
  - id: SA-FE-LLM-01
    domain: security
    prompt: |
      Audit frontend JavaScript/TypeScript for client-side security:
      1. Check for DOM-based XSS sinks: innerHTML, outerHTML, document.write, eval, setTimeout/setInterval with string args
      2. Trace user-controlled sources (location.hash, location.search, document.referrer, postMessage data) to sinks
      3. Check postMessage handlers for origin validation
      4. Verify localStorage/sessionStorage doesn't contain sensitive data
      5. Look for client-side open redirect patterns (window.location = userInput)
      6. Check for unsafe use of jQuery .html(), .append() with user input
      If no JavaScript/TypeScript is found, note that and skip.
    severity: warning
    desc: "Verify frontend code is protected against DOM-based XSS and client-side attacks"

  - id: SA-FE-LLM-02
    domain: security
    prompt: |
      Audit CORS configuration and SRI usage:
      1. Check for Access-Control-Allow-Origin with wildcard (*) combined with credentials
      2. Verify origin reflection is not used (reflecting request Origin header)
      3. Check that SRI (integrity=) attributes are present on CDN-hosted scripts/stylesheets
      4. Verify crossorigin attribute is set when SRI is used
      5. Check for missing Content-Security-Policy headers for frontend assets
      If no frontend assets are found, note that and skip.
    severity: warning
    desc: "Verify CORS and Subresource Integrity are properly configured"
```

- [ ] **Step 3: Run validation**

```bash
python3 scripts/validate_checkpoints.py
```

- [ ] **Step 4: Commit**

```bash
git add skills/security-audit/checkpoints.yaml
git commit -m "feat: add frontend security checkpoints (SA-FE-01 through SA-FE-07, SA-FE-LLM-01/02)"
```

---

### Task 8: Add AI/LLM Agent Security Checkpoints

**Files:**
- Modify: `skills/security-audit/checkpoints.yaml` (append to both sections)

- [ ] **Step 1: Add AI/LLM mechanical checkpoints**

Add to `mechanical:` section:

```yaml
  # === AI/LLM AGENT SECURITY ===
  - id: SA-AI-01
    type: command
    target: "! grep -rqE '(api_key|apiKey|API_KEY|secret|password|token)\\s*[:=]\\s*[\"'\\''](sk-|AKIA|ghp_|ghs_)' SKILL.md AGENTS.md CLAUDE.md .claude/ 2>/dev/null"
    severity: error
    desc: "AI agent config files must not contain hardcoded API keys or secrets"

  - id: SA-AI-02
    type: command
    target: "! grep -rqE 'dangerouslyDisableSandbox|--no-verify|--force' SKILL.md AGENTS.md CLAUDE.md .claude/ 2>/dev/null"
    severity: error
    desc: "AI agent configs must not disable safety mechanisms (sandbox, hooks, verification)"

  - id: SA-AI-03
    type: command
    target: "! grep -rqE 'Bash\\(\\*\\)|allowed-tools:.*Bash\\b[^(]' SKILL.md skills/*/SKILL.md 2>/dev/null"
    severity: warning
    desc: "AI skills should not grant unrestricted Bash access - scope to specific commands"

  - id: SA-AI-04
    type: command
    target: "! grep -rqE '\"version\"\\s*:\\s*\"latest\"' .claude/mcp*.json mcp.json 2>/dev/null"
    severity: warning
    desc: "MCP server versions should be pinned, not 'latest' (supply chain risk)"
```

- [ ] **Step 2: Add AI/LLM LLM review checkpoints**

Append to `llm_reviews:`:

```yaml
  # === AI/LLM AGENT SECURITY (OWASP LLM TOP 10 2025) ===
  - id: SA-AI-LLM-01
    domain: security
    prompt: |
      Audit AI agent skills and configurations for prompt injection risks (OWASP LLM01:2025):
      1. Check if skills that ingest external content (web pages, files, API responses) sanitize or segregate that content before passing to the model
      2. Look for tool results passed back to the model without content filtering
      3. Check if system prompts include instructions to validate/sanitize user input
      4. Verify that skills processing untrusted data mark it clearly as external content
      5. Check for multimodal injection risks (images, PDFs processed by the model)
      Look in: SKILL.md files, AGENTS.md, CLAUDE.md, hooks definitions
    severity: error
    desc: "Verify AI agent skills mitigate prompt injection risks (OWASP LLM01:2025)"

  - id: SA-AI-LLM-02
    domain: security
    prompt: |
      Audit AI agent configurations for sensitive information disclosure (OWASP LLM02:2025):
      1. Check system prompts, SKILL.md, AGENTS.md for hardcoded secrets, API keys, credentials
      2. Look for skills that load sensitive files (.env, credentials, private keys) into LLM context
      3. Check if agent conversation logs or tool outputs are stored without redaction
      4. Verify that skills don't expose internal infrastructure details (URLs, IPs, paths)
      5. Check MCP server configs for embedded credentials
      Look in: SKILL.md, AGENTS.md, CLAUDE.md, .claude/, mcp.json
    severity: error
    desc: "Verify AI agent configs don't leak sensitive information (OWASP LLM02:2025)"

  - id: SA-AI-LLM-03
    domain: security
    prompt: |
      Audit AI agent tool permissions for excessive agency (OWASP LLM06:2025):
      1. Check allowed-tools in SKILL.md - are permissions minimal? (e.g., read-only when write isn't needed)
      2. Look for skills with unrestricted Bash access (Bash(*) or Bash without command scoping)
      3. Check if high-impact actions (file deletion, git push, API calls) require human approval
      4. Verify MCP servers expose only necessary capabilities
      5. Check that safety hooks (PreToolUse, PostToolUse) exist for dangerous operations
      6. Look for skills that can modify their own configuration or other skills
      Look in: SKILL.md, .claude/settings*, hooks/, mcp.json
    severity: error
    desc: "Verify AI agent permissions follow least privilege (OWASP LLM06:2025)"

  - id: SA-AI-LLM-04
    domain: security
    prompt: |
      Audit AI agent configurations for improper output handling (OWASP LLM05:2025):
      1. Check if LLM output is passed directly to shell execution without validation
      2. Look for patterns where model-generated code is written to files without review gates
      3. Check if model-generated SQL, API calls, or commands use parameterized inputs
      4. Verify that agent hooks validate tool inputs before execution
      5. Check for skills that auto-execute generated code without sandboxing
      Look in: SKILL.md, scripts/, hooks/, .claude/settings*
    severity: warning
    desc: "Verify LLM output is validated before execution (OWASP LLM05:2025)"

  - id: SA-AI-LLM-05
    domain: security
    prompt: |
      Audit AI agent configurations for system prompt leakage and supply chain risks:
      LLM07 (System Prompt Leakage):
      1. Check if system prompts contain credentials, API keys, or internal URLs
      2. Verify security controls are enforced externally, not just in prompt instructions
      3. Look for business logic or filtering criteria that would be harmful if leaked

      LLM03 (Supply Chain):
      4. Check MCP server sources - are they pinned to specific versions/commits?
      5. Verify installed skills come from verified/trusted sources
      6. Check for AI/agent dependencies without version pinning
      Look in: SKILL.md, AGENTS.md, CLAUDE.md, .claude/, mcp.json
    severity: warning
    desc: "Verify system prompts don't leak secrets and AI supply chain is secured (OWASP LLM03/07:2025)"
```

- [ ] **Step 3: Run validation**

```bash
python3 scripts/validate_checkpoints.py
```

- [ ] **Step 4: Commit**

```bash
git add skills/security-audit/checkpoints.yaml
git commit -m "feat: add AI/LLM agent security checkpoints (SA-AI-01 through SA-AI-04, SA-AI-LLM-01 through SA-AI-LLM-05)"
```

---

### Task 9: Update SKILL.md

**Files:**
- Modify: `skills/security-audit/SKILL.md`

- [ ] **Step 1: Update SKILL.md expertise areas and references**

In the frontmatter, update the description to include new domains. Update version to 3.0.0.

In `## Expertise Areas`, add:
- **Infrastructure**: Dockerfile, Docker Compose, Kubernetes, Terraform security scanning
- **API Security**: OWASP API Top 10, GraphQL security, REST hardening
- **Frontend**: DOM XSS, SRI, CORS, postMessage, client-side storage
- **AI/LLM Security**: OWASP LLM Top 10 (2025), agent permission auditing, MCP security, prompt injection defense

In `## Reference Files`, add:
- **Infrastructure & API**: `iac-security.md`, `api-security.md`
- **Frontend**: `frontend-security.md`
- **AI/LLM Security**: `llm-security.md`

In `## Security Checklist`, add:
- [ ] Dockerfiles use non-root USER, no secrets in layers
- [ ] API endpoints enforce object-level and function-level authorization
- [ ] GraphQL introspection disabled in production, depth limits set
- [ ] Frontend scripts use SRI, no sensitive data in localStorage
- [ ] CORS configured with specific origins, not wildcards
- [ ] AI agent skills follow least-privilege for tool permissions
- [ ] MCP server versions pinned, no secrets in system prompts
- [ ] LLM output validated before shell execution or code generation

- [ ] **Step 2: Commit**

```bash
git add skills/security-audit/SKILL.md
git commit -m "feat: update SKILL.md with IaC, API, frontend, and AI/LLM security"
```

---

### Task 10: Update Validation Script and Run Full Validation

**Files:**
- Modify: `scripts/validate_checkpoints.py`

- [ ] **Step 1: Update validation script to check reference files exist**

Add a check that every reference file mentioned in SKILL.md exists in the references/ directory. Add after the duplicate check:

```python
    # Check that referenced files exist
    import os
    ref_dir = "skills/security-audit/references"
    ref_files = os.listdir(ref_dir)
    missing = []
    expected_refs = [
        "iac-security.md", "api-security.md",
        "frontend-security.md", "llm-security.md",
    ]
    for ref in expected_refs:
        if ref not in ref_files:
            missing.append(ref)
    if missing:
        print(f"WARNING: missing reference files: {missing}")
```

- [ ] **Step 2: Run full validation**

```bash
python3 scripts/validate_checkpoints.py
```
Expected: All new checkpoints valid, no duplicates, all reference files found.

- [ ] **Step 3: Commit**

```bash
git add scripts/validate_checkpoints.py
git commit -m "feat: update validation script to check new reference files"
```

---

### Task 11: Final Integration Commit

- [ ] **Step 1: Run full validation and verify**

```bash
python3 scripts/validate_checkpoints.py
```

- [ ] **Step 2: Verify all reference files exist**

```bash
ls skills/security-audit/references/{iac-security,api-security,frontend-security,llm-security}.md
```

- [ ] **Step 3: Verify SKILL.md is consistent**

Read SKILL.md and confirm all new references, expertise areas, and checklist items are present.
