# Audit Checklist

Quick pass/fail list for the end of an audit. Each item maps to a reference: tooling in `automated-scanning.md`, IaC and Kubernetes in `iac-security.md` and `kubernetes-security.md`, workflows in `github-actions-security.md`, APIs in `api-security.md` and `graphql-security.md`, browser issues in `frontend-security.md`, agents in `llm-security.md`.


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
