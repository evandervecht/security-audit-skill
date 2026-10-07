---
name: security-audit
description: "Use for security audits and any code security review: finding vulnerabilities (OWASP Top 10, CWE Top 25, XSS/SQLi/SSRF/XXE/CSRF), CVSS v4.0 scoring, leaked secrets, dependency CVEs, IaC (Dockerfile/Terraform), Kubernetes and GitHub Actions, API and GraphQL, frontend, cloud and mobile, and AI agent/LLM security (OWASP LLM Top 10). Covers 15 languages and 26 frameworks."
license: "MIT. See LICENSE-MIT"
compatibility: "Requires grep, jq, gh CLI."
metadata:
  author: E van der Vecht
  version: "3.3.0"
  repository: https://github.com/evandervecht/security-audit-skill
allowed-tools: Bash(grep:*) Bash(jq:*) Bash(gh:*) Read Glob Grep
---

# Security Audit Skill

Security audits for any project: OWASP Top 10, CWE Top 25 2025 and CVSS v4.0, with 565+ checkpoints and 85 reference guides across 15 languages, 26 frameworks, IaC, Kubernetes, GitHub Actions, APIs, frontend and AI/LLM agents. Load references on demand; never load them all.

## Audit Workflow

Scanner hits, checkpoint matches and review notes are candidates, not findings. Report a vulnerability only after an independent verifier has tried and failed to disprove it.

1. **Detect.** Identify the stack with `stack-detection.md` and load only the matching references plus `owasp-top10.md` and `cwe-top25.md`. Run the dispatcher and the checkpoints for the detected stack; review code using the loaded references. Collect candidates.
2. **Triage.** Drop fixture, test, vendored and generated paths; merge duplicates; report pure hygiene issues as `hardening`.
3. **Verify.** Hand each remaining candidate to a fresh subagent (or a separate pass after detection) with only the claim, never the detector's reasoning. The verifier follows the refutation checklist and returns `confirmed`, `unproven`, `refuted` or `hardening`.
4. **Score.** CVSS v4.0 (`cvss-scoring.md`) for `confirmed` only.
5. **Report.** Confirmed with source-to-sink trace and impact, then unproven with the one open fact, then hardening, then a short refuted list. Close with `audit-checklist.md`.

Severity needs a concrete impact. A missing second layer, where another layer already blocks the attack, is `hardening`. Full protocol and verifier prompt: `finding-verification.md`.

## Reference Files

All files are in `references/`. Language, framework, cloud, CMS and mobile references are mapped in `stack-detection.md`.

- **Core**: `owasp-top10.md`, `cwe-top25.md`, `cvss-scoring.md`, `audit-checklist.md`
- **Verification**: `finding-verification.md` (verdicts, refutation checklist, verifier prompt, finding record)
- **Vulnerability Prevention**: `xxe-prevention.md`, `deserialization-prevention.md`, `path-traversal-prevention.md`, `file-upload-security.md`, `input-validation.md`, `api-key-encryption.md`
- **Secure Architecture**: `authentication-patterns.md`, `security-headers.md`, `security-logging.md`, `cryptography-guide.md`
- **Modern Threats**: `modern-attacks.md`, `cve-patterns.md`, `cve-database.md`
- **DevSecOps**: `ci-security-pipeline.md`, `supply-chain-security.md`, `automated-scanning.md` (semgrep, trivy, gitleaks)
- **Incident Response**: `supply-chain-incident-response.md` (GitHub Actions supply chain compromises)
- **Infrastructure**: `iac-security.md` (Dockerfile, Compose, Terraform), `kubernetes-security.md`, `github-actions-security.md`
- **API and Frontend**: `api-security.md` (OWASP API Top 10), `graphql-security.md`, `frontend-security.md` (DOM XSS, SRI, CORS, postMessage, storage)
- **AI/LLM Security**: `llm-security.md` (OWASP LLM Top 10 2025, agent/skill/MCP auditing)
- **Compliance**: `compliance-gdpr.md`, `compliance-hipaa.md`, `compliance-iso27001.md`, `compliance-nist-csf.md`, `compliance-pci-dss.md`, `compliance-soc2.md`, `compliance-eu-ai-act.md`

## Scripts

```bash
# Multi-language security audit (auto-detects stack)
./scripts/security-audit-dispatcher.sh /path/to/project

# PHP-only project security audit (legacy)
./skills/security-audit/scripts/security-audit.sh /path/to/project

# GitHub repository security audit
./skills/security-audit/scripts/github-security-audit.sh owner/repo
```

---

> **Contributing:** https://github.com/evandervecht/security-audit-skill
