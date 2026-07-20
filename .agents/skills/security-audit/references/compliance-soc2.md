# SOC 2 Trust Services Criteria — Security Audit Checkpoint Mapping

Mapping of AICPA SOC 2 Type II Trust Services Criteria (2017, with 2022 revisions) to the 408 security-audit-skill checkpoints. This reference enables auditors and engineering teams to demonstrate how automated code and runtime scanning satisfies SOC 2 control requirements.

**Scope:** Common Criteria (CC) series — Security category. Availability, Processing Integrity, Confidentiality, and Privacy criteria are noted where checkpoint overlap exists but are not the primary focus.

**Legend:**
- **Full** — Checkpoints provide automated evidence sufficient for the control.
- **Partial** — Checkpoints cover part of the control; manual/procedural evidence also required.
- **Procedural** — Control is primarily organizational/procedural; checkpoints provide supporting evidence only.
- **N/A** — Control has no meaningful mapping to code or runtime scanning.

---

## CC1 — Control Environment

| SOC 2 Control | Control Description | Related Checkpoints | Coverage |
|---|---|---|---|
| CC1.1 | Entity demonstrates commitment to integrity and ethical values | N/A — organizational policy | **N/A** |
| CC1.2 | Board exercises oversight responsibility | N/A — governance | **N/A** |
| CC1.3 | Management establishes structure, authority, and responsibility | N/A — organizational | **N/A** |
| CC1.4 | Entity demonstrates commitment to competence | N/A — HR/training | **N/A** |
| CC1.5 | Entity holds individuals accountable | Security logging checkpoints provide audit trail: SA-AWS-03, SA-GCP-03, SA-AZURE-03 | **Partial** |

---

## CC2 — Communication and Information

| SOC 2 Control | Control Description | Related Checkpoints | Coverage |
|---|---|---|---|
| CC2.1 | Entity obtains or generates relevant, quality information | CVE database (cve-database.md) integration, dependency scanning checkpoints across all languages | **Partial** |
| CC2.2 | Entity internally communicates information | Security logging: SA-JS-14, SA-PY-14, SA-JAVA-14, SA-CS-14, SA-GO-14, SA-NODE-14, SA-EXPRESS-10 | **Partial** |
| CC2.3 | Entity communicates with external parties | LIVE-HDR-* (security headers communicate security posture to browsers), LIVE-TLS-* | **Partial** |

---

## CC3 — Risk Assessment

| SOC 2 Control | Control Description | Related Checkpoints | Coverage |
|---|---|---|---|
| CC3.1 | Entity specifies objectives with sufficient clarity | N/A — organizational risk framework | **N/A** |
| CC3.2 | Entity identifies and analyzes risks | All vulnerability detection checkpoints (408 total), CVSS scoring (cvss-scoring.md), CWE Top 25 mapping (cwe-top25.md) | **Full** |
| CC3.3 | Entity considers potential for fraud | SA-*-01 through SA-*-05 (injection attacks), SA-*-auth (authentication bypass), CSRF checkpoints | **Partial** |
| CC3.4 | Entity identifies and assesses changes | CI/CD pipeline checkpoints, dependency scanning, supply-chain-security.md | **Partial** |

---

## CC4 — Monitoring Activities

| SOC 2 Control | Control Description | Related Checkpoints | Coverage |
|---|---|---|---|
| CC4.1 | Entity selects, develops, and performs ongoing evaluations | All automated scanning checkpoints serve as ongoing evaluations when integrated into CI/CD | **Full** |
| CC4.2 | Entity evaluates and communicates deficiencies | CVSS scoring output, severity classifications (Critical/High/Medium/Low/Info) | **Partial** |

---

## CC5 — Control Activities

| SOC 2 Control | Control Description | Related Checkpoints | Coverage |
|---|---|---|---|
| CC5.1 | Entity selects and develops control activities | All 408 checkpoints represent control activities for software security | **Full** |
| CC5.2 | Entity selects and develops technology controls | Language-specific checkpoints (SA-JS-*, SA-PY-*, SA-JAVA-*, SA-CS-*, SA-GO-*, SA-RS-*, SA-RB-*), framework checkpoints, cloud checkpoints | **Full** |
| CC5.3 | Entity deploys control activities through policies | CI security pipeline checkpoints (ci-security-pipeline.md) | **Partial** |

---

## CC6 — Logical and Physical Access Controls

| SOC 2 Control | Control Description | Related Checkpoints | Coverage |
|---|---|---|---|
| CC6.1 | Logical and physical access controls — implementation | **Authentication:** SA-JS-10, SA-PY-10, SA-JAVA-10, SA-CS-10, SA-GO-10, SA-RS-10, SA-RB-10, SA-NODE-10, SA-SPRING-01 (Spring Security config), SA-DOTNET-01 (ASP.NET Identity), SA-DJANGO-01 (Django auth), SA-FLASK-01 (Flask-Login), SA-FASTAPI-01 (OAuth2/JWT), SA-EXPRESS-01 (Passport.js), SA-NEST-01 (Guards) **Authorization:** SA-DJANGO-01 (permission decorators), SA-RAILS-01 (mass assignment / Strong Parameters), SA-SPRING-01 (method security), SA-DOTNET-01 (Authorize attribute), SA-BLAZOR-01 (AuthorizeView) **IAM:** SA-AWS-01 (IAM wildcard policies), SA-AWS-02 (IAM roles), SA-GCP-01 (IAM bindings), SA-GCP-02 (service accounts), SA-AZURE-01 (RBAC assignments), SA-AZURE-02 (managed identities) | **Full** |
| CC6.2 | Prior to issuing credentials, entity registers and authorizes new users | SA-DJANGO-01 (user registration), SA-SPRING-01 (user provisioning), SA-DOTNET-01 (Identity registration), SA-EXPRESS-01 (signup validation) | **Partial** |
| CC6.3 | Entity authorizes, modifies, or removes access | SA-AWS-01 (IAM policy review), SA-GCP-01 (IAM binding review), SA-AZURE-01 (RBAC review), SA-RAILS-01 (mass assignment prevention) | **Partial** |
| CC6.4 | Entity restricts physical access | N/A — physical security | **N/A** |
| CC6.5 | Entity discontinues logical and physical protections over assets | N/A — primarily decommissioning | **N/A** |
| CC6.6 | System boundaries — restricting external access | **Security Headers:** LIVE-HDR-01 (Content-Security-Policy), LIVE-HDR-02 (X-Content-Type-Options), LIVE-HDR-03 (X-Frame-Options), LIVE-HDR-04 (Strict-Transport-Security), LIVE-HDR-05 (Referrer-Policy), LIVE-HDR-06 (Permissions-Policy), LIVE-HDR-07 (X-XSS-Protection deprecation) **TLS:** LIVE-TLS-01 (TLS version), LIVE-TLS-02 (certificate validity), LIVE-TLS-03 (cipher suites), LIVE-TLS-04 (HSTS preload) **CORS:** LIVE-CORS-01 (Access-Control-Allow-Origin), LIVE-CORS-02 (credentials mode), LIVE-CORS-03 (allowed methods), LIVE-CORS-04 (preflight caching) **Network/Firewall:** SA-AWS-09 (security groups), SA-AWS-10 (NACLs), SA-AZURE-06 (NSG rules), SA-GCP-06 (VPC firewall rules) | **Full** |
| CC6.7 | Restriction of privileged access | SA-AWS-01 (IAM wildcard `*` detection), SA-AWS-02 (root account usage), SA-GCP-01 (primitive roles), SA-GCP-02 (default service account), SA-AZURE-01 (Owner role assignments), SA-ANDROID-06 (android:debuggable flag), SA-IOS-06 (entitlements review) | **Full** |
| CC6.8 | Entity prevents or detects unauthorized or malicious software | Dependency scanning across all languages, supply-chain-security.md checkpoints, CVE database lookups, SA-*-dep (dependency vulnerability) checkpoints | **Full** |

---

## CC7 — System Operations

| SOC 2 Control | Control Description | Related Checkpoints | Coverage |
|---|---|---|---|
| CC7.1 | Detection of vulnerabilities | **All code scanning checkpoints (408)** organized by category: **Injection:** SA-01 (SQLi), SA-JS-01, SA-PY-01, SA-JAVA-01, SA-CS-01, SA-GO-01, SA-RS-01, SA-RB-01, SA-NODE-01, SA-REACT-01, SA-NEXT-01, SA-VUE-01, SA-ANG-01, SA-NUXT-01, SA-DJANGO-01, SA-FLASK-01, SA-FASTAPI-01, SA-SPRING-01, SA-DOTNET-01, SA-BLAZOR-01, SA-GIN-01, SA-RAILS-01, SA-EXPRESS-01, SA-NEST-01 (SQL injection variants) **XSS:** SA-13 (legacy), SA-JS-02, SA-PY-02, SA-REACT-01, SA-VUE-01, SA-ANG-01 **CSRF:** SA-JS-03, SA-DJANGO-02, SA-FLASK-02, SA-SPRING-02, SA-RAILS-02, SA-EXPRESS-02 **Command Injection:** SA-JS-04, SA-PY-04, SA-JAVA-04, SA-GO-04, SA-NODE-04 **Deserialization:** SA-JS-05, SA-PY-05, SA-JAVA-05, SA-CS-05, SA-RB-05 **Path Traversal:** SA-JS-06, SA-PY-06, SA-JAVA-06, SA-NODE-06, SA-GO-06 **XXE:** SA-JAVA-07, SA-CS-07, SA-PY-07 **SSRF:** SA-JS-08, SA-PY-08, SA-JAVA-08, SA-NODE-08, SA-GO-08 **CVE Mapping:** cve-database.md (known CVE patterns) **Dependency Scanning:** All SA-*-dep checkpoints | **Full** |
| CC7.2 | Monitoring of system components for anomalies | **Cloud Audit Logging:** SA-AWS-03 (CloudTrail enabled), SA-AWS-04 (CloudWatch alarms), SA-GCP-03 (Cloud Audit Logs), SA-GCP-04 (Cloud Monitoring), SA-AZURE-03 (Azure Monitor / Activity Log), SA-AZURE-04 (Azure Sentinel) **Application Logging:** SA-JS-14 (logging sensitive data), SA-PY-14, SA-JAVA-14, SA-NODE-14 **Runtime Monitoring:** LIVE-* checkpoints (all runtime checks) | **Full** |
| CC7.3 | Entity evaluates detected events to determine incidents | CVSS v4.0 scoring (cvss-scoring.md), severity classification, CWE mapping | **Partial** |
| CC7.4 | Entity responds to identified security incidents | supply-chain-incident-response.md checkpoints | **Partial** |
| CC7.5 | Entity identifies, develops, and implements remediation activities | Remediation guidance embedded in each checkpoint, fix suggestions in scan output | **Partial** |

---

## CC8 — Change Management

| SOC 2 Control | Control Description | Related Checkpoints | Coverage |
|---|---|---|---|
| CC8.1 | Entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes | **CI/CD Security Pipeline:** ci-security-pipeline.md checkpoints, pre-commit scanning, PR-gate scanning, dependency lockfile verification **IaC Security:** SA-AWS-07 (CloudFormation), SA-AWS-08 (Terraform), SA-GCP-07 (Terraform/GCP), SA-AZURE-07 (ARM/Bicep templates), iac-security.md checkpoints **Supply Chain:** supply-chain-security.md (lockfile integrity, signed commits) | **Partial** |

---

## CC9 — Risk Mitigation

| SOC 2 Control | Control Description | Related Checkpoints | Coverage |
|---|---|---|---|
| CC9.1 | Entity identifies, selects, and develops risk mitigation activities | All checkpoints with severity scoring, CVSS v4.0 integration | **Partial** |
| CC9.2 | Entity assesses and manages risks associated with vendors and partners | Dependency scanning, supply-chain-security.md, CVE database lookups | **Partial** |

---

## Additional Criteria — Confidentiality

| SOC 2 Control | Control Description | Related Checkpoints | Coverage |
|---|---|---|---|
| C1.1 | Entity identifies and maintains confidential information | SA-*-secrets (secrets detection), API key scanning, SA-JS-11 (hardcoded secrets), SA-PY-11, SA-JAVA-11, SA-GO-11, SA-NODE-11, SA-REACT-05 (env vars in client bundle), SA-NEXT-05 (NEXT_PUBLIC_ leaks) | **Full** |
| C1.2 | Entity disposes of confidential information | N/A — data lifecycle management | **N/A** |

---

## Additional Criteria — Availability

| SOC 2 Control | Control Description | Related Checkpoints | Coverage |
|---|---|---|---|
| A1.1 | Entity maintains, monitors, and evaluates current processing capacity | SA-AWS-05 (auto-scaling), SA-GCP-05 (instance groups), SA-AZURE-05 (scale sets) | **Partial** |
| A1.2 | Entity authorizes, designs, develops, implements, operates, and monitors environmental protections | Cloud security checkpoints (SA-AWS-*, SA-GCP-*, SA-AZURE-*) | **Partial** |
| A1.3 | Entity tests recovery plan procedures | N/A — disaster recovery testing | **N/A** |

---

## Additional Criteria — Processing Integrity

| SOC 2 Control | Control Description | Related Checkpoints | Coverage |
|---|---|---|---|
| PI1.1 | Entity obtains or generates, uses, and communicates relevant quality information | Input validation checkpoints (input-validation.md), SA-*-01 through SA-*-03 (injection prevention ensures data integrity) | **Partial** |

---

## Additional Criteria — Privacy

| SOC 2 Control | Control Description | Related Checkpoints | Coverage |
|---|---|---|---|
| P1-P8 | Privacy criteria (notice, choice, collection, use, access, disclosure, quality, monitoring) | SA-*-secrets (PII detection overlap), LIVE-HDR-05 (Referrer-Policy), security-logging.md (log scrubbing of PII) | **Partial** |

---

## Coverage Summary

| Coverage Level | Control Count | Percentage |
|---|---|---|
| Full | 8 | ~24% |
| Partial | 17 | ~52% |
| Procedural | 0 | 0% |
| N/A | 8 | ~24% |

---

## Gap Analysis

The following SOC 2 controls have **no checkpoint coverage** and require purely procedural/organizational evidence:

### Controls with No Coverage (N/A)

1. **CC1.1–CC1.4 (Control Environment)** — Organizational integrity, board oversight, management structure, and competence commitment. These are governance and HR controls with no technical artifact from code scanning.

2. **CC6.4 (Physical Access)** — Physical security controls for data centers and offices. Code scanning cannot address physical access restrictions.

3. **CC6.5 (Asset Decommissioning)** — Discontinuation of protections over decommissioned assets. No automated checkpoint exists for verifying asset retirement.

4. **C1.2 (Confidential Information Disposal)** — Secure deletion and disposal procedures. Code scanning detects secrets but cannot verify disposal.

5. **A1.3 (Recovery Testing)** — Disaster recovery and business continuity testing. Outside the scope of static and runtime analysis.

### Controls with Weak Coverage (Recommended Enhancements)

1. **CC6.2 (Credential Registration)** — Current checkpoints validate authentication implementation but do not specifically verify user registration workflows (e.g., email verification, MFA enrollment). **Recommendation:** Add SA-*-REG checkpoints for registration flow validation.

2. **CC6.3 (Access Modification/Removal)** — IAM checkpoints detect overly broad permissions but do not verify access review cadence or off-boarding procedures. **Recommendation:** Add LIVE-IAM-* checkpoints for stale credential detection.

3. **CC7.4–CC7.5 (Incident Response/Remediation)** — supply-chain-incident-response.md provides partial coverage, but formal incident response plan validation is not automated. **Recommendation:** Add IR-* checkpoint series for incident response readiness.

4. **CC8.1 (Change Management)** — CI/CD checkpoints cover security scanning in pipelines but do not verify approval workflows, change documentation, or rollback procedures. **Recommendation:** Add CI-APPROVE-* checkpoints for PR approval policy validation.

5. **CC9.2 (Vendor Risk)** — Dependency scanning identifies known CVEs but does not assess vendor security posture holistically. **Recommendation:** Integrate SBOM (Software Bill of Materials) generation checkpoints.

6. **Privacy Criteria (P1–P8)** — Minimal overlap with code scanning. Organizations requiring SOC 2 + Privacy should supplement with dedicated privacy scanning tools and data mapping exercises.

---

## Implementation Guidance

### Using This Mapping for SOC 2 Audits

1. **Evidence Collection:** Run the security-audit-skill scan and export results as JSON. Each finding maps to the checkpoint IDs listed above.

2. **Control Matrices:** Use the checkpoint-to-control mapping to populate your SOC 2 control matrix. Each scan run provides timestamped evidence.

3. **Continuous Monitoring:** Integrate scans into CI/CD pipelines (ci-security-pipeline.md) to demonstrate ongoing control effectiveness for CC4.1 and CC7.1.

4. **Gap Remediation:** Address items in the Gap Analysis section through organizational policies, manual procedures, or additional tooling.

### Cross-References

- **OWASP Top 10:** owasp-top10.md — Maps to CC7.1 vulnerability detection
- **CWE Top 25:** cwe-top25.md — Maps to CC3.2 risk identification
- **CVSS Scoring:** cvss-scoring.md — Maps to CC7.3 event evaluation
- **CVE Database:** cve-database.md — Maps to CC6.8 and CC7.1
- **Supply Chain:** supply-chain-security.md — Maps to CC9.2 vendor risk

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-03-31 | Initial SOC 2 mapping created with all CC, Confidentiality, Availability, Processing Integrity, and Privacy criteria | security-audit-skill |
