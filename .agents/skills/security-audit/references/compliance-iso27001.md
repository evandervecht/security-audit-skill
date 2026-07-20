# ISO 27001:2022 Annex A Controls — Security Audit Checkpoint Mapping

Mapping of ISO/IEC 27001:2022 Annex A controls to the 408 security-audit-skill checkpoints. This reference enables organizations pursuing or maintaining ISO 27001 certification to demonstrate how automated code and runtime scanning contributes to control implementation.

**Standard:** ISO/IEC 27001:2022 (third edition, published October 2022)
**Annex A Structure:** 4 themes, 93 controls (reduced from 114 in 2013 revision)

**Legend:**
- **Full** — Checkpoints provide automated evidence sufficient for the control.
- **Partial** — Checkpoints cover part of the control; manual/procedural evidence also required.
- **Supporting** — Checkpoints provide supplementary evidence but do not directly implement the control.
- **N/A** — Control has no meaningful mapping to code or runtime scanning.

---

## A.5 — Organizational Controls (37 controls)

Most organizational controls are policy and governance focused. Code scanning provides supporting evidence for a subset.

| ISO 27001 Control | Control Title | Related Checkpoints | Coverage |
|---|---|---|---|
| A.5.1 | Policies for information security | N/A — policy documentation | **N/A** |
| A.5.2 | Information security roles and responsibilities | N/A — organizational structure | **N/A** |
| A.5.3 | Segregation of duties | SA-AWS-01 (IAM least privilege), SA-GCP-01 (role separation), SA-AZURE-01 (RBAC) — detect excessive permissions that violate SoD | **Supporting** |
| A.5.4 | Management responsibilities | N/A — management oversight | **N/A** |
| A.5.5 | Contact with authorities | N/A — procedural | **N/A** |
| A.5.6 | Contact with special interest groups | N/A — procedural | **N/A** |
| A.5.7 | Threat intelligence | CVE database (cve-database.md), CWE Top 25 (cwe-top25.md), modern-attacks.md, supply-chain-security.md — automated threat intelligence integration | **Partial** |
| A.5.8 | Information security in project management | CI/CD security pipeline checkpoints — security gates in development projects | **Supporting** |
| A.5.9 | Inventory of information and other associated assets | N/A — asset inventory | **N/A** |
| A.5.10 | Acceptable use of information and other associated assets | N/A — usage policies | **N/A** |
| A.5.11 | Return of assets | N/A — HR/physical | **N/A** |
| A.5.12 | Classification of information | SA-*-secrets (detect classified/sensitive data in code), SA-REACT-05 (env vars in client), SA-NEXT-05 (public env leaks) | **Supporting** |
| A.5.13 | Labelling of information | N/A — data labelling procedures | **N/A** |
| A.5.14 | Information transfer | LIVE-TLS-* (secure transfer channels), LIVE-HDR-04 (HSTS), SA-*-crypto (encryption in transit) | **Partial** |
| A.5.15 | Access control | See A.8.5 below — authentication and authorization checkpoints | **Partial** |
| A.5.16 | Identity management | SA-DJANGO-01 (user model), SA-SPRING-01 (Identity), SA-DOTNET-01 (ASP.NET Identity), SA-AWS-02 (IAM users/roles) | **Supporting** |
| A.5.17 | Authentication information | SA-*-auth (password hashing, token validation), cryptography-guide.md (bcrypt, argon2), SA-*-10 (hardcoded credentials) | **Partial** |
| A.5.18 | Access rights | SA-AWS-01 (IAM policies), SA-GCP-01 (IAM bindings), SA-AZURE-01 (RBAC), SA-RAILS-01 (authorization), SA-DJANGO-01 (permissions) | **Partial** |
| A.5.19 | Information security in supplier relationships | supply-chain-security.md, dependency scanning checkpoints | **Partial** |
| A.5.20 | Addressing information security within supplier agreements | N/A — contractual | **N/A** |
| A.5.21 | Managing information security in the ICT supply chain | supply-chain-security.md, SA-*-dep (dependency vulnerability scanning), lockfile integrity checks | **Partial** |
| A.5.22 | Monitoring, review, and change management of supplier services | Dependency scanning (continuous CVE monitoring of third-party packages) | **Supporting** |
| A.5.23 | Information security for use of cloud services | SA-AWS-* (27 AWS checkpoints), SA-GCP-* (27 GCP checkpoints), SA-AZURE-* (27 Azure checkpoints), iac-security.md | **Full** |
| A.5.24 | Information security incident management planning and preparation | supply-chain-incident-response.md | **Supporting** |
| A.5.25 | Assessment and decision on information security events | CVSS v4.0 scoring (cvss-scoring.md), severity classification | **Partial** |
| A.5.26 | Response to information security incidents | supply-chain-incident-response.md — response playbooks | **Supporting** |
| A.5.27 | Learning from information security incidents | N/A — post-incident review process | **N/A** |
| A.5.28 | Collection of evidence | Scan output (JSON/structured) provides timestamped, reproducible evidence | **Partial** |
| A.5.29 | Information security during disruption | N/A — business continuity | **N/A** |
| A.5.30 | ICT readiness for business continuity | SA-AWS-05 (high availability), SA-GCP-05, SA-AZURE-05 — infrastructure resilience checks | **Supporting** |
| A.5.31 | Legal, statutory, regulatory, and contractual requirements | This compliance mapping document itself supports this control | **Supporting** |
| A.5.32 | Intellectual property rights | N/A — legal/licensing (though dependency license scanning could be added) | **N/A** |
| A.5.33 | Protection of records | Security logging checkpoints (log integrity, tamper prevention) | **Supporting** |
| A.5.34 | Privacy and protection of PII | SA-*-secrets (PII in code), security-logging.md (PII in logs), LIVE-HDR-05 (Referrer-Policy) | **Supporting** |
| A.5.35 | Independent review of information security | N/A — audit process | **N/A** |
| A.5.36 | Compliance with policies, rules, and standards for information security | All checkpoint scans verify compliance with security standards | **Partial** |
| A.5.37 | Documented operating procedures | N/A — documentation | **N/A** |

---

## A.6 — People Controls (8 controls)

People controls address HR security and are largely outside the scope of code scanning.

| ISO 27001 Control | Control Title | Related Checkpoints | Coverage |
|---|---|---|---|
| A.6.1 | Screening | N/A — HR background checks | **N/A** |
| A.6.2 | Terms and conditions of employment | N/A — contractual/HR | **N/A** |
| A.6.3 | Information security awareness, education, and training | Checkpoint descriptions and remediation guidance serve as developer education | **Supporting** |
| A.6.4 | Disciplinary process | N/A — HR | **N/A** |
| A.6.5 | Responsibilities after termination or change of employment | N/A — HR | **N/A** |
| A.6.6 | Confidentiality or non-disclosure agreements | N/A — legal | **N/A** |
| A.6.7 | Remote working | N/A — organizational policy | **N/A** |
| A.6.8 | Information security event reporting | Security logging checkpoints, CVSS scoring output — supports event reporting workflows | **Supporting** |

---

## A.7 — Physical Controls (14 controls)

Physical controls are not addressable by code scanning.

| ISO 27001 Control | Control Title | Related Checkpoints | Coverage |
|---|---|---|---|
| A.7.1 | Physical security perimeters | N/A | **N/A** |
| A.7.2 | Physical entry | N/A | **N/A** |
| A.7.3 | Securing offices, rooms, and facilities | N/A | **N/A** |
| A.7.4 | Physical security monitoring | N/A | **N/A** |
| A.7.5 | Protecting against physical and environmental threats | N/A | **N/A** |
| A.7.6 | Working in secure areas | N/A | **N/A** |
| A.7.7 | Clear desk and clear screen | N/A | **N/A** |
| A.7.8 | Equipment siting and protection | N/A | **N/A** |
| A.7.9 | Security of assets off-premises | SA-ANDROID-06 (mobile debuggable), SA-IOS-06 (mobile entitlements) — limited overlap for mobile device security | **Supporting** |
| A.7.10 | Storage media | N/A | **N/A** |
| A.7.11 | Supporting utilities | N/A | **N/A** |
| A.7.12 | Cabling security | N/A | **N/A** |
| A.7.13 | Equipment maintenance | N/A | **N/A** |
| A.7.14 | Secure disposal or re-use of equipment | N/A | **N/A** |

---

## A.8 — Technological Controls (34 controls)

This is the primary mapping area. Most checkpoints map to controls in this theme.

| ISO 27001 Control | Control Title | Related Checkpoints | Coverage |
|---|---|---|---|
| A.8.1 | User endpoint devices | SA-ANDROID-* (Android security checkpoints), SA-IOS-* (iOS security checkpoints), SA-ANDROID-06 (debuggable), SA-IOS-06 (entitlements) | **Partial** |
| A.8.2 | Privileged access rights | SA-AWS-01 (IAM wildcard `*`), SA-AWS-02 (root account), SA-GCP-01 (primitive roles owner/editor), SA-GCP-02 (default SA), SA-AZURE-01 (Owner/Contributor), SA-ANDROID-06 (debuggable flag) | **Full** |
| A.8.3 | Information access restriction | SA-DJANGO-01 (object-level permissions), SA-RAILS-01 (Strong Parameters / mass assignment), SA-SPRING-01 (method-level security @PreAuthorize), SA-DOTNET-01 ([Authorize] attribute), SA-BLAZOR-01 (AuthorizeView), SA-EXPRESS-01 (middleware guards), SA-NEST-01 (Guards/CASL) | **Full** |
| A.8.4 | Access to source code | SA-*-secrets (secrets in VCS — API keys, tokens, passwords in source), SA-JS-11, SA-PY-11, SA-JAVA-11, SA-GO-11, SA-NODE-11 (hardcoded credentials), SA-REACT-05 (env vars in client bundle), SA-NEXT-05 (NEXT_PUBLIC_ exposure) | **Partial** |
| A.8.5 | Secure authentication | **Password Hashing:** SA-*-crypto (bcrypt, argon2, scrypt), cryptography-guide.md **Session Management:** SA-JS-10, SA-PY-10, SA-DJANGO-03, SA-FLASK-03, SA-EXPRESS-03, SA-NEST-03 **JWT/Token:** SA-FASTAPI-01 (OAuth2), SA-SPRING-01 (Spring Security), SA-NEXT-03 (NextAuth) **MFA:** SA-AWS-02 (root MFA), SA-DJANGO-01 (django-otp) **Cookie Security:** LIVE-CORS-02 (credentials), SA-*-cookie (Secure, HttpOnly, SameSite) | **Full** |
| A.8.6 | Capacity management | SA-AWS-05, SA-GCP-05, SA-AZURE-05 (auto-scaling/capacity checks) | **Supporting** |
| A.8.7 | Protection against malware | Dependency scanning (malicious package detection), supply-chain-security.md (typosquatting, dependency confusion), CVE database | **Partial** |
| A.8.8 | Management of technical vulnerabilities | **All vulnerability scanning checkpoints (408)**, CVE database integration (cve-database.md), CVSS v4.0 scoring (cvss-scoring.md), CWE Top 25 mapping (cwe-top25.md), automated-scanning.md | **Full** |
| A.8.9 | Configuration management | **IaC Security:** SA-AWS-07 (CloudFormation misconfigurations), SA-AWS-08 (Terraform), SA-GCP-07 (Terraform/GCP), SA-AZURE-07 (ARM/Bicep), iac-security.md **Cloud Config:** SA-AWS-09 (security groups), SA-AWS-10 (S3 bucket policies), SA-GCP-06 (firewall rules), SA-AZURE-06 (NSG rules) **Framework Config:** SA-DJANGO-04 (DEBUG=True), SA-FLASK-04 (debug mode), SA-SPRING-04 (actuator exposure), SA-DOTNET-04 (detailed errors), SA-NEXT-04 (next.config.js security) | **Full** |
| A.8.10 | Information deletion | N/A — data lifecycle management | **N/A** |
| A.8.11 | Data masking | SA-*-secrets (detect unmasked secrets), security-logging.md (PII/credential masking in logs) | **Supporting** |
| A.8.12 | Data leakage prevention | SA-*-secrets (all language variants — secrets in source code), SA-REACT-05 (environment variables leaked to client), SA-NEXT-05 (NEXT_PUBLIC_ data exposure), SA-JS-11 (hardcoded API keys), SA-PY-11, SA-JAVA-11, SA-GO-11, SA-NODE-11, security-logging.md (sensitive data in logs), LIVE-HDR-05 (Referrer-Policy — URL leakage) | **Full** |
| A.8.13 | Information backup | N/A — backup procedures | **N/A** |
| A.8.14 | Redundancy of information processing facilities | SA-AWS-05, SA-GCP-05, SA-AZURE-05 (multi-AZ/region checks) | **Supporting** |
| A.8.15 | Logging | **Application Logging:** SA-JS-14, SA-PY-14, SA-JAVA-14, SA-CS-14, SA-GO-14, SA-NODE-14 (logging sensitive data prevention), security-logging.md (comprehensive logging guide) **Cloud Logging:** SA-AWS-03 (CloudTrail), SA-AWS-04 (CloudWatch), SA-GCP-03 (Cloud Audit Logs), SA-GCP-04 (Cloud Monitoring), SA-AZURE-03 (Azure Monitor), SA-AZURE-04 (Log Analytics/Sentinel) | **Full** |
| A.8.16 | Monitoring activities | **Runtime Monitoring:** All LIVE-* checkpoints (continuous runtime checks), LIVE-HDR-* (header monitoring), LIVE-TLS-* (TLS monitoring), LIVE-CORS-* (CORS monitoring) **Cloud Monitoring:** SA-AWS-04 (CloudWatch alarms), SA-GCP-04 (Cloud Monitoring), SA-AZURE-04 (Azure Monitor alerts) **CI/CD Monitoring:** CI security pipeline continuous scanning | **Full** |
| A.8.17 | Clock synchronization | N/A — infrastructure NTP configuration | **N/A** |
| A.8.18 | Use of privileged utility programs | SA-JS-04 (command injection via exec/spawn), SA-PY-04 (subprocess/os.system), SA-JAVA-04 (Runtime.exec), SA-GO-04 (os/exec), SA-NODE-04 (child_process) — detect unsafe invocation of system utilities | **Partial** |
| A.8.19 | Installation of software on operational systems | Dependency lockfile verification, supply-chain-security.md (package integrity) | **Supporting** |
| A.8.20 | Networks security | SA-AWS-09 (security groups), SA-AWS-10 (NACLs), SA-GCP-06 (VPC firewall), SA-AZURE-06 (NSG), LIVE-TLS-* (transport security) | **Partial** |
| A.8.21 | Security of network services | LIVE-TLS-01 (TLS version), LIVE-TLS-02 (certificate validity), LIVE-TLS-03 (cipher suites), LIVE-TLS-04 (HSTS preload), LIVE-CORS-* (CORS configuration) | **Full** |
| A.8.22 | Segregation of networks | SA-AWS-09 (security group isolation), SA-AWS-10 (subnet NACLs), SA-GCP-06 (VPC segmentation), SA-AZURE-06 (NSG subnet rules) | **Partial** |
| A.8.23 | Web filtering | LIVE-HDR-01 (Content-Security-Policy), LIVE-CORS-01 (origin restrictions) | **Supporting** |
| A.8.24 | Use of cryptography | **Cryptographic Algorithms:** SA-*-crypto (weak algorithm detection — MD5, SHA1, DES, RC4), cryptography-guide.md (full reference) **TLS:** LIVE-TLS-01 (minimum TLS 1.2), LIVE-TLS-03 (cipher suite strength) **Password Hashing:** SA-*-auth (bcrypt/argon2/scrypt verification) **Key Management:** SA-*-secrets (keys in source), api-key-encryption.md | **Full** |
| A.8.25 | Secure development life cycle | **All code scanning checkpoints integrated into SDLC:** CI/CD security pipeline (ci-security-pipeline.md), pre-commit hooks, PR-gate scans, OWASP Top 10 coverage (owasp-top10.md), CWE Top 25 coverage (cwe-top25.md), automated-scanning.md | **Full** |
| A.8.26 | Application security requirements | **OWASP Top 10:** owasp-top10.md (all 10 categories mapped to checkpoints) **Injection Prevention:** SA-*-01 (SQL injection across all languages), SA-*-04 (command injection), SA-*-07 (XXE) **Input Validation:** input-validation.md, SA-*-02 (XSS prevention) **Authentication/Authorization:** SA-*-auth, SA-*-access checkpoints **Session Management:** SA-*-session checkpoints | **Full** |
| A.8.27 | Secure system architecture and engineering principles | Cloud security architecture: SA-AWS-* (VPC, IAM, encryption at rest), SA-GCP-*, SA-AZURE-*, defense-in-depth via layered checkpoints | **Partial** |
| A.8.28 | Secure coding | **All language-specific checkpoints:** SA-JS-* (JavaScript/TypeScript), SA-PY-* (Python), SA-JAVA-* (Java), SA-CS-* (C#), SA-GO-* (Go), SA-RS-* (Rust), SA-RB-* (Ruby), SA-NODE-* (Node.js) **All framework-specific checkpoints:** SA-REACT-*, SA-NEXT-*, SA-VUE-*, SA-ANG-*, SA-NUXT-*, SA-DJANGO-*, SA-FLASK-*, SA-FASTAPI-*, SA-SPRING-*, SA-DOTNET-*, SA-BLAZOR-*, SA-GIN-*, SA-RAILS-*, SA-EXPRESS-*, SA-NEST-* **All CMS checkpoints:** SA-WP-*, SA-DRUPAL-*, SA-JOOMLA-* **Language feature references:** php-security-features.md, javascript-typescript-security-features.md, python-security-features.md, java-security-features.md, csharp-security-features.md, go-security-features.md, rust-security-features.md, ruby-security-features.md, nodejs-security-features.md | **Full** |
| A.8.29 | Security testing in development and acceptance | All SA-* checkpoints (static analysis), all LIVE-* checkpoints (runtime testing), CVSS scoring, CI/CD integration | **Full** |
| A.8.30 | Outsourced development | supply-chain-security.md, dependency scanning, SA-*-dep checkpoints | **Supporting** |
| A.8.31 | Separation of development, test, and production environments | SA-DJANGO-04 (DEBUG=True in production), SA-FLASK-04 (debug mode), SA-SPRING-04 (actuator exposed), SA-DOTNET-04 (detailed errors in production), SA-ANDROID-06 (debuggable in release) | **Partial** |
| A.8.32 | Change management | CI/CD security pipeline checkpoints, lockfile integrity, supply-chain-security.md | **Supporting** |
| A.8.33 | Test information | N/A — test data management | **N/A** |
| A.8.34 | Protection of information systems during audit testing | N/A — audit procedures | **N/A** |

---

## Coverage Summary by Theme

| Theme | Total Controls | Full | Partial | Supporting | N/A |
|---|---|---|---|---|---|
| A.5 Organizational | 37 | 1 | 10 | 9 | 17 |
| A.6 People | 8 | 0 | 0 | 2 | 6 |
| A.7 Physical | 14 | 0 | 0 | 1 | 13 |
| A.8 Technological | 34 | 13 | 7 | 5 | 9 |
| **Total** | **93** | **14** | **17** | **17** | **45** |

### Coverage by Level

| Coverage Level | Count | Percentage |
|---|---|---|
| Full | 14 | 15.1% |
| Partial | 17 | 18.3% |
| Supporting | 17 | 18.3% |
| N/A | 45 | 48.4% |
| **Addressable (Full + Partial + Supporting)** | **48** | **51.6%** |

---

## Gap Analysis

### Controls with No Coverage — Organizational (A.5)

These controls require policies, procedures, and organizational commitments that cannot be verified by code scanning:

1. **A.5.1 (Security Policies)** — Requires documented security policy. **Recommendation:** Reference this checkpoint mapping as evidence that technical policy is enforced via automation.

2. **A.5.2 (Roles and Responsibilities)** — Organizational chart and RACI. No technical analog.

3. **A.5.4 (Management Responsibilities)** — Management commitment evidence. No technical analog.

4. **A.5.5–A.5.6 (Contact with Authorities/Groups)** — Procedural contacts. No technical analog.

5. **A.5.9–A.5.11 (Asset Inventory/Use/Return)** — Asset management lifecycle. **Recommendation:** Add SBOM generation checkpoints to partially address A.5.9.

6. **A.5.13 (Information Labelling)** — Data classification labels. No technical analog.

7. **A.5.20 (Supplier Agreements)** — Contractual requirements. No technical analog.

8. **A.5.27 (Learning from Incidents)** — Post-incident review. No technical analog.

9. **A.5.29 (Security During Disruption)** — Business continuity. No technical analog.

10. **A.5.32 (Intellectual Property)** — License compliance. **Recommendation:** Add license scanning checkpoints (SA-*-LICENSE) to address open-source license compliance.

11. **A.5.35 (Independent Review)** — Audit process. No technical analog.

12. **A.5.37 (Documented Procedures)** — Operational documentation. No technical analog.

### Controls with No Coverage — People (A.6)

All people controls except A.6.3 and A.6.8 have no coverage. These are HR and legal controls by nature.

### Controls with No Coverage — Physical (A.7)

All 14 physical controls except A.7.9 (limited mobile device overlap) have no coverage. This is expected — code scanning cannot address physical security.

### Controls with No Coverage — Technological (A.8)

1. **A.8.10 (Information Deletion)** — Secure data deletion/retention. **Recommendation:** Add checkpoints for detecting missing data retention/deletion logic in database operations.

2. **A.8.13 (Information Backup)** — Backup verification. **Recommendation:** Add SA-AWS-BACKUP, SA-GCP-BACKUP, SA-AZURE-BACKUP checkpoints for backup configuration validation.

3. **A.8.17 (Clock Synchronization)** — NTP configuration. Outside code scanning scope.

4. **A.8.33 (Test Information)** — Test data protection. **Recommendation:** Add checkpoints detecting production data in test fixtures.

5. **A.8.34 (Audit Testing Protection)** — Audit procedures. Outside scope.

### Recommended New Checkpoint Series

| Proposed Series | ISO 27001 Control | Description |
|---|---|---|
| SA-*-LICENSE | A.5.32 | Open-source license compliance scanning |
| SA-*-SBOM | A.5.9 | Software Bill of Materials generation |
| SA-*-BACKUP | A.8.13 | Cloud backup configuration validation |
| SA-*-RETENTION | A.8.10 | Data retention/deletion logic verification |
| SA-*-TESTDATA | A.8.33 | Production data in test fixture detection |

---

## Cross-References

| Related Standard | Mapping Document |
|---|---|
| SOC 2 Trust Services Criteria | compliance-soc2.md |
| NIST CSF 2.0 | compliance-nist-csf.md |
| OWASP Top 10 | owasp-top10.md |
| CWE Top 25 | cwe-top25.md |
| CVSS v4.0 | cvss-scoring.md |

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-03-31 | Initial ISO 27001:2022 Annex A mapping created covering all 93 controls across 4 themes | security-audit-skill |
