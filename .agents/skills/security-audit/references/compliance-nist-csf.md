# NIST Cybersecurity Framework 2.0 — Security Audit Checkpoint Mapping

Mapping of NIST CSF 2.0 (released February 2024) functions, categories, and subcategories to the 408 security-audit-skill checkpoints. This reference enables organizations aligning to NIST CSF to demonstrate how automated code and runtime scanning contributes to cybersecurity outcomes.

**Framework Version:** NIST CSF 2.0 (NIST CSWP 29, February 26, 2024)
**Key Change from 1.1:** Addition of GOVERN (GV) function as the sixth core function.

**Legend:**
- **Full** — Checkpoints provide automated evidence sufficient for the category/subcategory.
- **Partial** — Checkpoints cover part of the category; manual/procedural evidence also required.
- **Supporting** — Checkpoints provide supplementary evidence but do not directly address the category.
- **N/A** — Category has no meaningful mapping to code or runtime scanning.

---

## GOVERN (GV) — Organizational Context, Strategy, and Supply Chain Risk Management

The GOVERN function establishes and monitors the organization's cybersecurity risk management strategy. Most subcategories are organizational/procedural, with limited but meaningful checkpoint overlap in supply chain risk.

| NIST CSF 2.0 ID | Category / Subcategory | Related Checkpoints | Coverage |
|---|---|---|---|
| GV.OC | **Organizational Context** — GV.OC-01 through GV.OC-04 are N/A (organizational mission, stakeholders, objectives). Mapped subcategories below: | | |
| GV.OC-03 | Legal, regulatory, and contractual requirements are understood | Compliance mapping documents (this file, compliance-soc2.md, compliance-iso27001.md) | **Supporting** |
| GV.OC-05 | Dependencies on other organizations are understood | supply-chain-security.md, SA-*-dep (dependency inventory) | **Supporting** |
| GV.RM | **Risk Management Strategy** — GV.RM-01/02/04/05/07 are N/A (risk appetite, strategy, communication). Mapped subcategories below: | | |
| GV.RM-03 | Cybersecurity risk management included in enterprise risk management | CVSS v4.0 scoring (cvss-scoring.md) provides quantified risk metrics | **Supporting** |
| GV.RM-06 | Standardized method for calculating and communicating cybersecurity risk | CVSS v4.0 scoring (cvss-scoring.md) — standardized methodology | **Partial** |
| GV.RR | **Roles, Responsibilities, and Authorities** — GV.RR-01 through GV.RR-04 are all N/A (governance structure, organizational roles, HR). No checkpoint mapping. | | **N/A** |
| GV.PO | **Policy** — GV.PO-01 is N/A (policy documentation). Mapped subcategory below: | | |
| GV.PO-02 | Cybersecurity risk policy is enforced | CI/CD security pipeline checkpoints enforce policy automatically | **Supporting** |
| GV.SC | Cybersecurity Supply Chain Risk Management | | |
| GV.SC-01 | A cybersecurity supply chain risk management program is established | supply-chain-security.md (comprehensive supply chain program) | **Partial** |
| GV.SC-02 | Supplier cybersecurity roles established | N/A — contractual | **N/A** |
| GV.SC-03 | Supply chain risk integrated into enterprise risk | supply-chain-security.md, dependency scanning in CI/CD | **Supporting** |
| GV.SC-04 | Suppliers known and prioritized by criticality | SA-*-dep (dependency inventory), supply-chain-security.md | **Supporting** |
| GV.SC-05 | Requirements for supply chain risks established | Lockfile integrity checks, dependency pinning | **Supporting** |
| GV.SC-06 | Due diligence before supplier relationships | N/A — procurement | **N/A** |
| GV.SC-07 | Provisions for concluded relationships | N/A — contractual offboarding | **N/A** |
| GV.SC-08 | Third parties included in incident planning | supply-chain-incident-response.md | **Supporting** |
| GV.SC-09 | Supply chain practices integrated into risk management | supply-chain-security.md, all language-specific scanning | **Partial** |
| GV.SC-10 | Provisions for evolving supply chain risks | CVE database (cve-database.md) continuous updates | **Supporting** |

---

## IDENTIFY (ID) — Asset Management, Risk Assessment, and Improvement

| NIST CSF 2.0 ID | Category / Subcategory | Related Checkpoints | Coverage |
|---|---|---|---|
| ID.AM | **Asset Management** — ID.AM-01 (hardware inventory) and ID.AM-08 (lifecycle) are N/A. Mapped subcategories: | | |
| ID.AM-02 | Software/service inventories maintained | SA-*-dep (dependency inventory), supply-chain-security.md (SBOM) | **Partial** |
| ID.AM-03 | Network communication flows documented | SA-AWS-09, SA-GCP-06, SA-AZURE-06 (firewall/NSG rules), LIVE-CORS-* | **Supporting** |
| ID.AM-04 | Supplier service inventories maintained | Dependency scanning provides third-party library inventory | **Supporting** |
| ID.AM-05 | Assets prioritized by criticality | CVSS scoring prioritizes by impact | **Supporting** |
| ID.AM-07 | Data inventories maintained | SA-*-secrets (sensitive data locations in codebase) | **Supporting** |
| ID.RA | Risk Assessment | | |
| ID.RA-01 | Vulnerabilities in assets are identified, validated, and recorded | **All 408 scanning checkpoints** — automated vulnerability identification, validation via pattern matching, recorded in structured output | **Full** |
| ID.RA-02 | Cyber threat intelligence is received from information sharing forums and sources | CVE database (cve-database.md), CWE Top 25 (cwe-top25.md), modern-attacks.md, OWASP Top 10 (owasp-top10.md) | **Partial** |
| ID.RA-03 | Internal and external threats to the organization are identified and recorded | All checkpoints identify internal code vulnerabilities; CVE database identifies external threats from dependencies | **Partial** |
| ID.RA-04 | Potential impacts and likelihoods of threats exploiting vulnerabilities are identified and recorded | CVSS v4.0 scoring (cvss-scoring.md) calculates impact and exploitability scores | **Full** |
| ID.RA-05 | Threats, vulnerabilities, likelihoods, and impacts are used to understand risk and inform prioritization | Severity classification (Critical/High/Medium/Low/Info), CVSS scoring, CWE mapping | **Full** |
| ID.RA-06 | Risk responses are chosen, prioritized, planned, tracked, and communicated | Remediation guidance in each checkpoint, fix suggestions | **Partial** |
| ID.RA-07 | Changes/exceptions managed for risk impact | N/A — change management process | **N/A** |
| ID.RA-08 | Vulnerability disclosure processes established | supply-chain-incident-response.md | **Supporting** |
| ID.RA-09 | Software authenticity/integrity assessed before use | supply-chain-security.md (package integrity, lockfile, signatures) | **Partial** |
| ID.RA-10 | Critical suppliers assessed before acquisition | N/A — procurement | **N/A** |
| ID.IM | **Improvement** — ID.IM-03 is N/A (operational process review). Mapped subcategories: | | |
| ID.IM-01 | Improvements identified from evaluations | Gap analysis in compliance mappings | **Supporting** |
| ID.IM-02 | Improvements from security tests | Scan results identify remediation improvements | **Partial** |
| ID.IM-04 | Incident response plans maintained | supply-chain-incident-response.md | **Supporting** |

---

## PROTECT (PR) — Access Control, Data Security, Platform Security, Technology Infrastructure Resilience

This is the highest-coverage function for code and runtime scanning checkpoints.

| NIST CSF 2.0 ID | Category / Subcategory | Related Checkpoints | Coverage |
|---|---|---|---|
| PR.AA | Identity Management, Authentication, and Access Control | | |
| PR.AA-01 | Identities and credentials for authorized users, services, and hardware are managed | SA-AWS-01 (IAM policies), SA-AWS-02 (IAM users/roles), SA-GCP-01 (IAM bindings), SA-GCP-02 (service accounts), SA-AZURE-01 (RBAC), SA-AZURE-02 (managed identities) | **Full** |
| PR.AA-02 | Identities are proofed and bound to credentials based on the context of interactions | SA-DJANGO-01 (user registration), SA-SPRING-01 (identity binding), SA-DOTNET-01 (ASP.NET Identity), SA-FASTAPI-01 (OAuth2 flows) | **Partial** |
| PR.AA-03 | Users, services, and hardware are authenticated | **All authentication checkpoints:** SA-JS-10, SA-PY-10, SA-JAVA-10, SA-CS-10, SA-GO-10, SA-RS-10, SA-RB-10, SA-NODE-10, SA-SPRING-01 (Spring Security), SA-DOTNET-01 (Identity), SA-DJANGO-01 (Django auth), SA-FLASK-01 (Flask-Login), SA-FASTAPI-01 (OAuth2/JWT), SA-EXPRESS-01 (Passport.js), SA-NEST-01 (Guards), SA-NEXT-03 (NextAuth), SA-NUXT-03 (auth module), SA-AWS-02 (root MFA) | **Full** |
| PR.AA-04 | Identity assertions are protected, conveyed, and verified | SA-*-crypto (JWT signing), SA-FASTAPI-01 (token verification), SA-SPRING-01 (token validation), LIVE-TLS-* (secure transport for assertions) | **Full** |
| PR.AA-05 | Access permissions, entitlements, and authorizations are defined with least privilege and separation of duties | SA-AWS-01 (IAM wildcard detection), SA-GCP-01 (primitive role detection), SA-AZURE-01 (excessive role assignments), SA-DJANGO-01 (object permissions), SA-RAILS-01 (Strong Parameters), SA-SPRING-01 (@PreAuthorize), SA-DOTNET-01 ([Authorize]), SA-BLAZOR-01 (AuthorizeView), SA-EXPRESS-01 (middleware), SA-NEST-01 (Guards) | **Full** |
| PR.AA-06 | Physical access to assets is managed, monitored, and enforced | N/A — physical access | **N/A** |
| PR.DS | Data Security | | |
| PR.DS-01 | The confidentiality, integrity, and availability of data-at-rest are protected | SA-*-crypto (encryption algorithm validation), SA-AWS-10 (S3 encryption), SA-GCP-08 (Cloud Storage encryption), SA-AZURE-08 (blob encryption), cryptography-guide.md | **Full** |
| PR.DS-02 | The confidentiality, integrity, and availability of data-in-transit are protected | LIVE-TLS-01 (TLS 1.2+ enforcement), LIVE-TLS-02 (certificate validity), LIVE-TLS-03 (strong cipher suites), LIVE-TLS-04 (HSTS preload), LIVE-HDR-04 (Strict-Transport-Security), SA-*-crypto (transport encryption) | **Full** |
| PR.DS-10 | The confidentiality, integrity, and availability of data-in-use are protected | SA-*-secrets (runtime secret exposure), SA-REACT-05 (client-side env exposure), SA-NEXT-05 (NEXT_PUBLIC_ leaks), security-logging.md (sensitive data in logs) | **Partial** |
| PR.DS-11 | Backups of data are created, protected, maintained, and tested | SA-AWS-05 (backup config), SA-GCP-05, SA-AZURE-05 (backup verification) | **Supporting** |
| PR.PS | Platform Security | | |
| PR.PS-01 | The configuration of the IT asset is managed and maintained | **IaC Configuration:** SA-AWS-07 (CloudFormation), SA-AWS-08 (Terraform), SA-GCP-07 (Terraform/GCP), SA-AZURE-07 (ARM/Bicep), iac-security.md **Application Config:** SA-DJANGO-04 (DEBUG), SA-FLASK-04 (debug), SA-SPRING-04 (actuator), SA-DOTNET-04 (errors), SA-NEXT-04 (next.config.js) **Cloud Config:** SA-AWS-09 (security groups), SA-AWS-10 (S3 policies), SA-GCP-06 (firewall), SA-AZURE-06 (NSG) | **Full** |
| PR.PS-02 | Software is maintained, replaced, and removed commensurate with risk | Dependency scanning (CVE detection triggers update), supply-chain-security.md (outdated dependency detection) | **Partial** |
| PR.PS-03 | Hardware is maintained, replaced, and removed commensurate with risk | N/A — hardware lifecycle | **N/A** |
| PR.PS-04 | Log records are generated and made available for continuous monitoring | SA-JS-14, SA-PY-14, SA-JAVA-14, SA-CS-14, SA-GO-14, SA-NODE-14 (logging implementation), SA-AWS-03 (CloudTrail), SA-GCP-03 (Audit Logs), SA-AZURE-03 (Monitor), security-logging.md | **Full** |
| PR.PS-05 | Installation and execution of unauthorized software is prevented | supply-chain-security.md (lockfile integrity, dependency confusion prevention), SA-*-dep (approved dependency validation) | **Partial** |
| PR.PS-06 | Secure software development practices are integrated into the software development life cycle | **All 408 scanning checkpoints**, CI/CD security pipeline, OWASP Top 10 coverage, CWE Top 25 coverage, automated-scanning.md | **Full** |
| PR.IR | Technology Infrastructure Resilience | | |
| PR.IR-01 | Networks and environments are protected from unauthorized logical access and usage | SA-AWS-09 (security groups), SA-AWS-10 (NACLs), SA-GCP-06 (VPC firewall), SA-AZURE-06 (NSG), LIVE-CORS-* (origin restrictions), LIVE-HDR-01 (CSP) | **Full** |
| PR.IR-02 | The organization's technology assets are protected from environmental threats | N/A — physical/environmental | **N/A** |
| PR.IR-03 | Mechanisms are implemented to achieve resilience requirements in normal and adverse situations | SA-AWS-05, SA-GCP-05, SA-AZURE-05 (multi-AZ, auto-scaling, redundancy checks) | **Supporting** |
| PR.IR-04 | Adequate resource capacity to ensure availability is maintained | SA-AWS-05, SA-GCP-05, SA-AZURE-05 (capacity/scaling configuration checks) | **Supporting** |

---

## DETECT (DE) — Continuous Monitoring and Adverse Event Analysis

Strong checkpoint coverage in this function through runtime checks and automated scanning.

| NIST CSF 2.0 ID | Category / Subcategory | Related Checkpoints | Coverage |
|---|---|---|---|
| DE.CM | Continuous Monitoring | | |
| DE.CM-01 | Networks and network services are monitored to find potentially adverse events | LIVE-TLS-* (TLS monitoring), LIVE-HDR-* (header monitoring), LIVE-CORS-* (CORS monitoring), SA-AWS-04 (CloudWatch), SA-GCP-04 (Cloud Monitoring), SA-AZURE-04 (Azure Monitor) | **Full** |
| DE.CM-02 | The physical environment is monitored to find potentially adverse events | N/A — physical monitoring | **N/A** |
| DE.CM-03 | Personnel activity and technology usage are monitored to find potentially adverse events | SA-AWS-03 (CloudTrail — API activity logging), SA-GCP-03 (Audit Logs), SA-AZURE-03 (Activity Log), security-logging.md (application-level activity logging) | **Partial** |
| DE.CM-06 | External service provider activities and services are monitored to find potentially adverse events | Dependency CVE monitoring (continuous), supply-chain-security.md (package registry monitoring) | **Partial** |
| DE.CM-09 | Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events | **All LIVE-* runtime checkpoints**, SA-AWS-04 (CloudWatch alarms), SA-GCP-04 (monitoring alerts), SA-AZURE-04 (Monitor alerts), all CI/CD continuous scanning | **Full** |
| DE.AE | Adverse Event Analysis | | |
| DE.AE-02 | Potentially adverse events are analyzed to better understand associated activities | CVSS v4.0 scoring (cvss-scoring.md) — impact and exploitability analysis, CWE classification, OWASP category mapping | **Partial** |
| DE.AE-03 | Information is correlated from multiple sources | Cross-reference between static analysis (SA-*), runtime checks (LIVE-*), CVE database, and CWE/OWASP mappings | **Partial** |
| DE.AE-04 | The estimated impact and scope of adverse events are understood | CVSS v4.0 scoring provides quantified impact/scope, severity classification (Critical/High/Medium/Low/Info) | **Full** |
| DE.AE-06 | Information on adverse events is provided to authorized staff and tools | Structured scan output (JSON), CI/CD pipeline integration, severity-based alerting | **Partial** |
| DE.AE-07 | Cyber threat intelligence and other contextual information are integrated into the analysis | CVE database (cve-database.md), CWE Top 25 (cwe-top25.md), OWASP Top 10 (owasp-top10.md), modern-attacks.md | **Partial** |
| DE.AE-08 | Incidents are declared when adverse events meet defined criteria | CVSS threshold-based severity classification triggers incident declaration | **Supporting** |

---

## RESPOND (RS) — Incident Management, Analysis, Reporting, and Mitigation

| NIST CSF 2.0 ID | Category / Subcategory | Related Checkpoints | Coverage |
|---|---|---|---|
| RS.MA | **Incident Management** — RS.MA-04/05 are N/A (escalation, recovery criteria). Mapped subcategories: | | |
| RS.MA-01 | Incident response plan executed with third parties | supply-chain-incident-response.md (playbooks) | **Supporting** |
| RS.MA-02 | Incident reports triaged and validated | CVSS scoring for triage, false positive validation | **Supporting** |
| RS.MA-03 | Incidents categorized and prioritized | Severity classification (Critical/High/Medium/Low/Info), CWE/OWASP categorization | **Partial** |
| RS.AN | **Incident Analysis** | | |
| RS.AN-03 | Analysis of what took place during incident | Checkpoint remediation guidance provides root cause context | **Supporting** |
| RS.AN-06 | Investigation actions recorded | Scan output: timestamped, reproducible records | **Supporting** |
| RS.AN-07 | Incident data integrity preserved | Structured JSON output with timestamps and checkpoint IDs | **Supporting** |
| RS.AN-08 | Incident magnitude estimated | CVSS v4.0 scoring quantifies magnitude | **Partial** |
| RS.CO | **Incident Reporting** — RS.CO-02/03 are N/A (notification and sharing procedures). | | **N/A** |
| RS.MI | **Incident Mitigation** — RS.MI-01 is N/A (runtime containment). Mapped subcategory: | | |
| RS.MI-02 | Incidents eradicated | Remediation guidance provides eradication steps (code fixes, config changes) | **Supporting** |

---

## RECOVER (RC) — Incident Recovery Planning and Execution

Recovery is primarily procedural and operational. RC.RP-01/02/04/05/06 and RC.CO-03/04 are all N/A (recovery execution, prioritization, business continuity, communications). The single mapped subcategory:

| NIST CSF 2.0 ID | Category / Subcategory | Related Checkpoints | Coverage |
|---|---|---|---|
| RC.RP-03 | Integrity of backups and restoration assets is verified | SA-AWS-05, SA-GCP-05, SA-AZURE-05 (backup configuration checks) | **Supporting** |

---

## Coverage Summary by Function

| NIST CSF 2.0 Function | Subcategories | Full | Partial | Supporting | N/A |
|---|---|---|---|---|---|
| GOVERN (GV) | 28 | 0 | 3 | 9 | 16 |
| IDENTIFY (ID) | 21 | 3 | 5 | 5 | 8 |
| PROTECT (PR) | 19 | 9 | 4 | 3 | 3 |
| DETECT (DE) | 11 | 3 | 5 | 1 | 2 |
| RESPOND (RS) | 13 | 0 | 2 | 5 | 6 |
| RECOVER (RC) | 8 | 0 | 0 | 1 | 7 |
| **Total** | **100** | **15** | **19** | **24** | **42** |

### Coverage by Level

| Coverage Level | Count | Percentage |
|---|---|---|
| Full | 15 | 15.0% |
| Partial | 19 | 19.0% |
| Supporting | 24 | 24.0% |
| N/A | 42 | 42.0% |
| **Addressable (Full + Partial + Supporting)** | **58** | **58.0%** |

### Strongest Coverage Areas

1. **PR.AA (Identity Management, Authentication, Access Control)** — 5 of 6 subcategories at Full coverage
2. **PR.DS (Data Security)** — 2 of 4 subcategories at Full coverage
3. **PR.PS (Platform Security)** — 3 of 6 subcategories at Full coverage
4. **DE.CM (Continuous Monitoring)** — 2 of 5 addressable subcategories at Full coverage
5. **ID.RA (Risk Assessment)** — 3 of 10 subcategories at Full coverage

---

## Gap Analysis

### Functions with No or Minimal Coverage

- **GOVERN (GV)** — 0 Full, 3 Partial. Inherently organizational. GV.SC (Supply Chain) has strongest coverage via supply-chain-security.md. **Recommendation:** Add SBOM generation for GV.SC-04.
- **RECOVER (RC)** — 0 Full, 0 Partial. Entirely procedural. Appropriately outside scope; backup config checks (SA-AWS/GCP/AZURE-05) are the sole contribution.
- **RESPOND (RS)** — 0 Full, 2 Partial. Primarily procedural. **Recommendation:** Add IR-* checkpoint series for incident response automation (auto-blocking, rollback triggers, circuit breakers).

### Key N/A Subcategories

Physical controls (ID.AM-01, DE.CM-02, PR.AA-06) and procedural controls (RS.MA-04/05, RS.CO-02/03) are outside code scanning scope. No checkpoint additions recommended for these.

### Recommended New Checkpoint Series for NIST CSF Alignment

| Proposed Series | NIST CSF Category | Description |
|---|---|---|
| SA-*-SBOM | GV.SC-04, ID.AM-02 | Software Bill of Materials generation and validation |
| IR-* | RS.MA, RS.MI | Incident response automation verification (circuit breakers, auto-blocking, rollback) |
| SA-*-NOTIFY | RS.CO | Security event notification configuration validation |
| SA-*-BASELINE | PR.PS-01 | Configuration baseline drift detection |

---

## Cross-References

| NIST CSF 2.0 | SOC 2 Equivalent | ISO 27001 Equivalent | Skill Reference |
|---|---|---|---|
| GV (Govern) | CC1, CC2, CC3 | A.5 Organizational | compliance-soc2.md, compliance-iso27001.md |
| ID (Identify) | CC3, CC4 | A.5.7, A.5.9, A.8.8 | cve-database.md, cvss-scoring.md |
| PR (Protect) | CC5, CC6, CC8 | A.8 Technological | owasp-top10.md, cryptography-guide.md |
| DE (Detect) | CC7 | A.8.15, A.8.16 | cwe-top25.md, automated-scanning.md |
| RS (Respond) | CC7.4, CC7.5 | A.5.24–A.5.28 | supply-chain-incident-response.md |
| RC (Recover) | CC9 | A.5.29, A.5.30 | N/A — outside code scanning scope |

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-03-31 | Initial NIST CSF 2.0 mapping created covering all 6 functions and 100 subcategories | security-audit-skill |
