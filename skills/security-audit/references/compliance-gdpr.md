# GDPR Compliance Mapping (Security of Processing)

Maps GDPR Articles 25, 32, and 35 to security-audit-skill checkpoints. Use this reference when auditing applications that process personal data of EU/EEA data subjects. Checkpoints prefixed with LIVE-* are runtime/dynamic checks; all others are static analysis checkpoints defined in checkpoints.yaml.

**Regulation:** General Data Protection Regulation (EU) 2016/679
**Focus:** Article 32 (Security of Processing), Article 25 (Data Protection by Design and by Default), Article 35 (Data Protection Impact Assessment)
**Scope:** Technical measures mapped to 408 security checkpoints across 30+ technology stacks

---

## Article 32 -- Security of Processing

Article 32(1) requires the controller and processor to implement appropriate technical and organisational measures to ensure a level of security appropriate to the risk, including as appropriate:

### Article 32(1)(a) -- Pseudonymisation and Encryption of Personal Data

| Category | Related Checkpoints | Coverage |
|---|---|---|
| **Encryption at rest (cloud storage)** | SA-AWS-05, SA-AWS-06 (S3 public access/encryption), SA-AZURE-03 (Blob public access), SA-GCP-03 (GCS bucket access), SA-AWS-10 (KMS key rotation) | **Good** -- detects unencrypted or publicly accessible storage |
| **Encryption at rest (databases)** | SA-AWS-12 (hardcoded DB passwords), SA-GCP-04 (Cloud SQL config), SA-AZURE-04 (SQL config) | **Partial** -- credential exposure; no encryption-at-rest toggle verification |
| **Encryption in transit (TLS)** | LIVE-TLS-01 (TLS 1.2+ enforcement), LIVE-TLS-02 (strong cipher suites), LIVE-TLS-03 (certificate validity) | **Good** -- runtime TLS validation |
| **HSTS enforcement** | LIVE-HDR-HSTS, SA-DJANGO-05 (SECURE_HSTS_SECONDS), SA-RAILS-05 (force_ssl), SA-EXPRESS-04 (helmet), SA-NEXT-04, SA-NUXT-04, SA-SPRING-04, SA-DOTNET-04 | **Good** -- framework and runtime checks |
| **Weak cryptography detection** | SA-23, SA-24 (md5/sha1 passwords), SA-PY-07, SA-JAVA-07, SA-CS-07, SA-GO-07, SA-RS-07, SA-RB-07 (per-language weak crypto) | **Good** -- cross-language weak algorithm detection |
| **Insecure randomness** | SA-29, SA-30 (PHP rand/mt_rand), SA-JS-07 (Math.random for security), SA-PY-10 (random module for security) | **Partial** -- common patterns detected |
| **Mobile encryption** | SA-IOS-02 (ATS bypass), SA-IOS-03 (Keychain usage), SA-ANDROID-07 (custom TrustManager), SA-ANDROID-08 (cleartext traffic), SA-ANDROID-03 (insecure storage) | **Good** -- mobile-specific encryption checks |
| **Key management** | SA-AWS-10 (KMS rotation), SA-AWS-07 (secrets in Lambda env), SA-SEC-01 through SA-SEC-04 (leaked keys) | **Partial** -- rotation and exposure; no key lifecycle management |

#### Gaps
- No pseudonymisation technique validation (tokenisation, data masking)
- No field-level encryption checks for specific personal data columns
- No encryption algorithm strength verification beyond known-weak detection

---

### Article 32(1)(b) -- Confidentiality, Integrity, Availability, and Resilience of Processing Systems

#### Confidentiality

| Category | Related Checkpoints | Coverage |
|---|---|---|
| **Access control (authentication)** | SA-SPRING-01, SA-DOTNET-01, SA-DJANGO-01, SA-FLASK-01, SA-FASTAPI-01, SA-RAILS-01, SA-EXPRESS-01, SA-NEST-01, SA-GIN-01, SA-BLAZOR-01 | **Good** -- auth implementation across all frameworks |
| **Access control (authorization)** | SA-40 (IDOR), SA-AWS-01 through SA-AWS-04 (IAM), SA-GCP-01/SA-GCP-02, SA-AZURE-01/SA-AZURE-02 | **Good** -- authorization and IAM checks |
| **Secrets management** | SA-02, SA-03 (.env in gitignore), SA-04 through SA-06 (hardcoded credentials), SA-AWS-07 (Lambda secrets), SA-SEC-01 through SA-SEC-04 (key patterns), SA-SC-01/SA-SC-02 | **Excellent** -- comprehensive secret detection |
| **Data exposure prevention** | SA-31 (phpinfo), SA-DJANGO-04 (DEBUG=True), SA-FLASK-03 (debug mode), SA-ANDROID-06 (debuggable), SA-FE-04 (source maps in production) | **Good** -- debug/info exposure detection |
| **CORS configuration** | SA-JS-10 (permissive CORS), SA-EXPRESS-03 (CORS middleware), SA-SPRING-03 (CORS config), SA-DJANGO-03 (CORS headers), SA-FLASK-02 (CORS), SA-FASTAPI-02 (CORS middleware), SA-GIN-02 (CORS), SA-RAILS-03 (CORS), SA-DOTNET-03 (CORS policy), SA-NEST-03 | **Excellent** -- cross-framework CORS validation |

#### Integrity

| Category | Related Checkpoints | Coverage |
|---|---|---|
| **SQL injection prevention** | SA-10 through SA-12 (PHP), SA-JS-01, SA-PY-01, SA-JAVA-01, SA-CS-01, SA-GO-01, SA-RS-01, SA-RB-01, SA-NODE-01 | **Excellent** -- all languages covered |
| **XSS prevention** | SA-13 (PHP), SA-JS-03, SA-REACT-01, SA-VUE-01, SA-ANG-01, SA-NEXT-01, SA-NUXT-01, SA-BLAZOR-02, SA-FE-01, SA-FE-02 | **Excellent** -- all frontend frameworks |
| **CSRF protection** | SA-DJANGO-02 (CSRF middleware), SA-SPRING-05 (CSRF config), SA-RAILS-02 (CSRF token), SA-FLASK-05 (WTForms CSRF), SA-DOTNET-05 (antiforgery), SA-BLAZOR-03 (antiforgery), SA-NEXT-02 | **Good** -- cross-framework CSRF checks |
| **Command injection** | SA-25 through SA-28 (PHP), SA-JS-05, SA-PY-05, SA-JAVA-05, SA-RB-05, SA-NODE-05, SA-GO-05 | **Good** -- all backend languages |
| **Deserialization** | SA-21, SA-22 (PHP), SA-PY-06, SA-JAVA-06, SA-CS-06, SA-RB-06, SA-NODE-06 | **Good** -- all major languages |
| **XXE prevention** | SA-08, SA-08b, SA-09 (PHP), SA-JAVA-08, SA-CS-08, SA-PY-08 | **Good** -- XML-processing languages |
| **Path traversal** | SA-JS-04, SA-PY-04, SA-JAVA-04, SA-NODE-04, SA-GO-04, SA-RB-04 | **Good** |
| **SSRF prevention** | SA-JS-09, SA-PY-09, SA-JAVA-09, SA-NODE-09, SA-GO-09 | **Good** |
| **Supply chain integrity** | SA-SC-01, SA-SC-02, SA-DEP-01 through SA-DEP-03, SA-14/SA-15 (Dependabot) | **Good** |

#### Availability

| Category | Related Checkpoints | Coverage |
|---|---|---|
| **Error handling** | SA-DJANGO-04 (DEBUG=True), SA-FLASK-03 (debug mode), SA-31 (phpinfo) | **Low** -- detects info leaks, not availability patterns |
| **Rate limiting** | SA-EXPRESS-05, SA-NEST-05, SA-SPRING-02 | **Low** -- limited framework coverage |
| **Cloud HA** | SA-AWS-11 (multi-region trails) | **Low** -- minimal availability checks |

#### Gaps
- No availability/resilience pattern detection (circuit breakers, retry logic, health checks)
- No rate limiting validation beyond a few frameworks
- No DDoS protection configuration checks

---

### Article 32(1)(c) -- Ability to Restore Availability and Access to Personal Data in a Timely Manner

| Category | Related Checkpoints | Coverage |
|---|---|---|
| **Backup configuration** | None directly | **None** |
| **Disaster recovery** | None directly | **None** |
| **Error handling / graceful degradation** | SA-DJANGO-04, SA-FLASK-03 (debug mode detection implies error handling review) | **Low** |
| **Cloud resilience** | SA-AWS-11 (multi-region CloudTrail) | **Low** -- tangential |

#### Gaps
- No backup configuration validation in IaC
- No disaster recovery plan verification
- No RTO/RPO configuration checks
- No database replication/failover detection
- This is primarily an infrastructure operations concern beyond code analysis scope

---

### Article 32(1)(d) -- Regular Testing, Assessing, and Evaluating Effectiveness of Technical and Organisational Measures

| Category | Related Checkpoints | Coverage |
|---|---|---|
| **Static analysis (SAST)** | SA-SAST-01 (semgrep in CI), SA-SAST-02 (custom rules) | **Good** -- CI integration |
| **Dependency scanning** | SA-DEP-01 (trivy), SA-DEP-02 (severity filtering), SA-DEP-03 (SBOM generation) | **Good** -- automated CVE detection |
| **Secret scanning** | SA-SEC-01 through SA-SEC-04, SA-02/SA-03 | **Good** |
| **CI pipeline security** | SA-07 (composer audit), SA-SAST-01 (semgrep), SA-14/SA-15 (Dependabot) | **Good** -- per-commit security gates |
| **Deep scanning** | SA-16 through SA-20 (multi-pass LLM analysis) | **Good** -- advanced analysis |
| **LLM-assisted review** | SA-LLM-21 through SA-LLM-38 (18 LLM review checkpoints) | **Good** -- AI-augmented security review |
| **Supply chain monitoring** | SA-SC-01, SA-SC-02 | **Partial** |
| **Runtime testing** | LIVE-TLS-01 through LIVE-TLS-03, LIVE-HDR-* (header checks) | **Partial** -- TLS and header validation |

#### Gaps
- No penetration testing workflow integration
- No security testing schedule enforcement
- No test coverage metrics for security-critical code paths
- No red team / adversarial testing support

---

## Article 25 -- Data Protection by Design and by Default

Article 25 requires that data protection principles are implemented from the outset of system design and that, by default, only personal data necessary for each specific purpose is processed.

### Article 25(1) -- Data Protection by Design

| Principle | Related Checkpoints | Coverage |
|---|---|---|
| **Minimisation in API responses** | SA-API-01 through SA-API-06 (API security), SA-FE-LLM-01/SA-FE-LLM-02 (frontend data handling) | **Partial** -- API security checks; no data minimisation validation |
| **Secure defaults** | SA-DJANGO-04 (DEBUG=True), SA-FLASK-03 (debug), SA-ANDROID-06 (debuggable), SA-EXPRESS-04 (helmet), SA-NEXT-04 (headers) | **Partial** -- detects insecure defaults |
| **Privacy-preserving logging** | SA-SPRING-06, SA-DJANGO-07, SA-RAILS-07, SA-EXPRESS-06 (logging config) | **Low** -- checks logging exists, not what is logged |
| **Input validation by default** | All injection prevention checkpoints (60+ checks) | **Good** -- prevents data corruption and injection |

### Article 25(2) -- Data Protection by Default

| Principle | Related Checkpoints | Coverage |
|---|---|---|
| **Default access restrictions** | SA-AWS-01 (deny wildcard), SA-AWS-05/SA-AWS-06 (S3 not public by default), SA-GCP-02 (no allUsers), SA-AZURE-03 (Blob not public) | **Good** -- cloud storage defaults |
| **Mobile data protection** | SA-ANDROID-03 (insecure storage), SA-ANDROID-04 (clipboard exposure), SA-ANDROID-09 (exported components), SA-IOS-03 (Keychain), SA-IOS-04 (pasteboard), SA-IOS-05 (data protection class) | **Good** -- mobile privacy checks |
| **Cookie security defaults** | SA-DJANGO-06, SA-FLASK-04, SA-RAILS-06, SA-EXPRESS-05, SA-SPRING-05 (Secure, HttpOnly, SameSite flags) | **Good** -- cross-framework cookie defaults |
| **CORS restrictive defaults** | SA-JS-10, SA-EXPRESS-03, SA-SPRING-03, SA-DJANGO-03, SA-FLASK-02, SA-FASTAPI-02, SA-GIN-02, SA-DOTNET-03, SA-NEST-03 | **Excellent** -- permissive CORS detection |

#### Gaps
- No data minimisation validation (which fields are returned in API responses)
- No purpose limitation checks (data used only for collected purpose)
- No consent mechanism validation
- No data retention enforcement
- No PII detection in logs or error messages
- No anonymisation/pseudonymisation technique verification

---

## Article 35 -- Data Protection Impact Assessment (DPIA)

Article 35 requires a DPIA when processing is likely to result in a high risk to the rights and freedoms of natural persons. The security-audit-skill supports DPIA by providing automated risk identification and scoring.

### DPIA Support Through Automated Risk Assessment

| DPIA Component | Related Resources | Coverage |
|---|---|---|
| **Systematic description of processing** | checkpoints.yaml (408 automated checks across all stacks) | **Partial** -- identifies security-relevant processing patterns |
| **Assessment of necessity and proportionality** | None | **None** -- legal/business assessment |
| **Risk assessment** | CVSS v4.0 scoring (cvss-scoring.md), CWE Top 25 mapping (cwe-top25.md), OWASP Top 10 mapping (owasp-top10.md) | **Good** -- standardised risk scoring |
| **Vulnerability inventory** | SA-DEP-01 through SA-DEP-03 (dependency CVEs), SA-SAST-01/SA-SAST-02 (code vulnerabilities), SA-16 through SA-20 (deep scanning) | **Good** -- automated vulnerability enumeration |
| **Measures to address risks** | All remediation guidance in reference files (60+ reference documents) | **Good** -- actionable remediation for each finding |
| **Monitoring and review** | SA-14/SA-15 (Dependabot continuous monitoring), SA-07 (CI pipeline), SA-SC-01/SA-SC-02 (supply chain) | **Partial** -- continuous scanning, not DPIA review cycle |

### Risk Scoring for DPIA

The security-audit-skill produces findings with standardised severity levels that map to DPIA risk assessment:

| Finding Severity | CVSS Score Range | DPIA Risk Level | Example Checkpoints |
|---|---|---|---|
| Error (Critical) | 9.0-10.0 | High | SA-25 (command injection), SA-SEC-01 (leaked AWS key) |
| Error | 7.0-8.9 | High | SA-10 (SQL injection), SA-21 (deserialization) |
| Warning (High) | 4.0-6.9 | Medium | SA-13 (XSS), SA-29 (weak randomness) |
| Warning | 0.1-3.9 | Low | SA-01 (SECURITY.md missing), SA-36 (deprecated header) |

#### Gaps
- No automated DPIA report generation
- No data flow mapping or data inventory
- No processing purpose classification
- No automated DPA (Data Protection Authority) notification support
- Risk scoring is technical only, does not assess rights/freedoms impact

---

## Coverage Summary

| GDPR Article | Coverage Level | Checkpoint Count | Key Gaps |
|---|---|---|---|
| Art. 32(1)(a) Encryption/Pseudonymisation | Good | ~35 | Pseudonymisation, field-level encryption |
| Art. 32(1)(b) Confidentiality | Excellent | ~120 | Complete injection/XSS/CSRF coverage |
| Art. 32(1)(b) Integrity | Excellent | ~80 | Comprehensive input validation |
| Art. 32(1)(b) Availability | Low | ~5 | Backup, HA, DDoS out of scope |
| Art. 32(1)(c) Restore Availability | None | 0 | DR/backup entirely out of scope |
| Art. 32(1)(d) Testing/Evaluation | Good | ~40 | No pentest workflow, good CI coverage |
| Art. 25(1) Design | Partial | ~30 | No data minimisation validation |
| Art. 25(2) Default | Good | ~25 | Cloud defaults, cookie security |
| Art. 35 DPIA | Partial | ~30 | Risk scoring only; no DPIA report |

**Overall GDPR Article 32 coverage: ~60% of technical security measures.**

The security-audit-skill excels at confidentiality and integrity controls (Art. 32(1)(b)) with comprehensive coverage of injection prevention, access control, and secrets management. The largest gaps are in availability/resilience (Art. 32(1)(c)) and data-protection-specific concerns like pseudonymisation, data minimisation, and purpose limitation.

### Privacy-Specific Gaps

The following GDPR-specific technical concerns are not covered:

1. **PII detection** -- No automated identification of personal data in code, logs, or API responses
2. **Consent management** -- No checks for consent collection, storage, or withdrawal mechanisms
3. **Data subject rights** -- No validation of right-to-erasure, portability, or access endpoints
4. **Data retention** -- No automated retention policy enforcement
5. **Cross-border transfers** -- No adequacy decision or SCCs validation
6. **Pseudonymisation** -- No technique validation (tokenisation, k-anonymity)

### Recommended Supplementary Controls

For comprehensive GDPR Article 32 compliance, supplement security-audit-skill with:

1. **PII scanning tools** (Amazon Macie, Google DLP API) for personal data detection
2. **Consent management platform** (OneTrust, Cookiebot) for Art. 7 compliance
3. **Data mapping tools** (BigID, Collibra) for Art. 30 records of processing
4. **Backup/DR solution** for Art. 32(1)(c)
5. **GRC platform** (Drata, Vanta, OneTrust) for DPIA management and ongoing compliance

---

## Changelog

| Date | Version | Changes |
|---|---|---|
| 2026-03-31 | 1.0.0 | Initial GDPR Article 32 compliance mapping for 408 checkpoints |
