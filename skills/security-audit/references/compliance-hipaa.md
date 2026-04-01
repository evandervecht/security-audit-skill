# HIPAA Security Rule Compliance Mapping

Maps HIPAA Security Rule (45 CFR Part 164, Subpart C) requirements to security-audit-skill checkpoints. Use this reference when auditing applications that create, receive, maintain, or transmit electronic protected health information (ePHI). Checkpoints prefixed with LIVE-* are runtime/dynamic checks; all others are static analysis checkpoints defined in checkpoints.yaml.

**Regulation:** HIPAA Security Rule (45 CFR 164.302-164.318)
**Scope:** Technical safeguards, administrative safeguards (security-relevant), and organizational requirements mapped to 408 security checkpoints

---

## Technical Safeguards (Section 164.312)

### 164.312(a)(1) -- Access Control (Required)

Implement technical policies and procedures for electronic information systems that maintain ePHI to allow access only to authorized persons or software programs.

| HIPAA Spec | Type | Description | Related Checkpoints | Coverage |
|---|---|---|---|---|
| 164.312(a)(2)(i) | Required | Unique User Identification | SA-AWS-03 (wildcard principals), SA-GCP-02 (allUsers/allAuthenticatedUsers), SA-AZURE-02 (role scope) | **Partial** -- cloud IAM checks |
| 164.312(a)(2)(ii) | Required | Emergency Access Procedure | None | **None** -- procedural control |
| 164.312(a)(2)(iii) | Addressable | Automatic Logoff | SA-DJANGO-06 (session config), SA-FLASK-04 (session timeout), SA-RAILS-06 (session management), SA-EXPRESS-05 (session config) | **Partial** -- framework session configuration |
| 164.312(a)(2)(iv) | Addressable | Encryption and Decryption | SA-AWS-05/SA-AWS-06 (S3 encryption), SA-AZURE-03 (Blob access), SA-GCP-03 (GCS access), SA-23/SA-24 (weak hashing), SA-PY-07 (weak crypto), SA-JAVA-07, SA-CS-07, SA-GO-07, SA-RS-07, SA-RB-07 (language-specific weak crypto) | **Good** -- encryption configuration and weak crypto detection |

**Framework-Specific Authentication Checkpoints:**

| Framework | Checkpoint | What It Checks |
|---|---|---|
| Spring | SA-SPRING-01 | Security filter chain configuration |
| ASP.NET | SA-DOTNET-01 | Authentication middleware |
| Django | SA-DJANGO-01 | Authentication views and backends |
| Rails | SA-RAILS-01 | Authentication implementation |
| Express | SA-EXPRESS-01 | Auth middleware presence |
| NestJS | SA-NEST-01 | Guard-based authentication |
| Flask | SA-FLASK-01 | Login management |
| FastAPI | SA-FASTAPI-01 | OAuth2/JWT dependency injection |
| Gin | SA-GIN-01 | Auth middleware |
| Blazor | SA-BLAZOR-01 | Authentication state provider |

**IAM/Authorization Checkpoints:**

| Provider | Checkpoints | What They Check |
|---|---|---|
| AWS | SA-AWS-01, SA-AWS-02, SA-AWS-03, SA-AWS-04, SA-AWS-08 | Wildcard actions, AssumeRole conditions, wildcard principals, PassRole scope, admin policy attachment |
| GCP | SA-GCP-01, SA-GCP-02 | Primitive roles, public access (allUsers) |
| Azure | SA-AZURE-01, SA-AZURE-02 | Contributor scope, role assignments |

#### Gaps
- No break-glass/emergency access procedure validation
- No session timeout enforcement verification at runtime
- No user provisioning/deprovisioning workflow checks

---

### 164.312(b) -- Audit Controls (Required)

Implement hardware, software, and/or procedural mechanisms that record and examine activity in systems that contain or use ePHI.

| HIPAA Spec | Type | Description | Related Checkpoints | Coverage |
|---|---|---|---|---|
| 164.312(b) | Required | Audit controls implemented | SA-AWS-11 (CloudTrail config), SA-GCP-07 (audit logging), SA-AZURE-07 (diagnostic logging) | **Good** -- cloud audit log configuration |

**Cloud Audit Logging Checkpoints:**

| Provider | Checkpoint | What It Checks |
|---|---|---|
| AWS | SA-AWS-11 | CloudTrail multi-region trails, log file validation enabled |
| GCP | SA-GCP-07 | Audit log sink configuration |
| Azure | SA-AZURE-07 | Diagnostic settings enabled |

**Application Logging Checkpoints:**

| Framework | Checkpoint | What It Checks |
|---|---|---|
| Spring | SA-SPRING-06 | Logging configuration (logback/log4j) |
| Django | SA-DJANGO-07 | Django logging framework setup |
| Rails | SA-RAILS-07 | Rails logger configuration |
| Express | SA-EXPRESS-06 | Logging middleware (morgan/winston) |
| NestJS | SA-NEST-06 | Logger module configuration |
| Flask | SA-FLASK-06 | Flask logging setup |
| FastAPI | SA-FASTAPI-06 | Logging configuration |
| Gin | SA-GIN-06 | Gin logger middleware |

#### Gaps
- No ePHI access logging verification (who accessed what patient data)
- No log retention period enforcement
- No log integrity protection beyond CloudTrail validation
- No centralized logging/SIEM configuration checks
- No audit log review process validation

---

### 164.312(c)(1) -- Integrity (Required)

Implement policies and procedures to protect ePHI from improper alteration or destruction.

| HIPAA Spec | Type | Description | Related Checkpoints | Coverage |
|---|---|---|---|---|
| 164.312(c)(1) | Required | ePHI integrity | Input validation checkpoints (below), deserialization prevention (SA-21, SA-22), supply chain integrity (SA-SC-01, SA-SC-02) | **Good** -- comprehensive input validation |
| 164.312(c)(2) | Addressable | Mechanism to authenticate ePHI | SA-AWS-11 (log file validation), SA-SC-01/SA-SC-02 (dependency integrity) | **Partial** -- limited to log and dependency integrity |

**Input Validation / Injection Prevention (Data Integrity):**

| Attack Vector | Checkpoints | Languages/Frameworks |
|---|---|---|
| SQL Injection | SA-10, SA-11, SA-12 (PHP superglobals), SA-JS-01, SA-PY-01, SA-JAVA-01, SA-CS-01, SA-GO-01, SA-RS-01, SA-RB-01 | All supported languages |
| XSS | SA-13 (PHP echo), SA-JS-03, SA-REACT-01, SA-VUE-01, SA-ANG-01, SA-NEXT-01 | PHP, JS, all frontend frameworks |
| Command Injection | SA-25 through SA-28 (PHP), SA-JS-05, SA-PY-05, SA-JAVA-05, SA-RB-05, SA-NODE-05 | All backend languages |
| Deserialization | SA-21, SA-22 (PHP), SA-PY-06, SA-JAVA-06, SA-CS-06, SA-RB-06, SA-NODE-06 | All backend languages |
| XXE | SA-08, SA-08b, SA-09 (PHP), SA-JAVA-08, SA-CS-08, SA-PY-08 | PHP, Java, C#, Python |
| Path Traversal | SA-JS-04, SA-PY-04, SA-JAVA-04, SA-NODE-04, SA-GO-04, SA-RB-04 | All backend languages |
| SSRF | SA-JS-09, SA-PY-09, SA-JAVA-09, SA-NODE-09, SA-GO-09 | All backend languages |
| Code Injection | SA-37, SA-38, SA-39 (PHP eval/assert/preg_replace) | PHP-specific |

#### Gaps
- No database integrity constraint validation
- No data-at-rest integrity verification (checksums, HMAC)
- No ePHI modification tracking

---

### 164.312(d) -- Person or Entity Authentication (Required)

Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed.

| HIPAA Spec | Type | Description | Related Checkpoints | Coverage |
|---|---|---|---|---|
| 164.312(d) | Required | Person/entity authentication | All auth checkpoints (SA-SPRING-01, SA-DOTNET-01, SA-DJANGO-01, etc.), SA-23/SA-24 (password hashing), SA-AWS-02 (MFA conditions) | **Good** -- authentication implementation checks |

**Authentication Strength Checkpoints:**

| Category | Checkpoints | What They Check |
|---|---|---|
| Weak Password Hashing | SA-23 (md5), SA-24 (sha1), SA-PY-07, SA-JAVA-07, SA-CS-07, SA-GO-07, SA-RS-07, SA-RB-07 | Insecure hash algorithms for passwords |
| Insecure Randomness | SA-29, SA-30 (PHP rand/mt_rand), SA-JS-07, SA-PY-10 | Weak token/session generation |
| Hardcoded Credentials | SA-04, SA-05, SA-06 (PHP), SA-AWS-07 (Lambda), SA-AWS-12 (IaC), SA-SEC-01 through SA-SEC-04 | Secrets in source code |
| MFA Conditions | SA-AWS-02 (AssumeRole without MFA condition) | Cloud IAM MFA enforcement |

#### Gaps
- No MFA implementation validation across identity providers
- No biometric authentication checks
- No certificate-based authentication validation
- No multi-factor authentication strength assessment

---

### 164.312(e)(1) -- Transmission Security (Required)

Implement technical security measures to guard against unauthorized access to ePHI being transmitted over an electronic communications network.

| HIPAA Spec | Type | Description | Related Checkpoints | Coverage |
|---|---|---|---|---|
| 164.312(e)(2)(i) | Addressable | Integrity controls for transmission | LIVE-TLS-01 (TLS version), LIVE-TLS-02 (cipher suites), SA-SC-01/SA-SC-02 (dependency integrity) | **Good** -- TLS and integrity checks |
| 164.312(e)(2)(ii) | Addressable | Encryption for transmission | LIVE-TLS-01, LIVE-TLS-02, LIVE-TLS-03 (cert validity), LIVE-HDR-HSTS, SA-IOS-02 (ATS bypass), SA-ANDROID-08 (cleartext traffic) | **Good** -- comprehensive TLS validation |

**Security Header Checkpoints (Transmission Protection):**

| Header | Checkpoint | Purpose |
|---|---|---|
| HSTS | LIVE-HDR-HSTS | Force HTTPS connections |
| CSP | LIVE-HDR-CSP, SA-FE-03 | Prevent unauthorized script execution |
| X-Content-Type-Options | LIVE-HDR-XCTO | Prevent MIME sniffing |
| X-Frame-Options | LIVE-HDR-XFO | Prevent clickjacking |
| Referrer-Policy | LIVE-HDR-RP | Control referrer information leakage |

**Framework TLS/Security Configuration:**

| Framework | Checkpoint | What It Checks |
|---|---|---|
| Django | SA-DJANGO-05 | SECURE_SSL_REDIRECT, SECURE_HSTS_SECONDS |
| Rails | SA-RAILS-05 | force_ssl configuration |
| Express | SA-EXPRESS-04 | Helmet middleware (security headers) |
| Next.js | SA-NEXT-04 | Security headers in next.config.js |
| Nuxt | SA-NUXT-04 | Security headers configuration |
| Spring | SA-SPRING-04 | HTTPS redirect, HSTS configuration |
| ASP.NET | SA-DOTNET-04 | HTTPS redirection middleware |
| iOS | SA-IOS-02 | App Transport Security (ATS) bypass detection |
| Android | SA-ANDROID-08 | android:usesCleartextTraffic detection |

**Cookie Security (Session Transmission):**

| Framework | Checkpoint | What It Checks |
|---|---|---|
| PHP | SA-33 | Direct $_COOKIE access |
| Django | SA-DJANGO-06 | SESSION_COOKIE_SECURE, SESSION_COOKIE_HTTPONLY |
| Flask | SA-FLASK-04 | Session cookie configuration |
| Rails | SA-RAILS-06 | Cookie security settings |
| Express | SA-EXPRESS-05 | Cookie middleware configuration |
| Spring | SA-SPRING-05 | Cookie security attributes |

#### Gaps
- No VPN/IPSec configuration checks
- No email encryption (S/MIME, PGP) validation
- No HL7/FHIR transport security checks (healthcare-specific)
- No API gateway TLS termination validation

---

## Administrative Safeguards (Section 164.308) -- Security-Relevant Technical Controls

### 164.308(a)(1) -- Security Management Process (Required)

Implement policies and procedures to prevent, detect, contain, and correct security violations.

| HIPAA Spec | Type | Description | Related Checkpoints | Coverage |
|---|---|---|---|---|
| 164.308(a)(1)(ii)(A) | Required | Risk Analysis | All 408 checkpoints collectively; CVSS scoring (cvss-scoring.md); CWE Top 25 (cwe-top25.md); OWASP Top 10 (owasp-top10.md) | **Good** -- automated risk identification |
| 164.308(a)(1)(ii)(B) | Required | Risk Management | SA-DEP-01 through SA-DEP-03 (vulnerability management), SA-14/SA-15 (Dependabot), SA-SC-01/SA-SC-02 (supply chain) | **Partial** -- identification only, not remediation tracking |
| 164.308(a)(1)(ii)(C) | Required | Sanction Policy | None | **None** -- organizational control |
| 164.308(a)(1)(ii)(D) | Required | Information System Activity Review | SA-AWS-11, SA-GCP-07, SA-AZURE-07 (audit logs) | **Partial** -- log configuration, not review process |

**Vulnerability Scanning Checkpoints:**

| Category | Checkpoints | What They Check |
|---|---|---|
| Dependency CVEs | SA-DEP-01 (trivy), SA-DEP-02 (severity filter), SA-DEP-03 (SBOM) | Known vulnerabilities in dependencies |
| SAST | SA-SAST-01 (semgrep), SA-SAST-02 (custom rules) | Static code analysis |
| Secret Scanning | SA-SEC-01 through SA-SEC-04 (key patterns), SA-02/SA-03 (env files) | Leaked credentials |
| Supply Chain | SA-SC-01, SA-SC-02 | Dependency integrity and provenance |
| Deep Scanning | SA-16 through SA-20 | Multi-pass analysis with LLM augmentation |
| CI Integration | SA-07 (composer audit), SA-SAST-01 (semgrep in CI) | Per-commit scanning |

### 164.308(a)(3) -- Workforce Security (Required)

| HIPAA Spec | Type | Description | Related Checkpoints | Coverage |
|---|---|---|---|---|
| 164.308(a)(3)(ii)(A) | Addressable | Authorization/Supervision | SA-AWS-01 through SA-AWS-04 (IAM), SA-GCP-01/SA-GCP-02, SA-AZURE-01/SA-AZURE-02 | **Partial** -- cloud permission checks |
| 164.308(a)(3)(ii)(B) | Addressable | Workforce Clearance | None | **None** -- HR process |
| 164.308(a)(3)(ii)(C) | Addressable | Termination Procedures | None | **None** -- HR process |

### 164.308(a)(4) -- Information Access Management (Required)

| HIPAA Spec | Type | Description | Related Checkpoints | Coverage |
|---|---|---|---|---|
| 164.308(a)(4)(ii)(A) | Addressable | Isolating Healthcare Clearinghouse Functions | None | **None** -- network segmentation |
| 164.308(a)(4)(ii)(B) | Required | Access Authorization | SA-AWS-01 (least privilege), SA-GCP-01, SA-AZURE-01, SA-40 (IDOR) | **Partial** |
| 164.308(a)(4)(ii)(C) | Addressable | Access Establishment and Modification | None | **None** -- process control |

### 164.308(a)(5) -- Security Awareness and Training (Required)

| HIPAA Spec | Type | Description | Related Checkpoints | Coverage |
|---|---|---|---|---|
| 164.308(a)(5)(ii)(A) | Addressable | Security Reminders | SA-AI-01 through SA-AI-04 (AI security), SA-LLM-21 through SA-LLM-38 (code review guidance) | **Partial** -- in-context security guidance |
| 164.308(a)(5)(ii)(B) | Addressable | Protection from Malicious Software | SA-DEP-01 through SA-DEP-03 (dependency scanning), SA-SAST-01/SA-SAST-02 | **Partial** -- code-level only |
| 164.308(a)(5)(ii)(C) | Addressable | Log-in Monitoring | SA-SPRING-02 (brute force), SA-EXPRESS-05 (rate limiting) | **Low** |
| 164.308(a)(5)(ii)(D) | Addressable | Password Management | SA-23/SA-24 (hashing), SA-SPRING-02, SA-DOTNET-02 | **Low** |

### 164.308(a)(6) -- Security Incident Procedures (Required)

| HIPAA Spec | Type | Description | Related Checkpoints | Coverage |
|---|---|---|---|---|
| 164.308(a)(6)(ii) | Required | Response and Reporting | SA-01 (SECURITY.md), supply-chain-incident-response.md reference | **Low** -- file presence and reference material only |

### 164.308(a)(7) -- Contingency Plan (Required)

| HIPAA Spec | Type | Description | Related Checkpoints | Coverage |
|---|---|---|---|---|
| 164.308(a)(7)(ii)(A-E) | Mixed | Data backup, disaster recovery, emergency mode | None directly | **None** -- infrastructure operations control |

---

## Coverage Summary

| HIPAA Section | Coverage Level | Checkpoint Count | Key Gaps |
|---|---|---|---|
| 164.312(a) Access Control | Good | ~40 | Emergency access, session timeout runtime verification |
| 164.312(b) Audit Controls | Good | ~15 | Log retention, SIEM, ePHI access tracking |
| 164.312(c) Integrity | Good | ~60 | Database constraints, data-at-rest integrity |
| 164.312(d) Authentication | Good | ~30 | MFA validation, biometrics |
| 164.312(e) Transmission | Good | ~25 | VPN, HL7/FHIR transport, email encryption |
| 164.308(a)(1) Security Mgmt | Good | ~30 | Remediation tracking, sanction policy |
| 164.308(a)(3) Workforce | Low | ~8 | HR processes out of scope |
| 164.308(a)(4) Access Mgmt | Partial | ~8 | Access provisioning workflows |
| 164.308(a)(5) Awareness | Partial | ~25 | Training records, formal programs |
| 164.308(a)(6) Incidents | Low | ~2 | Incident response plan depth |
| 164.308(a)(7) Contingency | None | 0 | Backup/DR out of scope |

**Overall HIPAA Security Rule coverage: ~55% of technical safeguards, ~25% of administrative safeguards.**

The security-audit-skill provides strong coverage of the Technical Safeguards (164.312), particularly for access control, integrity, and transmission security. Administrative safeguards that require organizational processes (workforce security, contingency planning, incident response) are largely out of scope.

### Healthcare-Specific Gaps

The following healthcare-specific security concerns are not covered by current checkpoints:

1. **HL7/FHIR API security** -- No checks for healthcare interoperability protocol security
2. **PHI in logs** -- No detection of patient identifiers in application logs
3. **De-identification validation** -- No HIPAA Safe Harbor or Expert Determination method checks
4. **Business Associate Agreement (BAA) enforcement** -- No cloud provider BAA status verification
5. **Minimum Necessary Standard** -- No data minimization validation in API responses

### Recommended Supplementary Controls

For full HIPAA Security Rule compliance, supplement security-audit-skill with:

1. **Identity governance platform** (Okta, Azure AD) for 164.312(a) and 164.308(a)(3-4)
2. **SIEM/log management** (Splunk, Datadog) for 164.312(b)
3. **Backup and DR solution** for 164.308(a)(7)
4. **GRC platform** (Drata, Vanta) for administrative safeguards
5. **Healthcare-specific security tools** (Protenus, ClearDATA) for ePHI monitoring

---

## Changelog

| Date | Version | Changes |
|---|---|---|
| 2026-03-31 | 1.0.0 | Initial HIPAA Security Rule compliance mapping for 408 checkpoints |
