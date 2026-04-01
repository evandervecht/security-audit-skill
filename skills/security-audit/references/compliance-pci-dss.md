# PCI DSS v4.0 Compliance Mapping

Maps PCI DSS v4.0 requirements to security-audit-skill checkpoints. Use this reference when auditing applications that process, store, or transmit cardholder data. Checkpoints prefixed with LIVE-* are runtime/dynamic checks; all others are static analysis checkpoints defined in checkpoints.yaml.

**Standard:** PCI DSS v4.0 (March 2022, mandatory March 31, 2025)
**Scope:** All 12 requirements mapped to 408 security checkpoints across 30+ technology stacks

---

## Requirement 1: Install and Maintain Network Security Controls

Network security controls (firewalls, security groups, NSGs) must restrict traffic between trusted and untrusted networks, and between systems within the cardholder data environment.

| PCI DSS Sub-Req | Description | Related Checkpoints | Coverage |
|---|---|---|---|
| 1.2.1 | Inbound/outbound traffic restrictions | SA-AWS-09 (open security groups 0.0.0.0/0), SA-AZURE-06 (open NSGs), SA-GCP-05 (open firewall rules) | **Partial** -- detects overly permissive CIDR blocks in IaC; does not validate actual firewall state |
| 1.2.5 | All services, protocols, and ports allowed are identified and approved | SA-AWS-09, SA-GCP-05, SA-AZURE-06 | **Partial** -- flags open-to-world rules; cannot verify business justification |
| 1.2.6 | Security features for insecure services/protocols | LIVE-TLS-01 (TLS version check), LIVE-TLS-02 (cipher suite validation) | **Partial** -- validates TLS configuration; does not cover non-HTTP protocols |
| 1.3.1 | Inbound traffic to CDE restricted | SA-AWS-09, SA-AZURE-06, SA-GCP-05, SA-IAC-01 through SA-IAC-10 | **Partial** -- IaC-level detection only |
| 1.3.2 | Outbound traffic from CDE restricted | SA-AWS-09, SA-AZURE-06 | **Low** -- egress rule analysis limited |
| 1.4.1 | NSCs between trusted and untrusted networks | SA-AWS-09, SA-AZURE-06, SA-GCP-05 | **Partial** -- detects misconfigured rules |
| 1.4.2 | Inbound traffic from untrusted to trusted restricted | SA-AWS-09, SA-AZURE-06, SA-GCP-05 | **Partial** |
| 1.5.1 | Security controls on computing devices connecting to untrusted networks | SA-IOS-02 (ATS bypass), SA-ANDROID-08 (cleartext traffic) | **Low** -- mobile-specific only |

### Gaps

- No runtime verification of actual firewall/NSG state (IaC drift detection)
- No protocol-level inspection beyond HTTP/TLS
- Egress filtering analysis is minimal
- No network segmentation validation

---

## Requirement 2: Apply Secure Configurations to All System Components

Default configurations must be changed, unnecessary services removed, and system components hardened before deployment.

| PCI DSS Sub-Req | Description | Related Checkpoints | Coverage |
|---|---|---|---|
| 2.2.1 | Configuration standards for all system components | SA-IAC-01 through SA-IAC-10 (IaC security), SA-AWS-01 through SA-AWS-12, SA-GCP-01 through SA-GCP-10, SA-AZURE-01 through SA-AZURE-10 | **Good** -- comprehensive IaC misconfiguration detection |
| 2.2.2 | Vendor default accounts managed | SA-AWS-08 (admin policy attachment), SA-AWS-12 (hardcoded passwords in IaC) | **Partial** -- detects hardcoded credentials in config |
| 2.2.4 | Only necessary services, protocols enabled | SA-DJANGO-04 (DEBUG=True in production), SA-ANDROID-06 (debuggable flag), SA-31 (phpinfo exposure), SA-FLASK-03 (debug mode) | **Partial** -- detects debug/dev modes left enabled |
| 2.2.5 | Insecure services secured if needed | LIVE-TLS-01, LIVE-TLS-02, SA-IOS-02 (ATS bypass) | **Partial** -- TLS-specific |
| 2.2.6 | System security parameters configured | SA-NEXT-04 (security headers), SA-EXPRESS-04 (helmet middleware), SA-DJANGO-05 (security middleware), SA-RAILS-05 (force_ssl) | **Good** -- framework security configuration checks |
| 2.2.7 | Non-console admin access encrypted | LIVE-TLS-01, LIVE-HDR-HSTS | **Partial** -- validates TLS and HSTS |

### Gaps

- No OS-level hardening checks (CIS benchmarks)
- No verification that default credentials are changed in databases/middleware
- No service enumeration on running systems

---

## Requirement 3: Protect Stored Account Data

Stored account data must be protected with encryption, truncation, masking, or hashing.

| PCI DSS Sub-Req | Description | Related Checkpoints | Coverage |
|---|---|---|---|
| 3.1.1 | Account data retention policies | None directly | **None** -- no data retention policy enforcement |
| 3.3.1 | PAN stored as unreadable (encryption, hashing, truncation) | SA-23, SA-24 (weak hashing), SA-PY-07 (weak crypto), SA-JAVA-07 (weak crypto), SA-CS-07 (weak crypto), SA-GO-07 (weak crypto) | **Partial** -- detects weak algorithms; cannot verify PAN-specific handling |
| 3.3.2 | PAN masked when displayed | None directly | **None** -- no PAN display masking checks |
| 3.4.1 | PAN secured with strong crypto if stored | SA-AWS-05, SA-AWS-06 (S3 public access), SA-AZURE-03 (Blob public access), SA-GCP-03 (GCS bucket access) | **Partial** -- validates storage access controls |
| 3.5.1 | Encryption keys managed securely | SA-AWS-10 (KMS key rotation disabled), SA-AWS-07 (secrets in Lambda env vars), SA-SEC-01 through SA-SEC-04 (leaked secrets) | **Good** -- key management and secret detection |
| 3.5.1.1 | Key-encrypting keys at least as strong | SA-AWS-10 (KMS rotation) | **Low** -- limited to rotation check |
| 3.5.1.2 | Key storage in fewest locations | SA-02, SA-03 (env files not committed), SA-AWS-07 (Lambda env secrets) | **Partial** -- detects secrets in code |
| 3.6.1 | Key-management procedures | SA-AWS-10 | **Low** -- rotation only |
| 3.7.1-3.7.9 | Cryptographic key management | SA-AWS-10, SA-SEC-01 through SA-SEC-04 | **Low** -- automated checks limited |

### Gaps

- No PAN-specific detection (regex for card numbers in code/logs)
- No data retention policy verification
- No display masking validation
- No key ceremony or split-knowledge verification
- No encryption-at-rest validation for databases beyond IaC checks

---

## Requirement 4: Protect Cardholder Data with Strong Cryptography During Transmission

Cardholder data must be encrypted with strong cryptography during transmission over open, public networks.

| PCI DSS Sub-Req | Description | Related Checkpoints | Coverage |
|---|---|---|---|
| 4.2.1 | Strong cryptography for PAN transmission | LIVE-TLS-01 (TLS 1.2+ enforcement), LIVE-TLS-02 (strong cipher suites), LIVE-TLS-03 (certificate validity) | **Good** -- comprehensive TLS validation |
| 4.2.1.1 | Trusted certificates used | LIVE-TLS-03 (cert validation), SA-IOS-02 (ATS bypass), SA-ANDROID-07 (custom TrustManager) | **Good** -- validates certificate handling |
| 4.2.1.2 | Wireless networks transmitting PAN use strong crypto | SA-IOS-02, SA-ANDROID-08 (cleartext traffic) | **Partial** -- mobile-specific |
| 4.2.2 | PAN secured if sent via end-user messaging | None | **None** -- no messaging channel checks |
| HSTS enforcement | HTTP Strict Transport Security | LIVE-HDR-HSTS, SA-NEXT-04 (Next.js headers), SA-EXPRESS-04 (helmet), SA-DJANGO-05 (SECURE_HSTS_SECONDS), SA-RAILS-05 (force_ssl) | **Good** -- framework and runtime checks |
| Cookie security | Secure flag on cookies | SA-33 (PHP cookie handling), SA-DJANGO-06 (SESSION_COOKIE_SECURE), SA-FLASK-04 (session cookie config), SA-RAILS-06 (cookie security) | **Good** -- cross-framework cookie checks |

### Gaps

- No detection of PAN in non-HTTPS API calls
- No end-user messaging technology checks
- No VPN/IPSec validation

---

## Requirement 5: Protect All Systems and Networks from Malicious Software

Anti-malware mechanisms must be deployed and maintained on all systems commonly affected by malicious software.

| PCI DSS Sub-Req | Description | Related Checkpoints | Coverage |
|---|---|---|---|
| 5.2.1 | Anti-malware deployed | SA-DEP-01, SA-DEP-02, SA-DEP-03 (dependency scanning), SA-SAST-01, SA-SAST-02 (SAST tools) | **Low** -- code-level scanning only, not endpoint AV |
| 5.2.2 | Anti-malware performs scans | SA-07 (composer audit in CI), SA-SAST-01 (semgrep in CI), SA-DEP-01 (trivy scanning) | **Partial** -- CI pipeline scanning |
| 5.3.1 | Anti-malware kept current | SA-14, SA-15 (Dependabot enabled) | **Low** -- dependency update automation only |
| 5.3.3 | Anti-malware for removable media | None | **None** -- not applicable to code review |

### Gaps

- This requirement primarily targets endpoint/system-level anti-malware, not application code
- No endpoint detection and response (EDR) integration
- Code scanning covers supply chain attacks but not traditional malware

---

## Requirement 6: Develop and Maintain Secure Systems and Software

Security vulnerabilities must be identified and addressed, and secure development practices followed for bespoke and custom software.

| PCI DSS Sub-Req | Description | Related Checkpoints | Coverage |
|---|---|---|---|
| 6.1.1 | Security policies for developing secure software | SA-01 (SECURITY.md exists) | **Low** -- file existence only |
| 6.2.1 | Bespoke software developed securely | All SA-JS-*, SA-PY-*, SA-JAVA-*, SA-CS-*, SA-GO-*, SA-RS-*, SA-RB-* language checkpoints (90+ checks) | **Excellent** -- comprehensive code-level security analysis |
| 6.2.2 | Software development personnel trained | SA-AI-01 through SA-AI-04 (AI/LLM security awareness), SA-LLM-21 through SA-LLM-38 (LLM-assisted review) | **Partial** -- verifies security review quality, not training records |
| 6.2.3 | Bespoke software reviewed before release | SA-LLM-21 through SA-LLM-38 (LLM code review), SA-SAST-01, SA-SAST-02 (automated SAST), SA-16 through SA-20 (deep scanning) | **Good** -- automated review with LLM-augmented analysis |
| 6.2.4 | Software engineering techniques prevent attacks | SA-10 through SA-13 (injection prevention), SA-21/SA-22 (deserialization), SA-25 through SA-28 (command injection), SA-37 through SA-39 (code injection), all framework-specific injection checks | **Excellent** -- OWASP Top 10 coverage across all frameworks |
| 6.3.1 | Security vulnerabilities identified and managed | SA-DEP-01 through SA-DEP-03 (dependency CVE scanning), SA-14/SA-15 (Dependabot), SA-SC-01/SA-SC-02 (supply chain) | **Good** -- automated vulnerability identification |
| 6.3.2 | Software inventory maintained | SA-DEP-01 (dependency enumeration via trivy) | **Partial** -- dependency-level only |
| 6.3.3 | Patches/updates installed timely | SA-14/SA-15 (Dependabot), SA-DEP-02 (vulnerability severity filtering) | **Partial** -- automation enabled, not enforcement |
| 6.4.1 | Public-facing web apps protected from attacks | SA-FE-01 through SA-FE-06 (frontend security), SA-REACT-*, SA-VUE-*, SA-ANG-*, SA-NEXT-*, SA-NUXT-* (framework XSS prevention) | **Good** -- broad frontend protection checks |
| 6.4.2 | Public-facing web apps use automated technical solution | LIVE-HDR-CSP (Content Security Policy), SA-FE-03 (CSP configuration), SA-EXPRESS-04 (helmet) | **Partial** -- CSP/WAF configuration checks |
| 6.4.3 | Payment page scripts managed and authorized | SA-FE-01 (inline script detection), SA-FE-03 (CSP), SA-NEXT-01 (script handling) | **Partial** -- script integrity checks |
| 6.5.1 | Change management procedures | SA-07 (CI security in workflows), SA-SAST-01 (CI SAST integration), SA-IAC-01 through SA-IAC-10 (IaC review) | **Partial** -- CI pipeline security gates |
| 6.5.2 | Dev/test environments separated from production | SA-DJANGO-04 (DEBUG=True detection), SA-FLASK-03 (debug mode), SA-ANDROID-06 (debuggable) | **Low** -- detects debug flags, not environment separation |
| 6.5.3 | Pre-production and production environments separated | SA-DJANGO-04, SA-FLASK-03 | **Low** |
| 6.5.4 | Roles and functions separated | SA-AWS-01 (wildcard IAM), SA-AWS-04 (PassRole), SA-AWS-08 (admin policy) | **Partial** -- IAM separation of duties |
| 6.5.5 | Live PANs not used in testing | None | **None** -- no test data validation |
| 6.5.6 | Test data/accounts removed before production | SA-31 (phpinfo), SA-DJANGO-04 (DEBUG) | **Low** |

### Gaps

- No payment page script inventory or SRI (Subresource Integrity) enforcement
- No test data detection in production environments
- No formal SDLC process validation (only CI gate checks)

---

## Requirement 7: Restrict Access to System Components and Cardholder Data by Business Need to Know

Access must be limited to only the minimum necessary to perform job responsibilities.

| PCI DSS Sub-Req | Description | Related Checkpoints | Coverage |
|---|---|---|---|
| 7.2.1 | Access control model defined | SA-AWS-01 (wildcard actions), SA-AWS-04 (PassRole scope), SA-GCP-01 (primitive roles), SA-AZURE-01 (contributor role scope) | **Partial** -- detects over-permissive IAM |
| 7.2.2 | Access assigned based on job classification | SA-AWS-01, SA-AWS-08 (admin policy), SA-GCP-01, SA-AZURE-01 | **Partial** -- flags broad permissions |
| 7.2.3 | Required privileges approved by authorized personnel | None | **None** -- no approval workflow integration |
| 7.2.4 | User accounts reviewed periodically | None | **None** -- no periodic review checks |
| 7.2.5 | Application/system accounts managed | SA-AWS-02 (AssumeRole conditions), SA-AWS-03 (wildcard principals) | **Low** -- detects misconfigured service accounts |
| 7.2.5.1 | Application/system account access reviewed | None | **None** |
| 7.2.6 | Access rights follow least privilege | SA-AWS-01, SA-AWS-04, SA-GCP-01, SA-AZURE-01, SA-40 (IDOR detection) | **Partial** -- code and IaC level checks |

### Gaps

- No RBAC/ABAC model validation
- No user access review automation
- No privilege escalation path analysis
- No approval workflow integration

---

## Requirement 8: Identify Users and Authenticate Access to System Components

Every user must be assigned a unique identification and strong authentication must be enforced.

| PCI DSS Sub-Req | Description | Related Checkpoints | Coverage |
|---|---|---|---|
| 8.2.1 | All users assigned unique ID | SA-AWS-03 (wildcard principals), SA-GCP-02 (allUsers/allAuthenticatedUsers) | **Low** -- cloud-level only |
| 8.2.2 | Group/shared accounts managed | SA-AWS-03, SA-AWS-08 | **Low** |
| 8.3.1 | All user access authenticated | SA-40 (IDOR), SA-SPRING-01 (auth config), SA-DOTNET-01 (auth middleware), SA-DJANGO-01 (auth views), SA-RAILS-01 (auth checks), SA-EXPRESS-01 (auth middleware), SA-NEST-01 (guards) | **Good** -- cross-framework auth detection |
| 8.3.2 | Strong crypto for authentication | SA-23, SA-24 (password hashing), SA-PY-07, SA-JAVA-07, SA-CS-07, SA-GO-07, SA-RS-07 (weak crypto per language) | **Good** -- detects weak password hashing across languages |
| 8.3.4 | Invalid auth attempts limited | SA-SPRING-02 (brute force), SA-EXPRESS-05 (rate limiting), SA-NEST-05 (throttling) | **Partial** -- framework-specific |
| 8.3.6 | Password complexity enforced | SA-SPRING-02, SA-DOTNET-02 (password validation) | **Low** -- limited framework coverage |
| 8.3.9 | Passwords/passphrases for single-factor changed periodically | None | **None** -- no rotation enforcement |
| 8.4.2 | MFA for all access to CDE | SA-AWS-02 (MFA condition on AssumeRole) | **Low** -- AWS-specific MFA condition check |
| 8.5.1 | MFA systems properly configured | None | **None** -- no MFA configuration audit |
| 8.6.1 | Interactive login to system accounts managed | SA-AWS-07 (secrets in env), SA-SEC-01 through SA-SEC-04 (leaked credentials) | **Partial** -- credential exposure |

### Gaps

- No MFA enforcement validation across identity providers
- No password policy strength verification (beyond hashing algorithm)
- No session timeout enforcement checks
- No account lockout configuration validation

---

## Requirement 9: Restrict Physical Access to Cardholder Data

**Coverage: None.** This requirement addresses physical security controls (facility access, media handling, POS devices). The security-audit-skill operates entirely at the code and infrastructure-as-code level and does not address physical security.

---

## Requirement 10: Log and Monitor All Access to System Components and Cardholder Data

Logging mechanisms must track user activities and system events, and logs must be reviewed to identify anomalies.

| PCI DSS Sub-Req | Description | Related Checkpoints | Coverage |
|---|---|---|---|
| 10.2.1 | Audit logs enabled and active | SA-AWS-11 (CloudTrail multi-region/validation), SA-GCP-07 (audit logging), SA-AZURE-07 (diagnostic logging) | **Good** -- cloud audit log configuration |
| 10.2.1.1 | Audit logs capture all individual user access | SA-SPRING-06 (logging config), SA-DJANGO-07 (logging), SA-RAILS-07 (logging), SA-EXPRESS-06 (logging middleware) | **Partial** -- framework logging checks |
| 10.2.1.2 | Actions by individuals with admin access logged | SA-AWS-11 (CloudTrail), SA-GCP-07, SA-AZURE-07 | **Partial** -- cloud-level only |
| 10.2.1.3 | Access to audit logs captured | SA-AWS-11 | **Low** -- trail validation only |
| 10.2.1.5 | Changes to identification/auth mechanisms logged | None directly | **None** |
| 10.2.2 | Audit logs record required details | SA-AWS-11 (log file validation), SA-GCP-07, SA-AZURE-07 | **Partial** -- configuration checks |
| 10.3.1 | Audit log read access limited | SA-AWS-05/SA-AWS-06 (S3 log bucket access) | **Low** |
| 10.3.2 | Audit logs protected from modification | SA-AWS-11 (enable_log_file_validation) | **Partial** -- CloudTrail specific |
| 10.3.3 | Audit logs backed up promptly | None | **None** |
| 10.3.4 | File integrity monitoring on audit logs | SA-AWS-11 (log file validation) | **Low** |
| 10.4.1 | Audit logs reviewed at least daily | None | **None** -- no review process validation |
| 10.5.1 | Audit log history retained | None | **None** -- no retention policy checks |
| 10.6.1 | Time synchronization technology in use | None | **None** |
| 10.7.1 | Critical security control failures detected and responded to | None | **None** |

### Gaps

- No log completeness validation
- No log retention policy enforcement
- No time synchronization verification
- No SIEM integration checks
- No log review process validation
- Limited to IaC configuration; no runtime log analysis

---

## Requirement 11: Test Security of Systems and Networks Regularly

System components, processes, and custom software must be tested frequently to ensure security controls continue to function properly.

| PCI DSS Sub-Req | Description | Related Checkpoints | Coverage |
|---|---|---|---|
| 11.3.1 | Internal vulnerability scans quarterly | SA-SAST-01, SA-SAST-02 (SAST tools), SA-DEP-01 through SA-DEP-03 (dependency scanning), SA-16 through SA-20 (deep scanning) | **Good** -- comprehensive automated scanning |
| 11.3.1.1 | All other applicable vulnerabilities managed | SA-DEP-01 through SA-DEP-03, SA-SC-01/SA-SC-02 (supply chain) | **Partial** |
| 11.3.2 | External vulnerability scans quarterly (ASV) | LIVE-TLS-01 through LIVE-TLS-03, LIVE-HDR-* (runtime header checks) | **Partial** -- runtime checks complement ASV |
| 11.3.3 | Internal and external scans after significant changes | SA-07 (CI audit), SA-SAST-01 (CI SAST) | **Good** -- CI integration ensures per-change scanning |
| 11.4.1 | Penetration testing performed | SA-16 through SA-20 (deep scanning), SA-LLM-21 through SA-LLM-38 (LLM-assisted review) | **Partial** -- automated analysis, not manual pentest |
| 11.5.1 | Intrusion detection/prevention | None | **None** -- IDS/IPS not in scope |
| 11.5.2 | Change-detection mechanism deployed | SA-SC-01/SA-SC-02 (supply chain integrity) | **Low** -- dependency-level only |
| 11.6.1 | Payment page change-detection mechanisms | SA-FE-01 (inline scripts), SA-FE-03 (CSP) | **Low** |

### Gaps

- No ASV scan coordination or validation
- No IDS/IPS configuration checks
- No manual penetration testing workflow integration
- No file integrity monitoring beyond supply chain

---

## Requirement 12: Support Information Security with Organizational Policies and Programs

**Coverage: Low.** This requirement addresses organizational policies, risk assessments, security awareness training, and incident response plans. The security-audit-skill provides:

| PCI DSS Sub-Req | Description | Related Checkpoints | Coverage |
|---|---|---|---|
| 12.3.1 | Risk assessment performed annually | CVSS scoring (cvss-scoring.md reference) | **Low** -- risk scoring methodology available |
| 12.6.1 | Security awareness program | SA-AI-01 through SA-AI-04 | **Low** -- AI security awareness only |
| 12.10.1 | Incident response plan exists | SA-01 (SECURITY.md) | **Low** -- file presence only |

---

## Coverage Summary

| PCI DSS Requirement | Coverage Level | Checkpoint Count | Key Gaps |
|---|---|---|---|
| Req 1: Network Security Controls | Partial | ~8 | No runtime firewall state, no egress analysis |
| Req 2: Secure Configurations | Good | ~35 | No OS hardening, no default credential checks |
| Req 3: Protect Stored Data | Partial | ~15 | No PAN detection, no retention policy |
| Req 4: Data in Transit | Good | ~12 | No non-HTTP protocol checks |
| Req 5: Anti-Malware | Low | ~8 | Endpoint AV out of scope |
| Req 6: Secure Development | Excellent | ~200+ | Best coverage area; minor gaps in payment page scripts |
| Req 7: Restrict Access | Partial | ~10 | No RBAC validation, no approval workflows |
| Req 8: Authentication | Good | ~25 | No MFA validation, no password policy audit |
| Req 9: Physical Access | None | 0 | Entirely out of scope |
| Req 10: Logging | Partial | ~12 | No runtime log analysis, no retention checks |
| Req 11: Testing | Good | ~20 | No ASV/IDS integration |
| Req 12: Policies | Low | ~3 | Organizational controls out of scope |

**Overall PCI DSS v4.0 coverage: ~65% of automatable technical controls.**

Requirements 6 (Secure Development) and 4 (Data in Transit) have the strongest coverage. Requirements 9 (Physical), 12 (Policies), and portions of 7-8 (Access Management) represent the largest gaps, which is expected for a code-level security analysis tool.

### Recommended Supplementary Controls

For full PCI DSS v4.0 compliance, supplement security-audit-skill with:

1. **Network scanning tools** (Nessus, Qualys) for Requirements 1, 11
2. **Identity governance** (Okta, Azure AD reviews) for Requirements 7, 8
3. **SIEM platform** (Splunk, Sentinel) for Requirement 10
4. **Physical security assessments** for Requirement 9
5. **GRC platform** (Drata, Vanta) for Requirement 12

---

## Changelog

| Date | Version | Changes |
|---|---|---|
| 2026-03-31 | 1.0.0 | Initial PCI DSS v4.0 compliance mapping for 408 checkpoints |
