# EU AI Act Compliance Mapping (Cybersecurity & Technical Requirements)

Maps the EU AI Act (Regulation (EU) 2024/1689) Articles 9, 13, 14, and 15 to security-audit-skill checkpoints. Use this reference when auditing AI systems — particularly high-risk AI systems (Annex III) and general-purpose AI (GPAI) models — for technical compliance. Checkpoints prefixed with LIVE-* are runtime/dynamic checks; all others are static analysis checkpoints defined in checkpoints.yaml.

**Regulation:** Regulation (EU) 2024/1689 (EU AI Act)
**Effective:** 1 August 2024; phased enforcement through 2 August 2027
**Focus:** Article 9 (Risk Management), Article 13 (Transparency), Article 14 (Human Oversight), Article 15 (Accuracy, Robustness, and Cybersecurity)
**Scope:** Technical measures mapped to 408 security checkpoints across 30+ technology stacks, with emphasis on AI/LLM agent security checkpoints

---

## Article 15 -- Accuracy, Robustness, and Cybersecurity

Article 15 requires that high-risk AI systems achieve an appropriate level of accuracy, robustness, and cybersecurity. This is the most technically relevant article for code-level security auditing.

### Article 15(1) -- Appropriate Levels of Accuracy, Robustness, and Cybersecurity

High-risk AI systems shall be designed and developed in such a way that they achieve an appropriate level of accuracy, robustness, and cybersecurity, and that they perform consistently in those respects throughout their lifecycle.

| Category | Related Checkpoints | Coverage |
|---|---|---|
| **Accuracy monitoring** | SA-LLM-32 (output validation), SA-AI-LLM-04 (improper output handling) | **Low** -- detects unvalidated output; no accuracy metric enforcement |
| **Robustness against errors** | SA-AI-LLM-01 (prompt injection defence), SA-AI-LLM-04 (output validation), all injection checkpoints | **Partial** -- adversarial robustness via injection prevention |
| **Cybersecurity (see 15(5) below)** | Full checkpoint suite (408 checks) | **Good** -- comprehensive code-level security |

---

### Article 15(4) -- Robustness Against Adversarial Inputs

High-risk AI systems shall be resilient against attempts by unauthorised third parties to alter their use, outputs, or performance by exploiting system vulnerabilities. Technical solutions shall be appropriate to the relevant circumstances and risks.

#### Prompt Injection and Adversarial Input Resilience

| Category | Related Checkpoints | Coverage |
|---|---|---|
| **Direct prompt injection** | SA-AI-LLM-01 (prompt injection defence in skills) | **Good** -- checks for input segregation and validation instructions |
| **Indirect prompt injection** | SA-AI-LLM-01 (external content segregation) | **Good** -- checks tool output handling and content boundaries |
| **Tool output poisoning** | SA-AI-LLM-04 (improper output handling), SA-AI-LLM-01 (tool result injection) | **Good** -- detects unvalidated model output passed to execution |
| **Model manipulation via inputs** | SA-PY-02 (eval injection), SA-JS-01 (eval), SA-NODE-01 (exec injection) | **Good** -- prevents attacker-controlled code execution |
| **Data poisoning in training/RAG** | None directly | **None** -- training data validation out of scope for static analysis |

#### Exploitation of System Vulnerabilities

| Category | Related Checkpoints | Coverage |
|---|---|---|
| **Injection attacks (SQLi/XSS/CSRF)** | 60+ injection prevention checkpoints across all languages | **Excellent** |
| **Deserialization attacks** | SA-PY-01, SA-JAVA-01, SA-CS-01, SA-RB-04, SA-LLM-21 | **Good** |
| **Supply chain attacks** | SA-SC-01, SA-SC-02, SA-DEP-01 through SA-DEP-03, SA-AI-LLM-05 | **Good** |
| **Infrastructure vulnerabilities** | SA-AWS-*, SA-AZURE-*, SA-GCP-*, IaC checkpoints | **Good** |
| **Mobile attack surface** | SA-ANDROID-*, SA-IOS-* | **Good** -- mobile-specific security |

#### Gaps
- No adversarial machine learning robustness testing (FGSM, PGD, etc.)
- No input perturbation resilience measurement
- No model evasion attack detection
- No data poisoning detection for training pipelines or RAG indices

---

### Article 15(5) -- Cybersecurity Requirements

High-risk AI systems shall be resilient against attempts to alter their use, outputs, or performance by exploiting cybersecurity vulnerabilities. Appropriate measures shall include those aimed at preventing and controlling attacks, including model poisoning, adversarial examples, confidentiality attacks, and model flaws.

#### (a) Preventing AI-Specific Attack Vectors

| Attack Vector | Related Checkpoints | Coverage |
|---|---|---|
| **Prompt injection** | SA-AI-LLM-01 (skills), SA-AI-LLM-04 (output handling) | **Good** |
| **Sensitive information disclosure** | SA-AI-LLM-02 (secrets in prompts/configs), SA-SEC-01 through SA-SEC-04 | **Good** |
| **Excessive agency** | SA-AI-LLM-03 (tool permission audit, least privilege) | **Good** |
| **System prompt leakage** | SA-AI-LLM-05 (prompt secrets, supply chain) | **Good** |
| **Model extraction / inference attacks** | None | **None** -- requires runtime monitoring |
| **Training data extraction** | None | **None** -- requires model-level analysis |
| **Membership inference** | None | **None** -- requires model-level analysis |

#### (b) Controlling Traditional Cybersecurity Vulnerabilities

| Category | Related Checkpoints | Coverage |
|---|---|---|
| **Authentication and access control** | SA-SPRING-01, SA-DOTNET-01, SA-DJANGO-01, SA-FLASK-01, SA-FASTAPI-01, SA-RAILS-01, SA-EXPRESS-01, SA-NEST-01, SA-GIN-01, SA-BLAZOR-01 | **Good** -- all frameworks |
| **Secrets management** | SA-02 through SA-06, SA-AWS-07, SA-SEC-01 through SA-SEC-04 | **Excellent** |
| **Encryption in transit** | LIVE-TLS-01 through LIVE-TLS-03, framework HSTS checks | **Good** |
| **Encryption at rest** | SA-AWS-05, SA-AWS-06, SA-AZURE-03, SA-GCP-04 | **Partial** |
| **Dependency vulnerabilities** | SA-DEP-01 (trivy), SA-DEP-02, SA-DEP-03, SA-14/SA-15 | **Good** |
| **Infrastructure hardening** | IaC checkpoints (Docker, K8s, Terraform) | **Good** |
| **API security** | SA-API-01 through SA-API-06 | **Good** |
| **CORS and header security** | LIVE-HDR-*, cross-framework CORS checks | **Excellent** |
| **Security logging and monitoring** | SA-SPRING-06, SA-DJANGO-07, SA-RAILS-07, SA-EXPRESS-06 | **Partial** |

---

## Article 9 -- Risk Management System

Article 9 requires providers of high-risk AI systems to establish, implement, document, and maintain a risk management system. The risk management system shall identify and analyse known and reasonably foreseeable risks, estimate and evaluate risks, and adopt appropriate measures to manage them.

### Article 9(2) -- Identification and Analysis of Known and Foreseeable Risks

| Risk Category | Related Checkpoints | Coverage |
|---|---|---|
| **Vulnerability identification (SAST)** | SA-SAST-01, SA-SAST-02 (semgrep in CI) | **Good** -- automated static analysis |
| **Dependency vulnerability scanning** | SA-DEP-01 through SA-DEP-03, CVE enrichment (cve-feed.ts) | **Good** -- NVD and OSV API integration |
| **Secret exposure risk** | SA-SEC-01 through SA-SEC-04, SA-02/SA-03 | **Good** |
| **AI-specific risk identification** | SA-AI-LLM-01 through SA-AI-LLM-05 | **Good** -- OWASP LLM Top 10 mapping |
| **Risk scoring** | CVSS v4.0 scoring (cvss-scoring.md), CWE Top 25, OWASP Top 10 | **Good** -- standardised methodology |

### Article 9(5) -- Testing for Risk Management

| Testing Measure | Related Checkpoints | Coverage |
|---|---|---|
| **Automated security testing** | SA-SAST-01, SA-DEP-01, SA-SEC-01 | **Good** -- CI pipeline integration |
| **Runtime validation** | LIVE-TLS-01 through LIVE-TLS-03, LIVE-HDR-* | **Partial** -- TLS and header validation |
| **Supply chain monitoring** | SA-SC-01, SA-SC-02, SA-AI-LLM-05 | **Partial** |
| **Continuous monitoring** | SA-14/SA-15 (Dependabot), SA-07 (composer audit) | **Partial** |

#### Gaps
- No formal risk management framework template
- No risk register generation
- No residual risk calculation after mitigation
- No risk acceptance workflow

---

## Article 13 -- Transparency and Provision of Information to Deployers

Article 13 requires that high-risk AI systems be designed and developed in such a way as to ensure their operation is sufficiently transparent to enable deployers to interpret a system's output and use it appropriately.

### Article 13(3) -- Information to be Provided

| Requirement | Related Checkpoints | Coverage |
|---|---|---|
| **Intended purpose documentation** | SA-AI-LLM-02 (config audit), SKILL.md validation | **Partial** -- checks config completeness |
| **Level of accuracy / limitations** | None | **None** -- no accuracy benchmark validation |
| **Known or foreseeable circumstances leading to risks** | Full scan output with severity mapping | **Partial** -- vulnerability findings serve as risk indicators |
| **Human oversight measures** | SA-AI-LLM-03 (permission audit, safety hooks) | **Partial** -- checks for human-in-the-loop patterns |
| **Input data specifications** | None | **None** -- no input spec validation |
| **Logging capabilities** | SA-SPRING-06, SA-DJANGO-07, SA-RAILS-07, SA-EXPRESS-06, SA-AI-LLM-02 (log redaction) | **Partial** |

#### Gaps
- No automated documentation completeness checking against Article 13(3) requirements
- No model card or system card validation
- No performance metrics documentation verification
- No bias/fairness documentation checks

---

## Article 14 -- Human Oversight

Article 14 requires that high-risk AI systems be designed and developed in such a way as to be effectively overseen by natural persons during the period in which the system is in use.

### Article 14(4) -- Effective Oversight Capabilities

| Requirement | Related Checkpoints | Coverage |
|---|---|---|
| **Human approval for high-impact actions** | SA-AI-LLM-03 (safety hooks for dangerous operations) | **Good** -- verifies human-in-the-loop for destructive actions |
| **Ability to override or interrupt** | SA-AI-LLM-03 (tool permission scoping), SA-AI-LLM-04 (execution gates) | **Partial** -- checks for kill switches and confirmation gates |
| **Monitoring of AI system operation** | SA-AI-LLM-02 (logging and audit trails), security logging checkpoints | **Partial** |
| **Understanding system capabilities/limitations** | SA-AI-LLM-05 (system prompt review) | **Low** -- checks for leakage, not comprehensibility |

#### Gaps
- No enforcement of stop/override mechanisms at code level
- No automated audit trail completeness checking
- No verification of real-time monitoring dashboards
- No escalation path validation

---

## General-Purpose AI Models (Chapter V, Section 2)

For providers of GPAI models, Article 53 requires transparency obligations and Article 55 addresses systemic risk. The security-audit-skill primarily supports cybersecurity requirements for systems built on GPAI models.

### Article 53 -- GPAI Model Obligations

| Requirement | Related Checkpoints | Coverage |
|---|---|---|
| **Technical documentation** | SA-AI-LLM-05 (supply chain, version pinning) | **Low** -- checks dependencies, not documentation |
| **Information for downstream providers** | None | **None** -- business process |
| **Copyright compliance** | None | **None** -- legal concern |
| **Model evaluation** | None | **None** -- requires model benchmarking |

### Article 55 -- GPAI Models with Systemic Risk

| Requirement | Related Checkpoints | Coverage |
|---|---|---|
| **Model evaluation and adversarial testing** | SA-AI-LLM-01 (prompt injection), SA-AI-LLM-04 (output validation) | **Low** -- pattern detection only |
| **Cybersecurity protections** | Full checkpoint suite | **Good** -- application-layer security |
| **Incident reporting** | None | **None** -- organisational process |

---

## Coverage Summary

| EU AI Act Article | Coverage Level | Checkpoint Count | Key Gaps |
|---|---|---|---|
| Art. 15(4) Adversarial robustness | Good | ~15 | No ML-level robustness testing |
| Art. 15(5)(a) AI-specific cybersecurity | Good | ~20 | Model extraction, training data attacks |
| Art. 15(5)(b) Traditional cybersecurity | Excellent | ~350 | Comprehensive injection/auth/secrets |
| Art. 9 Risk management | Partial | ~40 | No risk register or residual risk calc |
| Art. 13 Transparency | Low | ~10 | No model card validation |
| Art. 14 Human oversight | Partial | ~10 | No override mechanism enforcement |
| Art. 53/55 GPAI obligations | Low | ~5 | Documentation and eval out of scope |

**Overall EU AI Act technical coverage: ~45% of technical requirements.**

The security-audit-skill provides strong coverage for Article 15(5)(b) (traditional cybersecurity) with 350+ checkpoints across all stacks. Article 15(4) (adversarial robustness) is partially covered through prompt injection and injection prevention checkpoints. The largest gaps are in AI-specific areas: adversarial ML testing, model-level attacks, transparency documentation, and formal risk management frameworks. These require specialised ML security tooling beyond static code analysis.

### AI-Specific Gaps

The following EU AI Act technical concerns are not covered:

1. **Adversarial ML robustness** -- No automated testing for adversarial examples, data poisoning, or model evasion attacks
2. **Model evaluation benchmarks** -- No accuracy, fairness, or bias metric validation
3. **Model cards / system cards** -- No documentation format validation
4. **Training data governance** -- No data quality, representativeness, or bias checks on training data
5. **Conformity assessment** -- No automated support for Annex VI/VII conformity procedures
6. **Post-market monitoring** -- No production performance drift detection

### Recommended Supplementary Controls

For comprehensive EU AI Act compliance, supplement security-audit-skill with:

1. **Adversarial ML tools** (Adversarial Robustness Toolbox, Garak for LLMs) for Article 15(4) robustness testing
2. **Model evaluation frameworks** (Inspect, lm-eval-harness) for accuracy and bias benchmarking
3. **AI documentation tools** (Model Cards Toolkit, Hugging Face model cards) for Article 13 transparency
4. **Data governance platforms** (Great Expectations, Evidently AI) for Article 10 data quality
5. **GRC platform** (Drata, Vanta, Credo AI) for risk management and conformity assessment
6. **Production monitoring** (Arize AI, WhyLabs) for post-market surveillance

---

## Changelog

| Date | Version | Changes |
|---|---|---|
| 2026-04-14 | 1.0.0 | Initial EU AI Act compliance mapping for 408 checkpoints |
