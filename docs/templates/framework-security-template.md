# {Framework} Security Patterns

{Brief intro: Security patterns, common misconfigurations, and detection regexes for {Framework} applications.}

## Cross-Site Scripting (XSS)

### {Framework-specific XSS pattern}

```{lang}
// VULNERABLE: {description}
{vulnerable code}

// SECURE: {description}
{secure code}
```

**Detection regex:** `{regex pattern}`
**Checkpoint:** SA-{FRAMEWORK}-{NN}
**Severity:** error

{Repeat for each XSS pattern specific to this framework.}

## Injection

### {SQL/NoSQL/Command/Template injection pattern}

```{lang}
// VULNERABLE: {description}
{vulnerable code}

// SECURE: {description}
{secure code}
```

**Detection regex:** `{regex pattern}`
**Checkpoint:** SA-{FRAMEWORK}-{NN}
**Severity:** error

## Authentication & Authorization

### {Auth pattern specific to this framework}

```{lang}
// VULNERABLE: {description}
{vulnerable code}

// SECURE: {description}
{secure code}
```

**Detection regex:** `{regex pattern}`
**Checkpoint:** SA-{FRAMEWORK}-{NN}
**Severity:** error

## CSRF Protection

### {Framework-specific CSRF pattern}

{Same structure as above.}

## Security Misconfiguration

### {Common misconfiguration}

{Same structure as above.}

## Data Exposure

### {Sensitive data exposure pattern}

{Same structure as above.}

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| {Finding name} | Critical/High/Medium/Low | Immediate/1 week/1 month | Low/Medium/High |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `{language}-security-features.md` — Language-level patterns
- `{other relevant references}`

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| {YYYY-MM-DD} | Initial release | Phase {N} |
