# {Language} Security Features by Version

{Brief intro: Modern {Language} versions introduce features that directly improve security when used correctly. This reference documents security-relevant features from {Language} {version range}.}

## {Language} {Version X.0}

### {Feature Name}

```{lang}
// VULNERABLE: {description of insecure pattern}
{vulnerable code example}

// SECURE: {description of secure pattern using this feature}
{secure code example}
```

**Security implication:** {Explain how this feature prevents a specific vulnerability class. Reference CWE where applicable.}

{Repeat for each security-relevant feature in this version.}

## {Language} {Version X+1.0}

{Repeat version sections as needed.}

## Detection Patterns for Auditing {Language} Version Features

| Pattern | Regex | Severity | Checkpoint ID |
|---------|-------|----------|---------------|
| {Vulnerable pattern name} | `{detection regex}` | error/warning | SA-{LANG}-{NN} |
| {Next pattern} | `{regex}` | error/warning | SA-{LANG}-{NN} |

## Version Adoption Security Checklist

- [ ] {Checklist item for upgrading securely}
- [ ] {Next item}

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `cwe-top25.md` — CWE Top 25 mapping
- `input-validation.md` — Input validation patterns
- `{other relevant references}`

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| {YYYY-MM-DD} | Initial release | Phase {N} |
