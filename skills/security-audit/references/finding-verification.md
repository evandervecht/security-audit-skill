# Finding Verification

Every candidate finding is challenged by a reviewer whose job is to prove it wrong. Only candidates that survive are reported as vulnerabilities. Scanner hits, checkpoint matches and LLM reviews are all *candidates* until they pass this step.

## Why

Pattern scanners and single-pass reviews over-report. A `grep` hit on `eval(` says nothing about whether an attacker controls the argument. A reviewer that already believes a finding tends to confirm it. Separating "find" from "verify", and giving the verifier the opposite goal, removes most false positives at a small cost in tokens.

## Pipeline

1. **Collect.** Gather candidates from `scripts/security-audit-dispatcher.sh`, mechanical checkpoints, `llm_reviews` prompts and manual review.
2. **Triage (mechanical, no LLM).** Drop or group before spending tokens:
   - Hits in test fixtures, eval directories, vendored code, generated code, docs and examples. List them as excluded, do not verify.
   - Duplicates: same sink, same root cause. Keep one candidate and list the other locations.
   - Pure hygiene hits (missing header, unpinned action) that need no data-flow argument. Report them as `hardening` directly.
3. **Verify.** Each remaining candidate goes to a verifier (see below).
4. **Score.** CVSS (`cvss-scoring.md`) only for `confirmed` findings. `unproven` findings get no score.
5. **Report.** Group by verdict. Confirmed first.

## Verdicts

| Verdict | Meaning | Reported as |
|---|---|---|
| `confirmed` | Complete source-to-sink trace with file:line evidence, no effective control on the path, concrete impact | Vulnerability, with CVSS score |
| `unproven` | Plausible, but one specific fact could not be established from the code (runtime config, upstream caller, deployment) | Open question, with the exact fact to check. No score |
| `refuted` | The verifier found the control, dead path or missing precondition that defeats it | Listed briefly with the reason, so reruns do not re-raise it |
| `hardening` | A missing secondary control, where another layer already blocks the attack, or a hygiene issue | Recommendation, not a vulnerability |

Do not upgrade `unproven` to `confirmed` because the bug class is common or the code "looks risky".

## Verifier independence

- **Fresh context.** Run the verifier as a separate subagent when the agent supports it. Otherwise run it as a separate pass after all detection is finished, and state the refutation goal explicitly.
- **Claim, not argument.** Give the verifier the claim (location, bug class, alleged source and sink) and repository access. Do not pass the detector's reasoning, confidence or severity guess; they anchor the verifier.
- **Never self-verify.** The agent or pass that raised a candidate does not decide its verdict.

## Refutation checklist

The verifier works through these in order and stops at the first one that defeats the claim.

1. **Reachability.** Is the code reachable from an entry point in a shipped build? Look for dead code, feature flags that are off, debug-only routes and test helpers.
2. **Attacker control.** Trace the value backwards from the sink. Does it originate from a request, file, message, environment or other input an attacker can influence? Constants, config set by operators and server-generated IDs are not attacker-controlled.
3. **Controls on the path.** Look for validation, allow-lists, type coercion, parameterisation, framework auto-escaping, ORM binding, authorization checks and middleware that run before the sink. Read the framework reference for the stack (for example `django-security.md`) to know which defaults protect.
4. **Context match.** Is the control right for this sink? HTML escaping does not protect a SQL query or a shell argument; a URL allow-list checked before a redirect does not protect a later fetch.
5. **Preconditions.** What must the attacker already have (account, role, network position, user interaction)? If the precondition already grants the impact, the finding adds nothing.
6. **Impact.** State what the attacker gains in one sentence: read another tenant's data, execute a command, forge a session. "Could be dangerous" is not an impact.
7. **Layering.** If another layer blocks the attack outright, the verdict is `hardening`, not `confirmed`.

If every step holds, the verdict is `confirmed`. If a step cannot be answered from the code, the verdict is `unproven` and the open fact is that step's question.

## Verifier prompt

Use this template once per candidate (or per small group of low-severity candidates in one file).

```text
You are verifying a candidate security finding. Your goal is to DISPROVE it.
Assume it is a false positive until the code proves otherwise.

Candidate:
- ID: {id}
- Class: {bug class, e.g. SQL injection, CWE-89}
- Sink: {file}:{line}
- Alleged source: {where attacker input is said to come from}

Work through the refutation checklist in references/finding-verification.md.
Read the actual code. Cite file:line for every step of the trace.

Return exactly:
- verdict: confirmed | unproven | refuted | hardening
- trace: ordered list of file:line steps from source to sink (confirmed only)
- defeated_by: the check that defeats the claim, with file:line (refuted/hardening only)
- open_fact: the one fact still unknown (unproven only)
- impact: one sentence (confirmed only)
- preconditions: what the attacker needs (confirmed only)
```

## Finding record

Record each verified candidate in this shape, in the report or as JSON next to it.

```json
{
  "id": "SA-PY-03-001",
  "checkpoint": "SA-PY-03",
  "class": "Command injection",
  "cwe": "CWE-78",
  "verdict": "confirmed",
  "location": "app/tasks/export.py:88",
  "trace": [
    "app/api/export.py:41 request.args['fmt'] read into fmt",
    "app/api/export.py:47 fmt passed to run_export(fmt)",
    "app/tasks/export.py:88 subprocess.run(f'convert --to {fmt} ...', shell=True)"
  ],
  "preconditions": "Authenticated user, any role",
  "impact": "Runs arbitrary shell commands as the worker service account",
  "cvss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
  "fix": "Validate fmt against an allow-list and call subprocess.run with an argument list"
}
```

For `refuted` and `hardening`, keep `id`, `class`, `location`, `verdict` and `defeated_by`. For `unproven`, keep `id`, `class`, `location`, `verdict` and `open_fact`.

## Cost control

- Triage first; most scanner noise disappears without an LLM.
- Verify every high and critical candidate on its own.
- Batch low-severity candidates by file, at most five per verifier.
- If the budget runs out, report unverified candidates as `unproven` with `open_fact: not verified`, never as `confirmed`.

## Reruns

Keep the previous report's records. On a rerun, skip `refuted` candidates whose code is unchanged (compare the file at the cited lines), and re-verify `unproven` ones first: they are the cheapest place to gain confidence.
