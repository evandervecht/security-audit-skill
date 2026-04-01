# Dependency Sandbox — Usage Guide

Isolated Docker-based environment for monitoring package installations. Detects supply chain attacks by tracing network calls, file system access, and process spawning during `npm install`, `pip install`, `go mod download`, `cargo fetch`, and `dotnet restore`.

## Quick Start

```bash
# Scan a public npm package
./scripts/dependency-sandbox.sh npm lodash@4.17.21

# Scan a public Python package
./scripts/dependency-sandbox.sh pip requests==2.31.0

# Scan a Go module
./scripts/dependency-sandbox.sh go github.com/gin-gonic/gin

# Scan a Rust crate
./scripts/dependency-sandbox.sh rust serde

# Scan a NuGet package
./scripts/dependency-sandbox.sh dotnet Newtonsoft.Json
```

## Project Scanning

Scan all dependencies in a project's manifest file:

```bash
./scripts/dependency-sandbox.sh npm-project ./package.json
./scripts/dependency-sandbox.sh pip-project ./requirements.txt
./scripts/dependency-sandbox.sh go-project ./go.mod
./scripts/dependency-sandbox.sh rust-project ./Cargo.toml
./scripts/dependency-sandbox.sh dotnet-project ./MyApp.csproj
```

## Private Registry Support

When scanning packages from private registries, you need to:

1. **Allowlist the registry host** so it's not flagged as suspicious
2. **Provide a scoped credential file** (never your full `~/.npmrc`)

```bash
# npm with private registry
./scripts/dependency-sandbox.sh \
  --registry npm.mycompany.com \
  --auth-file ./scoped-npmrc \
  npm @mycompany/sdk@1.0.0

# pip with private registry
./scripts/dependency-sandbox.sh \
  --registry pypi.mycompany.com \
  --auth-file ./scoped-pip.conf \
  pip my-internal-lib==2.0.0

# Multiple private registries
./scripts/dependency-sandbox.sh \
  --registry npm.mycompany.com \
  --registry registry.corp.io \
  --auth-file ./scoped-npmrc \
  npm @mycompany/sdk@1.0.0
```

### Creating Scoped Credential Files

**Never mount your full `~/.npmrc`, `~/.pypirc`, or `~/.cargo/credentials.toml`** — a malicious package could read and exfiltrate all tokens in those files. Instead, create a minimal file scoped to the specific registry.

#### npm (scoped .npmrc)

```ini
# Only the token for the private registry — nothing else
//npm.mycompany.com/:_authToken=npm_XXXXXXXXXXXXXXXXXXXX
registry=https://npm.mycompany.com/
```

#### pip (scoped pip.conf)

```ini
[global]
index-url = https://username:token@pypi.mycompany.com/simple/
```

#### Go (scoped .netrc)

```
machine git.mycompany.com
  login oauth2
  password glpat-XXXXXXXXXXXXXXXXXXXX
```

Also set `GONOSUMCHECK=mycompany.com/*` and `GONOSUMDB=mycompany.com/*` in the environment.

#### Rust (scoped credentials.toml)

```toml
[registries.mycompany]
token = "Bearer XXXXXXXXXXXXXXXXXXXX"
```

#### .NET (scoped nuget.config)

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="mycompany" value="https://nuget.mycompany.com/v3/index.json" />
  </packageSources>
  <packageSourceCredentials>
    <mycompany>
      <add key="Username" value="deploy" />
      <add key="ClearTextPassword" value="XXXXXXXXXXXXXXXXXXXX" />
    </mycompany>
  </packageSourceCredentials>
</configuration>
```

## What Gets Monitored

The sandbox uses `strace` to monitor all system calls during package installation:

| Check | What it detects | Severity |
|-------|----------------|----------|
| **Network connections** | Connections to hosts outside known package registries | WARNING |
| **DNS lookups** | DNS resolution for non-registry domains | WARNING |
| **File writes** | Writes outside the package directory (`node_modules`, `.cargo`, etc.) | WARNING |
| **Process spawning** | Execution of unexpected binaries (not node/python/go/cargo/dotnet) | WARNING |
| **Environment access** | Reading sensitive env vars (AWS_SECRET, GITHUB_TOKEN, etc.) | WARNING |
| **Credential exfiltration** | Install scripts reading the mounted auth credential file | CRITICAL |
| **Credential + network** | Process that reads credentials AND connects to non-registry host | CRITICAL |

## Container Security

All sandbox containers are hardened:

| Control | Value |
|---------|-------|
| **Base images** | dhi.io registry with SHA256 digest pinning |
| **Build** | Multi-stage (dev → hardened runtime) |
| **User** | Non-root (`sandbox:sandbox`, `/sbin/nologin`) |
| **Filesystem** | Read-only rootfs, tmpfs for `/tmp` and `/sandbox` |
| **Capabilities** | `--cap-drop=ALL` |
| **Privileges** | `--security-opt=no-new-privileges:true` |
| **Resources** | 512MB RAM, 1 CPU, 256 PID limit |
| **Auth file** | Mounted read-only, access monitored via strace |

## MCP Tool

The sandbox is also available as an MCP tool for AI-powered IDEs:

```json
{
  "tool": "dependency_sandbox",
  "arguments": {
    "ecosystem": "npm",
    "package": "lodash@4.17.21"
  }
}
```

Supported ecosystems: `npm`, `pip`, `go`, `rust`, `dotnet`.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no suspicious behavior detected |
| 1 | Suspicious — one or more findings |
| 2 | Usage error or Docker not available |

## Troubleshooting

**Docker not running:** Start Docker Desktop or the Docker daemon.

**Permission denied on strace:** The sandbox uses `strace` inside the container. Some Docker configurations may block ptrace. Add `--cap-add=SYS_PTRACE` if needed (reduces isolation — only use for debugging).

**Package install fails:** The sandbox has restricted network and filesystem access. Some packages with native dependencies may fail to build. This is expected — the sandbox is for monitoring behavior, not building production artifacts.

**Auth file not found in container:** Ensure the auth file path is absolute or relative to the current directory.
