# Kubernetes Manifest Security

Kubernetes manifests declare how workloads run inside a cluster. A single permissive `securityContext`, a `hostPath` mount, or a hardcoded secret is applied automatically and at scale, so manifest misconfigurations are a high-value audit surface. This reference extends [iac-security.md](iac-security.md) with manifest-level checks for Pods, Deployments, DaemonSets, StatefulSets, Jobs, and their Helm/Kustomize equivalents.

The checkpoints below (`SA-KUBE-01` .. `SA-KUBE-08`) are mechanical regex checks applied to `*.yaml` / `*.yml` files. The hardened (`SECURE`) examples are the recommended remediation.

---

## Privileged Containers (SA-KUBE-01)

A privileged container runs with all Linux capabilities and effectively has root on the host node. Escaping such a container is trivial. Privileged mode is almost never required for application workloads.

```yaml
# VULNERABLE: privileged mode grants full host access
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
    - name: app
      image: myapp:1.2.3
      securityContext:
        privileged: true
```

```yaml
# SECURE: never run privileged; drop escalation
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
    - name: app
      image: myapp:1.2.3
      securityContext:
        privileged: false
        allowPrivilegeEscalation: false
```

### Detection Pattern

```
privileged:\s*true
```

---

## hostPath Volumes (SA-KUBE-02)

`hostPath` mounts a directory from the host node directly into the pod. A compromised container can then read or modify host files (including `/var/run/docker.sock`, kubelet credentials, or `/etc`), enabling node takeover. Use `emptyDir`, PVCs, ConfigMaps, or `projected` volumes instead.

```yaml
# VULNERABLE: host filesystem mounted into the pod
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
    - name: app
      image: myapp:1.2.3
      volumeMounts:
        - name: host
          mountPath: /host
  volumes:
    - name: host
      hostPath:
        path: /var/lib/data
```

```yaml
# SECURE: ephemeral emptyDir volume, no host exposure
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
    - name: app
      image: myapp:1.2.3
      volumeMounts:
        - name: cache
          mountPath: /cache
  volumes:
    - name: cache
      emptyDir: {}
```

### Detection Pattern

```
hostPath:\s*\n\s*path:
```

---

## Privilege Escalation (SA-KUBE-03)

`allowPrivilegeEscalation` controls whether a process can gain more privileges than its parent (e.g. via setuid binaries or file capabilities). It defaults to `true`, so it must be explicitly set to `false`. Setting it to `true` is a misconfiguration to flag.

```yaml
# VULNERABLE: process can escalate privileges
securityContext:
  allowPrivilegeEscalation: true
```

```yaml
# SECURE: escalation disabled
securityContext:
  allowPrivilegeEscalation: false
```

### Detection Pattern

```
allowPrivilegeEscalation:\s*true
```

---

## Running as Root (SA-KUBE-04)

Containers run as UID 0 (root) by default. Combined with a container escape, root inside the container becomes root on the node. Set `runAsNonRoot: true` and a non-zero `runAsUser`. An explicit `runAsUser: 0` is the misconfiguration.

```yaml
# VULNERABLE: explicitly running as root
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  securityContext:
    runAsUser: 0
  containers:
    - name: app
      image: myapp:1.2.3
```

```yaml
# SECURE: enforce non-root with a fixed UID
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1001
  containers:
    - name: app
      image: myapp:1.2.3
```

### Detection Pattern

```
runAsUser:\s*0\b
```

The `\b` word boundary prevents false positives on non-zero UIDs such as `runAsUser: 1000` or `runAsUser: 1001`.

---

## Host Namespace Sharing (SA-KUBE-05)

`hostNetwork`, `hostPID`, and `hostIPC` share the node's network stack, process tree, or IPC namespace with the pod. They break the isolation boundary: a pod can bind host ports, ptrace host processes, or read host shared memory. All default to `false` and should stay there.

```yaml
# VULNERABLE: host namespaces shared
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  hostNetwork: true
  hostPID: true
  containers:
    - name: app
      image: myapp:1.2.3
```

```yaml
# SECURE: isolated namespaces (explicit for clarity)
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false
  containers:
    - name: app
      image: myapp:1.2.3
```

### Detection Pattern

```
host(Network|PID|IPC):\s*true
```

---

## Dangerous Linux Capabilities (SA-KUBE-06)

Adding broad capabilities such as `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, or `ALL` gives a container near-root power over the kernel and host networking. The hardened baseline is to `drop: [ALL]` and add back only the specific capabilities the workload needs (e.g. `NET_BIND_SERVICE`).

The detection pattern matches both the YAML block-sequence and the inline flow-sequence forms, and is anchored on `add:` so that a dangerous capability appearing under `drop:` (e.g. `drop: [ALL]`) does not false-positive.

```yaml
# VULNERABLE: dangerous capabilities added (block form)
securityContext:
  capabilities:
    add:
      - SYS_ADMIN
      - NET_RAW
```

```yaml
# VULNERABLE: same risk, inline flow form
securityContext:
  capabilities:
    add: ["NET_RAW", "SYS_ADMIN"]
```

```yaml
# SECURE: drop everything, add only what is required
securityContext:
  capabilities:
    drop:
      - ALL
    add:
      - NET_BIND_SERVICE
```

### Detection Pattern

```
add:\s*(?:\[[^]]*\b(SYS_ADMIN|NET_ADMIN|SYS_PTRACE|ALL)\b|(?:\n\s*-\s*\w+)*\n\s*-\s*(SYS_ADMIN|NET_ADMIN|SYS_PTRACE|ALL)\b)
```

---

## Mutable Image Tags (SA-KUBE-07)

Pinning an image to `:latest` (or any mutable tag) makes deploys non-deterministic: the same manifest can pull different image contents over time, defeating supply-chain controls and complicating incident response. Pin a semantic version and, ideally, a content digest.

```yaml
# VULNERABLE: mutable :latest tag
containers:
  - name: app
    image: registry.example.com/myapp:latest
```

```yaml
# SECURE: pinned version + digest
containers:
  - name: app
    image: registry.example.com/myapp:1.4.2@sha256:abc123
```

### Detection Pattern

```
image:\s*\S+:latest\b
```

The `\b` after `latest` and the required `:latest` tag boundary avoid false positives on repository names that merely contain the word `latest` (e.g. `registry.io/latest-app:1.0`).

---

## Plaintext Secrets in env (SA-KUBE-08)

Hardcoding credentials as a plaintext `value:` under `env:` commits them to version control and exposes them to anyone who can read the manifest or pod spec. Reference a Secret via `valueFrom.secretKeyRef` instead (and manage the Secret itself with external-secrets or sealed-secrets — see [iac-security.md](iac-security.md)).

```yaml
# VULNERABLE: plaintext secret in the manifest
env:
  - name: DB_PASSWORD
    value: "superSecret123"
```

```yaml
# SECURE: reference a Secret
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: app-secrets
        key: db-password
```

### Detection Pattern

```
name:\s*\w*(PASSWORD|SECRET|TOKEN|API_?KEY)\w*\s*\n\s*value:\s*["']?\S
```

The `valueFrom:` form (the secure remediation) is a near-miss that this pattern correctly does NOT match.

---

## Related Checks (not pinned to a single regex)

These require structural / absence analysis and are best handled in review rather than a line-level regex:

- **Missing resource limits** — every container should set `resources.requests` and `resources.limits` (CPU + memory) to prevent noisy-neighbor and DoS conditions.
- **`automountServiceAccountToken`** — set to `false` on Pods and ServiceAccounts that do not call the Kubernetes API, so a compromised pod cannot use the mounted token.
- **`runAsNonRoot` not set** — the absence of `runAsNonRoot: true` is itself a risk even when no explicit `runAsUser: 0` is present.
- **`readOnlyRootFilesystem`** — should be `true` so a compromised process cannot persist to the container filesystem.
- **Missing NetworkPolicy / overly broad RBAC** — see [iac-security.md](iac-security.md).

---

## Prevention Checklist

- [ ] No container runs `privileged: true`.
- [ ] No `hostPath` volumes; use `emptyDir`, PVCs, ConfigMaps, or `projected` volumes.
- [ ] `allowPrivilegeEscalation: false` on every container.
- [ ] `runAsNonRoot: true` and a non-zero `runAsUser`; never `runAsUser: 0`.
- [ ] `hostNetwork`, `hostPID`, `hostIPC` all `false`.
- [ ] `capabilities.drop: [ALL]`; add back only the minimum needed.
- [ ] Images pinned to an immutable version tag and digest, never `:latest`.
- [ ] Secrets referenced via `secretKeyRef`, never hardcoded as plaintext `value:`.
- [ ] Every container declares `resources.requests` and `resources.limits`.
- [ ] `automountServiceAccountToken: false` where the API is not used.
- [ ] `readOnlyRootFilesystem: true` and a `seccompProfile: { type: RuntimeDefault }`.
- [ ] NetworkPolicy restricts pod-to-pod traffic; RBAC follows least privilege.
