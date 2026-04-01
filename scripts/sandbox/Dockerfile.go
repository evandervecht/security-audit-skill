# Stage 1: Build toolchain + govulncheck in dev container
FROM dhi.io/golang:1.22-alpine@sha256:1699c10032ca2582ec89a24a1312d986a3f094aed3d5c1147b19880afe40e052 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends strace \
    && rm -rf /var/lib/apt/lists/*
RUN go install golang.org/x/vuln/cmd/govulncheck@latest

# Stage 2: Hardened non-root runtime
FROM dhi.io/golang:1.22-alpine@sha256:1699c10032ca2582ec89a24a1312d986a3f094aed3d5c1147b19880afe40e052

COPY --from=builder /usr/bin/strace /usr/bin/strace
COPY --from=builder /root/go/bin/govulncheck /usr/local/bin/govulncheck

# Create non-root user with restricted home
RUN echo 'sandbox:x:10001:10001::/sandbox:/bin/false' >> /etc/passwd \
    && echo 'sandbox:x:10001:' >> /etc/group \
    && mkdir -p /sandbox && chown 10001:10001 /sandbox

ENV GOPATH=/sandbox/go
RUN mkdir -p /sandbox/go && chown sandbox:sandbox /sandbox/go

# Entrypoint script: download + govulncheck
COPY entrypoint-go.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /sandbox

# Drop to non-root
USER sandbox:sandbox

ENTRYPOINT ["strace", "-f", "-e", "trace=network,process,openat", "-o", "/tmp/strace.log", "--", "/usr/local/bin/entrypoint.sh"]
