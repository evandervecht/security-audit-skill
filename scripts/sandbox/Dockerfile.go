# Stage 1: Build toolchain in dev container
FROM dhi.io/library/golang:1.22-alpine@sha256:1699c10032ca2582ec89a24a1312d986a3f094aed3d5c1147b19880afe40e052 AS builder

RUN apk add --no-cache strace

# Stage 2: Hardened non-root runtime
FROM dhi.io/library/golang:1.22-alpine@sha256:1699c10032ca2582ec89a24a1312d986a3f094aed3d5c1147b19880afe40e052

COPY --from=builder /usr/bin/strace /usr/bin/strace

RUN rm -rf /var/cache/apk/* /tmp/*

# Create non-root user with restricted home
RUN addgroup -S sandbox && adduser -S -G sandbox -h /sandbox -s /sbin/nologin sandbox

# Go needs GOPATH writable
ENV GOPATH=/sandbox/go
RUN mkdir -p /sandbox/go && chown sandbox:sandbox /sandbox/go

WORKDIR /sandbox

# Drop to non-root
USER sandbox:sandbox

ENTRYPOINT ["strace", "-f", "-e", "trace=network,process,openat", "-o", "/tmp/strace.log", "--", "go", "mod", "download"]
