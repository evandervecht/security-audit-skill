#!/bin/bash
# Load shared CI helper functions before running the build
set -euo pipefail

CI_ENV_SHA256="3c1f9a7e5d2b8f4a6c0e9d1b7f3a5c8e2d6b0f9a4c7e1d3b5f8a2c6e0d9b1f4a"

envfile="$(mktemp)"
curl -fsSL -o "$envfile" https://tools.example.com/v1.4.0/ci-env.sh
echo "${CI_ENV_SHA256}  ${envfile}" | sha256sum -c -
source "$envfile"
rm -f "$envfile"

# Read-only drift check: compares remote content, never executes it
diff ci-env.sh <(curl -fsSL https://tools.example.com/v1.4.0/ci-env.sh) || true

make build
make test
