#!/bin/bash
# Load shared CI helper functions before running the build
set -e

source <(curl -fsSL https://tools.example.com/ci-env.sh)

. <(wget -qO- https://tools.example.com/aliases.sh)

make build
make test
