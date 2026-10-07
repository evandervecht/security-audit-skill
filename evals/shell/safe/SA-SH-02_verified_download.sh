#!/bin/bash
# Bootstrap a CI runner with the vendor toolchain (pinned version + checksum)
set -euo pipefail

INSTALL_SHA256="9f2a4c8e1b7d3f6a0c5e9d2b8f4a7c1e3d6b9f0a2c5e8d1b4f7a0c3e6d9b2f5a"

installer="$(mktemp)"
curl -fsSL -o "$installer" "https://get.example.com/v3.2.1/install.sh"
echo "${INSTALL_SHA256}  ${installer}" | sha256sum -c -
sudo bash "$installer" --prefix=/opt/toolchain
rm -f "$installer"

# Lint the remote script without executing it - the pipe target is a checker, not a shell
curl -fsSL "https://get.example.com/v3.2.1/install.sh" | shellcheck -

echo "runner ready"
