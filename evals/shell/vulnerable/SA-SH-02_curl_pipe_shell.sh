#!/bin/bash
# Bootstrap a CI runner with the vendor toolchain
set -e

echo "installing toolchain"
curl -fsSL https://get.example.com/install.sh | sudo bash

echo "installing node helper"
wget -qO- https://mirror.example.com/setup-node.sh | sh

echo "runner ready"
