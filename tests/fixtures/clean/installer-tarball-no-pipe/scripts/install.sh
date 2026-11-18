#!/bin/sh
set -eu
url="https://releases.example.invalid/formatter-1.2.3.tar.gz"
curl -fsSL -o formatter.tar.gz "$url"
echo "0000000000000000000000000000000000000000000000000000000000000000  formatter.tar.gz" | sha256sum -c -
tar -xzf formatter.tar.gz -C "$HOME/tools"
