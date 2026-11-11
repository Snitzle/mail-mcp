#!/bin/sh
# Install mail-mcp where only root can change it. Run as root from the repository root,
# after `cargo build --release`:
#
#     sudo sh scripts/install-root.sh
#
# Installs the binary to /usr/local/bin/mail-mcp and, if there is no policy yet, the
# default policy to /etc/mail-mcp/policy.toml. An existing policy is never overwritten.
set -eu

here=$(cd "$(dirname "$0")/.." && pwd)
binary="$here/target/release/mail-mcp"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root (use sudo)." >&2
    exit 1
fi
if [ ! -x "$binary" ]; then
    echo "Build first: cargo build --release" >&2
    exit 1
fi

install -o root -g root -m 0755 "$binary" /usr/local/bin/mail-mcp
install -d -o root -g root -m 0755 /etc/mail-mcp
if [ ! -e /etc/mail-mcp/policy.toml ]; then
    install -o root -g root -m 0644 "$here/policy.example.toml" /etc/mail-mcp/policy.toml
fi
# Fedora: give the files their expected SELinux labels. Harmless elsewhere.
if command -v restorecon >/dev/null 2>&1; then
    restorecon -R /usr/local/bin/mail-mcp /etc/mail-mcp || true
fi

echo "Installed /usr/local/bin/mail-mcp and /etc/mail-mcp/policy.toml"
