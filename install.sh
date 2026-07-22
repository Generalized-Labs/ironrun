#!/usr/bin/env bash
set -euo pipefail

# ironrun installer
# Usage: curl -fsSL https://ironrun.dev/install.sh -o /tmp/ironrun-install.sh && bash /tmp/ironrun-install.sh
#
# Installs the latest ironrun binary to /usr/local/bin (or ~/.local/bin if no sudo).

REPO="generalized-labs/ironrun"
BINARY="ironrun"
INSTALL_DIR="${IRONRUN_INSTALL_DIR:-}"

# Detect OS and architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
  linux*)  OS="Linux" ;;
  darwin*) OS="Darwin" ;;
  *)       echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac

case "$ARCH" in
  x86_64|amd64) ARCH="x86_64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *)             echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# Get latest version
VERSION="${IRONRUN_VERSION:-}"
if [ -z "$VERSION" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')"
  if [ -z "$VERSION" ]; then
    echo "Could not determine latest version. Set IRONRUN_VERSION to override." >&2
    exit 1
  fi
fi

TARBALL="${BINARY}_${OS}_${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"

echo "Installing ironrun ${VERSION} for ${OS}/${ARCH}..."

# Create temp dir
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Download
curl -fsSL "$DOWNLOAD_URL" -o "$TMP/$TARBALL"

# Verification is mandatory. Never install an artifact without the matching
# release checksum, even when GitHub is partially unavailable.
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
if ! curl -fsSL "$CHECKSUMS_URL" -o "$TMP/checksums.txt"; then
  echo "Could not download checksums for ${VERSION}; refusing an unverified install." >&2
  exit 1
fi
EXPECTED="$(awk -v file="$TARBALL" '$2 == file { print $1 }' "$TMP/checksums.txt")"
if [ -z "$EXPECTED" ] || [ "$(printf '%s\n' "$EXPECTED" | wc -l | tr -d ' ')" != "1" ]; then
  echo "checksums.txt has no unique entry for ${TARBALL}; refusing installation." >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "$TMP/$TARBALL" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL="$(shasum -a 256 "$TMP/$TARBALL" | awk '{print $1}')"
else
  echo "No SHA-256 tool found (need sha256sum or shasum); refusing installation." >&2
  exit 1
fi
if [ "$ACTUAL" = "$EXPECTED" ]; then
  echo "Checksum verified."
else
  echo "Checksum mismatch! Expected $EXPECTED, got $ACTUAL" >&2
  exit 1
fi

# Extract
tar -xzf "$TMP/$TARBALL" -C "$TMP"

# Determine install dir
if [ -z "$INSTALL_DIR" ]; then
  if [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
  elif sudo -n true 2>/dev/null; then
    INSTALL_DIR="/usr/local/bin"
    USE_SUDO=1
  else
    INSTALL_DIR="$HOME/.local/bin"
  fi
fi
mkdir -p "$INSTALL_DIR"

# Install
if [ "${USE_SUDO:-}" = "1" ]; then
  sudo install -m755 "$TMP/$BINARY" "$INSTALL_DIR/$BINARY"
else
  install -m755 "$TMP/$BINARY" "$INSTALL_DIR/$BINARY"
fi

echo "ironrun ${VERSION} installed to ${INSTALL_DIR}/${BINARY}"

# PATH hint
if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
  echo ""
  echo "NOTE: Add ${INSTALL_DIR} to your PATH:"
  echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
fi

echo ""
echo "Run: ironrun --help"
echo "Docs: https://github.com/generalized-labs/ironrun"
