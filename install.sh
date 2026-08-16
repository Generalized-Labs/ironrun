#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# ironrun installer
#
# Usage:
#   curl -fsSL https://ironrun.dev/install.sh | bash
#
# Environment Overrides:
#   IRONRUN_VERSION       - Specific version to install (e.g. "v0.4.0")
#   IRONRUN_INSTALL_DIR   - Custom install directory (e.g. "/usr/local/bin")
# ==============================================================================

REPO="generalized-labs/ironrun"
BINARY="ironrun"
INSTALL_DIR="${IRONRUN_INSTALL_DIR:-}"

# Formatting
BOLD="$(tput bold 2>/dev/null || echo '')"
GREEN="$(tput setaf 2 2>/dev/null || echo '')"
CYAN="$(tput setaf 6 2>/dev/null || echo '')"
YELLOW="$(tput setaf 3 2>/dev/null || echo '')"
RED="$(tput setaf 1 2>/dev/null || echo '')"
RESET="$(tput sgr0 2>/dev/null || echo '')"

printf "%s" "${CYAN}${BOLD}"
cat << "EOF"
  _                          
 (_) _ __ ___  _ __  _ __ _   _ _ __  
 | | '__/ _ \| '_ \| '__| | | | '_ \ 
 | | | | (_) | | | | |  | |_| | | | |
 |_|_|  \___/|_| |_|_|   \__,_|_| |_|
EOF
printf "%s\n" "${RESET}"
echo "${BOLD}Shield your secrets from AI coding agents (Claude Code, Codex, Cursor).${RESET}"
echo ""

# 1. Detect OS & Architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
  linux*)  OS="Linux" ;;
  darwin*) OS="Darwin" ;;
  *)       echo "${RED}Error: Unsupported operating system: $OS${RESET}" >&2; exit 1 ;;
esac

case "$ARCH" in
  x86_64|amd64) ARCH="x86_64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *)             echo "${RED}Error: Unsupported architecture: $ARCH${RESET}" >&2; exit 1 ;;
esac

# 2. Resolve Version
VERSION="${IRONRUN_VERSION:-}"
if [ -z "$VERSION" ]; then
  printf "Fetching latest release version... "
  # Try GitHub API first, fallback to redirect location header if rate-limited
  VERSION="$(curl -fsSL -H "Accept: application/vnd.github+json" "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name"' | head -n1 | sed -E 's/.*"([^"]+)".*/\1/' || true)"
  if [ -z "$VERSION" ]; then
    VERSION="$(curl -fsSI "https://github.com/${REPO}/releases/latest" 2>/dev/null | grep -i "^location:" | head -n1 | sed -E 's/.*\/tag\/([^[:space:]\r\n]+).*/\1/' || true)"
  fi
  if [ -z "$VERSION" ]; then
    echo "${RED}Failed${RESET}"
    echo "${RED}Could not automatically determine the latest release version.${RESET}" >&2
    echo "Please specify a version manually: IRONRUN_VERSION=v0.4.0 curl -fsSL https://ironrun.dev/install.sh | bash" >&2
    exit 1
  fi
  printf "%s\n" "${GREEN}${VERSION}${RESET}"
fi

TARBALL="${BINARY}_${OS}_${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"

echo "Downloading ${BOLD}ironrun ${VERSION}${RESET} for ${OS}/${ARCH}..."

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if ! curl -fsSL "$DOWNLOAD_URL" -o "$TMP/$TARBALL"; then
  echo "${RED}Download failed for: ${DOWNLOAD_URL}${RESET}" >&2
  exit 1
fi

# 3. Checksum Verification
printf "Verifying cryptographic checksum... "
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
if curl -fsSL "$CHECKSUMS_URL" -o "$TMP/checksums.txt" 2>/dev/null; then
  EXPECTED="$(awk -v file="$TARBALL" '$2 == file { print $1 }' "$TMP/checksums.txt")"
  if [ -n "$EXPECTED" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
      ACTUAL="$(sha256sum "$TMP/$TARBALL" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
      ACTUAL="$(shasum -a 256 "$TMP/$TARBALL" | awk '{print $1}')"
    else
      ACTUAL=""
    fi
    if [ -n "$ACTUAL" ]; then
      if [ "$ACTUAL" = "$EXPECTED" ]; then
        printf "%s\n" "${GREEN}Verified ✓${RESET}"
      else
        printf "%s\n" "${RED}MISMATCH ✗${RESET}"
        echo "${RED}Checksum mismatch! Expected $EXPECTED, got $ACTUAL${RESET}" >&2
        exit 1
      fi
    else
      printf "%s\n" "${YELLOW}Skipped (no sha256 tool)${RESET}"
    fi
  else
    printf "%s\n" "${YELLOW}No checksum found${RESET}"
  fi
else
  printf "%s\n" "${YELLOW}Checksum file not found${RESET}"
fi

# 4. Extract
tar -xzf "$TMP/$TARBALL" -C "$TMP"

# 5. Determine Destination
USE_SUDO=0
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

if [ "$USE_SUDO" = "1" ]; then
  sudo install -m755 "$TMP/$BINARY" "$INSTALL_DIR/$BINARY"
else
  install -m755 "$TMP/$BINARY" "$INSTALL_DIR/$BINARY"
fi

echo ""
echo "${GREEN}✓ Successfully installed ${BOLD}ironrun${RESET}${GREEN} to ${INSTALL_DIR}/${BINARY}${RESET}"

# 6. Check PATH and offer profile guidance
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
  echo ""
  echo "${YELLOW}Notice: ${INSTALL_DIR} is not in your \$PATH.${RESET}"
  
  SHELL_NAME="$(basename "${SHELL:-bash}")"
  case "$SHELL_NAME" in
    zsh)  PROFILE="$HOME/.zshrc" ;;
    bash) PROFILE="$HOME/.bashrc" ;;
    fish) PROFILE="$HOME/.config/fish/config.fish" ;;
    *)    PROFILE="$HOME/.profile" ;;
  esac

  echo "Add it with:"
  echo "  ${BOLD}echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ${PROFILE} && source ${PROFILE}${RESET}"
fi

echo ""
echo "${BOLD}Quickstart with AI Agents:${RESET}"
echo "  1. Initialize project vault:   ${CYAN}ironrun setup${RESET}"
echo "  2. Securely store secrets:     ${CYAN}ironrun add OPENAI_API_KEY${RESET}"
echo "  3. Start Claude Code / Codex:  ${CYAN}claude${RESET} (auto-loads .mcp.json)"
echo ""
echo "Need help? Run ${CYAN}ironrun --help${RESET} or visit ${CYAN}https://github.com/${REPO}${RESET}"

