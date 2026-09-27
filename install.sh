#!/bin/sh
#
# ironrun installer
# =================
#
# Installs a PINNED ironrun release and verifies it before touching your
# system. Nothing is installed unless all three checks pass:
#
#   1. checksums.txt is Sigstore-verified (keyless cosign, GitHub OIDC
#      identity of the ironrun release workflow);
#   2. the tarball's SHA-256 matches checksums.txt          (fail closed);
#   3. the tarball's own Sigstore bundle verifies           (fail closed).
#
# Recommended (pinned) usage — download the installer that shipped with the
# release you want, so the script itself is also pinned:
#
#   curl -fsSL https://github.com/generalized-labs/ironrun/releases/download/vX.Y.Z/install.sh -o /tmp/install-ironrun.sh
#   sh /tmp/install-ironrun.sh --version vX.Y.Z
#
# Or let the script resolve the latest tagged release (still a pinned tag):
#
#   curl -fsSL https://ironrun.dev/install.sh | sh
#
# Flags (also settable via the IRONRUN_* env vars below):
#
#   --version vX.Y.Z   install this exact release (env: IRONRUN_VERSION)
#   --dir PATH         install into PATH          (env: IRONRUN_INSTALL_DIR)
#   --uninstall        remove the ironrun binary instead of installing
#   --purge            with --uninstall: also delete ~/.ironrun
#                      (project registry + encrypted secret stores).
#                      Requires --yes when stdin is not a terminal.
#   --yes, -y          confirm destructive prompts non-interactively
#   --help, -h         this help
#
# ironrun collects no telemetry; see docs/telemetry.md.
#
set -eu

REPO="generalized-labs/ironrun"
BINARY="ironrun"

# Pinned cosign used to verify Sigstore bundles when no `cosign` is on PATH.
# Hashes were captured from the official sigstore/cosign release page over
# TLS; bump together with COSIGN_VERSION.
COSIGN_VERSION="v2.4.3"
#   cosign-darwin-amd64
COSIGN_SHA256_DARWIN_X86_64="98a3bfd691f42c6a5b721880116f89210d8fdff61cc0224cd3ef2f8e55a466fb"
#   cosign-darwin-arm64
COSIGN_SHA256_DARWIN_ARM64="edfc761b27ced77f0f9ca288ff4fac7caa898e1e9db38f4dfdf72160cdf8e638"
#   cosign-linux-amd64
COSIGN_SHA256_LINUX_X86_64="caaad125acef1cb81d58dcdc454a1e429d09a750d1e9e2b3ed1aed8964454708"
#   cosign-linux-arm64
COSIGN_SHA256_LINUX_ARM64="bd0f9763bca54de88699c3656ade2f39c9a1c7a2916ff35601caf23a79be0629"

# Expected keyless Sigstore identity: the ironrun release workflow signing
# from a tag (see .github/workflows/release.yml).
SIGSTORE_IDENTITY_REGEXP="^https://github\\.com/generalized-labs/ironrun/\\.github/workflows/release\\.yml@refs/tags/"
SIGSTORE_OIDC_ISSUER="https://token.actions.githubusercontent.com"

MODE="install"
VERSION="${IRONRUN_VERSION:-}"
INSTALL_DIR="${IRONRUN_INSTALL_DIR:-}"
PURGE=0
YES=0

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

info() {
  printf '%s\n' "$*"
}

usage() {
  sed -n '2,/^set -eu/p' "$0" | sed 's/^# \{0,1\}//'
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "need sha256sum or shasum to verify downloads"
  fi
}

fetch() {
  # fetch <url> <dest> — fail closed on any download problem.
  if ! curl -fsSL --retry 2 --proto '=https' --tlsv1.2 "$1" -o "$2"; then
    die "download failed: $1"
  fi
}

check_version() {
  # Refuse anything that is not a plain release tag (it ends up in URLs).
  # End-anchored: a trailing `*` in a case pattern would admit `v1.2.3;evil`.
  if ! printf '%s' "$1" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'; then
    die "refusing suspicious version string: $1"
  fi
}

# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------

while [ $# -gt 0 ]; do
  case "$1" in
    --uninstall) MODE="uninstall"; shift ;;
    --purge) PURGE=1; shift ;;
    --yes|-y) YES=1; shift ;;
    --version)
      [ $# -ge 2 ] || die "--version needs a value"
      VERSION="$2"; shift 2 ;;
    --version=*) VERSION="${1#--version=}"; shift ;;
    --dir)
      [ $# -ge 2 ] || die "--dir needs a value"
      INSTALL_DIR="$2"; shift 2 ;;
    --dir=*) INSTALL_DIR="${1#--dir=}"; shift ;;
    --help|-h) usage; exit 0 ;;
    --) shift; break ;;
    -*) die "unknown flag: $1 (see --help)" ;;
    *) die "unexpected argument: $1 (see --help)" ;;
  esac
done

# ---------------------------------------------------------------------------
# uninstall
# ---------------------------------------------------------------------------

do_uninstall() {
  removed=0
  # Candidate install locations: explicit dir, the usual system/user dirs,
  # and wherever the shell currently finds ironrun.
  for candidate in \
      "${INSTALL_DIR:+$INSTALL_DIR/$BINARY}" \
      "/usr/local/bin/$BINARY" \
      "$HOME/.local/bin/$BINARY" \
      "$(command -v "$BINARY" 2>/dev/null || true)"; do
    [ -n "$candidate" ] || continue
    [ -f "$candidate" ] || continue
    if [ -w "$candidate" ]; then
      rm -f "$candidate" || die "could not remove $candidate"
    elif command -v sudo >/dev/null 2>&1; then
      sudo rm -f "$candidate" || die "could not remove $candidate (sudo failed)"
    else
      die "cannot remove $candidate (not writable, no sudo)"
    fi
    info "removed $candidate"
    removed=1
  done
  [ "$removed" = "1" ] || info "no ironrun binary found; nothing to remove"

  if [ "$PURGE" = "1" ]; then
    target="$HOME/.ironrun"
    if [ -d "$target" ]; then
      info ""
      info "WARNING: --purge permanently deletes $target"
      info "  (project registry, encrypted secret stores, pending approvals)."
      info "  There is no recovery and no plaintext export (by design —"
      info "  values never leave the vault). Re-create any secrets from"
      info "  their original sources after reinstalling."
      if [ "$YES" != "1" ]; then
        [ -t 0 ] || die "--purge needs --yes when stdin is not a terminal"
        printf 'Type DELETE to continue: '
        read -r answer
        [ "$answer" = "DELETE" ] || die "aborted; binary removal (above) still stands"
      fi
      rm -rf "$target" || die "could not remove $target"
      info "removed $target"
    else
      info "no $target directory; nothing to purge"
    fi
    info ""
    info "Note: the npm launcher cache (~/.cache/ironrun) is left in place;"
    info "remove it manually if you also used npx @generalized-labs/ironrun."
  elif [ "$MODE" = "uninstall" ]; then
    info ""
    info "Kept $HOME/.ironrun (projects, secrets). Re-run with --purge to delete it."
  fi
  exit 0
}

[ "$MODE" = "uninstall" ] && do_uninstall

# ---------------------------------------------------------------------------
# install
# ---------------------------------------------------------------------------

need_cmd curl
need_cmd tar
need_cmd awk
need_cmd mktemp

info ""
info "  _                           "
info " (_) _ __ ___  _ __  _ __ _   _ _ __  "
info " | | '__/ _ \\ | '_ \\| '__| | | | '_ \\ "
info " | | | | (_) | | | | |  | |_| | | | |"
info " |_|_|  \\___/|_| |_|_|   \\__,_|_| |_|"
info ""
info "Shield your secrets from AI coding agents (Claude Code, Codex, Cursor)."
info ""

# 1. Detect OS & architecture.
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$OS" in
  linux*)  OS="Linux" ;;
  darwin*) OS="Darwin" ;;
  *)       die "unsupported operating system: $OS" ;;
esac
case "$ARCH" in
  x86_64|amd64) ARCH="x86_64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *)            die "unsupported architecture: $ARCH" ;;
esac
PLATFORM_KEY="${OS}_${ARCH}"

# 2. Resolve a PINNED version (a release tag, never a moving branch).
if [ -z "$VERSION" ]; then
  info "Resolving latest release version... "
  VERSION="$(curl -fsSL --proto '=https' --tlsv1.2 \
      -H "Accept: application/vnd.github+json" \
      "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
      | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' || true)"
  [ -n "$VERSION" ] || die "could not determine the latest release; set IRONRUN_VERSION=vX.Y.Z (or --version vX.Y.Z) explicitly"
  info "latest release: $VERSION"
fi
check_version "$VERSION"

TARBALL="${BINARY}_${PLATFORM_KEY}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

info "Installing ironrun ${VERSION} for ${PLATFORM_KEY}..."
info ""

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# 3. Fetch release files.
info "* downloading ${TARBALL}"
fetch "${BASE_URL}/${TARBALL}" "$TMP/$TARBALL"
info "* downloading checksums.txt (+ Sigstore bundle)"
fetch "${BASE_URL}/checksums.txt" "$TMP/checksums.txt"
fetch "${BASE_URL}/checksums.txt.sigstore.json" "$TMP/checksums.txt.sigstore.json"
info "* downloading ${TARBALL}.sigstore.json"
fetch "${BASE_URL}/${TARBALL}.sigstore.json" "$TMP/$TARBALL.sigstore.json"

# 4. Provision cosign: prefer the user's own, else fetch the PINNED cosign
#    release binary and verify its SHA-256 against the hash baked into this
#    script before executing it.
if command -v cosign >/dev/null 2>&1; then
  COSIGN="cosign"
  info "* using system cosign: $(command -v cosign)"
else
  # Cosign release assets use "amd64", not "x86_64" (cosign-linux-amd64, etc.).
  COSIGN_FILE="cosign-$(printf '%s' "$PLATFORM_KEY" | tr '[:upper:]' '[:lower:]' | sed 's/_/-/;s/x86_64/amd64/')"
  case "$PLATFORM_KEY" in
    Linux_x86_64)  COSIGN_SHA256="$COSIGN_SHA256_LINUX_X86_64" ;;
    Linux_arm64)   COSIGN_SHA256="$COSIGN_SHA256_LINUX_ARM64" ;;
    Darwin_x86_64) COSIGN_SHA256="$COSIGN_SHA256_DARWIN_X86_64" ;;
    Darwin_arm64)  COSIGN_SHA256="$COSIGN_SHA256_DARWIN_ARM64" ;;
  esac
  info "* fetching pinned cosign ${COSIGN_VERSION} (${COSIGN_FILE})"
  fetch "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/${COSIGN_FILE}" \
        "$TMP/cosign"
  ACTUAL="$(sha256_of "$TMP/cosign")"
  [ "$ACTUAL" = "$COSIGN_SHA256" ] \
    || die "cosign SHA-256 mismatch (expected ${COSIGN_SHA256}, got ${ACTUAL}); refusing to verify with an untrusted tool"
  chmod 755 "$TMP/cosign"
  COSIGN="$TMP/cosign"
  info "* cosign ${COSIGN_VERSION} verified against pinned hash"
fi

# 5. Sigstore-verify checksums.txt (fail closed).
info "* verifying checksums.txt signature (Sigstore)..."
"$COSIGN" verify-blob \
  --bundle "$TMP/checksums.txt.sigstore.json" \
  --certificate-identity-regexp "$SIGSTORE_IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$SIGSTORE_OIDC_ISSUER" \
  "$TMP/checksums.txt" >/dev/null \
  || die "checksums.txt Sigstore verification FAILED; refusing to install"

# 6. SHA-256-verify the tarball against the now-trusted checksums.txt
#    (fail closed — a missing entry is a hard failure).
info "* verifying ${TARBALL} checksum..."
EXPECTED="$(awk -v file="$TARBALL" '$2 == file { print $1 }' "$TMP/checksums.txt")"
[ -n "$EXPECTED" ] || die "no checksum entry for ${TARBALL} in checksums.txt; refusing to install"
ACTUAL="$(sha256_of "$TMP/$TARBALL")"
[ "$ACTUAL" = "$EXPECTED" ] \
  || die "checksum MISMATCH for ${TARBALL} (expected ${EXPECTED}, got ${ACTUAL}); refusing to install"
info "  checksum OK"

# 7. Sigstore-verify the tarball bundle itself (fail closed).
info "* verifying ${TARBALL} signature (Sigstore)..."
"$COSIGN" verify-blob \
  --bundle "$TMP/$TARBALL.sigstore.json" \
  --certificate-identity-regexp "$SIGSTORE_IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$SIGSTORE_OIDC_ISSUER" \
  "$TMP/$TARBALL" >/dev/null \
  || die "${TARBALL} Sigstore verification FAILED; refusing to install"
info "  signature OK — release is authentic"

# 8. Extract.
tar -xzf "$TMP/$TARBALL" -C "$TMP"

# 9. Determine destination.
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

info ""
info "Successfully installed ironrun ${VERSION} to ${INSTALL_DIR}/${BINARY}"
info "  verified: Sigstore signature + SHA-256 checksum (fail-closed)"

# 10. Check PATH and offer profile guidance.
if ! printf '%s' "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
  info ""
  info "Notice: ${INSTALL_DIR} is not in your \$PATH."
  SHELL_NAME="$(basename "${SHELL:-sh}")"
  case "$SHELL_NAME" in
    zsh)  PROFILE="$HOME/.zshrc" ;;
    bash) PROFILE="$HOME/.bashrc" ;;
    fish) PROFILE="$HOME/.config/fish/config.fish" ;;
    *)    PROFILE="$HOME/.profile" ;;
  esac
  info "Add it with:"
  info "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ${PROFILE} && source ${PROFILE}"
fi

info ""
info "Verify the install:"
info "  ironrun version -v    # prints version, commit hash, build date"
info ""
info "Quickstart:"
info "  1. Initialize project vault:   ironrun setup"
info "  2. Securely store secrets:     ironrun add OPENAI_API_KEY"
info "  3. Start Claude Code / Codex:  claude (auto-loads .mcp.json)"
info ""
info "Uninstall later with:"
info "  sh /tmp/install-ironrun.sh --uninstall            # removes the binary"
info "  sh /tmp/install-ironrun.sh --uninstall --purge    # also deletes ~/.ironrun"
info ""
info "Need help? Run ironrun --help or visit https://github.com/${REPO}"
