# Homebrew formula for ironrun.
#
# TAP LAYOUT
# ----------
# This file is a reference copy. goreleaser generates and publishes the real
# formula to `generalized-labs/homebrew-tap` (see .goreleaser.yml), and users
# install with:
#
#   brew tap generalized-labs/tap
#   brew install ironrun
#
# PER-RELEASE MAINTENANCE
# -----------------------
# For each release tag vX.Y.Z:
#   1. Set `version` below to X.Y.Z (no leading v).
#   2. Replace every "TODO_<PLATFORM>" sha256 with the matching line from the
#      release's checksums.txt (which is itself Sigstore-signed; see
#      docs/INSTALL.md). Artifact names:
#        ironrun_Darwin_x86_64.tar.gz / ironrun_Darwin_arm64.tar.gz
#        ironrun_Linux_x86_64.tar.gz  / ironrun_Linux_arm64.tar.gz
#   3. Replace every "TODO_<PLATFORM>_BUNDLE" sha256 with the SHA-256 of the
#      corresponding <artifact>.sigstore.json bundle asset, e.g.
#      ironrun_Darwin_arm64.tar.gz.sigstore.json (note: the bundle name is the
#      artifact name plus ".sigstore.json").
#
# The install step verifies the Sigstore bundle with cosign (fail closed)
# *before* installing the binary; the url/sha256 pins provide the standard
# Homebrew integrity check on top.

class Ironrun < Formula
  desc "Local encrypted environment workspace for humans and AI coding agents"
  homepage "https://github.com/generalized-labs/ironrun"
  # Set to the release version (no leading v), e.g. "0.4.1".
  version "0.0.0-UNRELEASED"

  on_macos do
    on_arm do
      url "https://github.com/generalized-labs/ironrun/releases/download/v#{version}/ironrun_Darwin_arm64.tar.gz"
      sha256 "TODO_DARWIN_ARM64"

      resource "sigstore-bundle" do
        url "https://github.com/generalized-labs/ironrun/releases/download/v#{version}/ironrun_Darwin_arm64.tar.gz.sigstore.json"
        sha256 "TODO_DARWIN_ARM64_BUNDLE"
      end
    end
    on_intel do
      url "https://github.com/generalized-labs/ironrun/releases/download/v#{version}/ironrun_Darwin_x86_64.tar.gz"
      sha256 "TODO_DARWIN_X86_64"

      resource "sigstore-bundle" do
        url "https://github.com/generalized-labs/ironrun/releases/download/v#{version}/ironrun_Darwin_x86_64.tar.gz.sigstore.json"
        sha256 "TODO_DARWIN_X86_64_BUNDLE"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/generalized-labs/ironrun/releases/download/v#{version}/ironrun_Linux_arm64.tar.gz"
      sha256 "TODO_LINUX_ARM64"

      resource "sigstore-bundle" do
        url "https://github.com/generalized-labs/ironrun/releases/download/v#{version}/ironrun_Linux_arm64.tar.gz.sigstore.json"
        sha256 "TODO_LINUX_ARM64_BUNDLE"
      end
    end
    on_intel do
      url "https://github.com/generalized-labs/ironrun/releases/download/v#{version}/ironrun_Linux_x86_64.tar.gz"
      sha256 "TODO_LINUX_X86_64"

      resource "sigstore-bundle" do
        url "https://github.com/generalized-labs/ironrun/releases/download/v#{version}/ironrun_Linux_x86_64.tar.gz.sigstore.json"
        sha256 "TODO_LINUX_X86_64_BUNDLE"
      end
    end
  end

  depends_on "cosign"

  def install
    # Verify the Sigstore bundle for the downloaded tarball BEFORE
    # installing anything. cached_download is the sha256-pinned tarball.
    # The staged bundle keeps the resource URL's basename
    # (ironrun_<OS>_<arch>.tar.gz.sigstore.json) — derive it from the URL
    # rather than hardcoding it.
    bundle_name = resource("sigstore-bundle").url.split("/").last
    resource("sigstore-bundle").stage do
      bundle = Pathname.pwd/bundle_name
      system "cosign", "verify-blob",
             "--bundle", bundle.to_s,
             "--certificate-identity-regexp",
             "^https://github\\.com/generalized-labs/ironrun/\\.github/workflows/release\\.yml@refs/tags/",
             "--certificate-oidc-issuer",
             "https://token.actions.githubusercontent.com",
             cached_download.to_s
    end

    bin.install "ironrun"
  end

  test do
    # `version` prints the stamped release version; -v adds commit + date.
    assert_match version.to_s, shell_output("#{bin}/ironrun version")
  end
end
