#!/usr/bin/env bash
# Regenerate packaging/homebrew/flamberge.rb for a given release tag.
#
# Downloads the macOS-arm64 and Linux-x86_64 release tarballs for the tag,
# computes their SHA256s, and rewrites the formula. Idempotent: re-running for
# the same tag reproduces the identical file. Used both locally and by the
# `homebrew` job in .github/workflows/package-managers.yml.
#
# Usage: packaging/scripts/update-homebrew-formula.sh v0.1.0 [output.rb]
set -euo pipefail

tag="${1:?usage: update-homebrew-formula.sh <tag> [output-path]}"
version="${tag#v}"
repo="${FLAMBERGE_REPO:-kessriga/flamberge}"
out="${2:-$(cd "$(dirname "$0")/.." && pwd)/homebrew/flamberge.rb}"

base="https://github.com/${repo}/releases/download/${tag}"
mac_asset="flamberge-${tag}-aarch64-apple-darwin.tar.gz"
linux_asset="flamberge-${tag}-x86_64-unknown-linux-gnu.tar.gz"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Prefer the checksums already published on the release; fall back to hashing
# the downloaded tarballs directly.
sha_for() {
  local asset="$1"
  curl -fsSL "${base}/${asset}" -o "${tmp}/${asset}"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${tmp}/${asset}" | cut -d' ' -f1
  else
    shasum -a 256 "${tmp}/${asset}" | cut -d' ' -f1
  fi
}

mac_sha="$(sha_for "$mac_asset")"
linux_sha="$(sha_for "$linux_asset")"

cat > "$out" <<EOF
# Homebrew formula for flamberge.
#
# This file is the source of truth for the \`kessriga/homebrew-flamberge\` tap
# (repo \`kessriga/homebrew-flamberge\`, path \`Formula/flamberge.rb\`). It installs
# the prebuilt release binary rather than compiling from source. The url + sha256
# pairs are regenerated for each tag by packaging/scripts/update-homebrew-formula.sh.
#
# Once the tap exists:  brew install kessriga/flamberge/flamberge
class Flamberge < Formula
  desc "Command-line DRM removal for ebooks (DeDRM_tools, reimplemented in Rust)"
  homepage "https://github.com/${repo}"
  version "${version}"
  license "MIT"

  on_macos do
    on_arm do
      url "${base}/${mac_asset}"
      sha256 "${mac_sha}"
    end
  end

  on_linux do
    on_intel do
      url "${base}/${linux_asset}"
      sha256 "${linux_sha}"
    end
  end

  def install
    # The tarball unpacks to a single flamberge-<version>-<target>/ directory;
    # Homebrew changes into it automatically before \`install\` runs.
    bin.install "flamberge"
  end

  test do
    assert_match "flamberge", shell_output("#{bin}/flamberge --help")
  end
end
EOF

echo "Wrote $out"
echo "  macOS-arm64:  $mac_sha"
echo "  Linux-x86_64: $linux_sha"
