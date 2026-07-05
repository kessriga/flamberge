# Homebrew formula for flamberge.
#
# This file is the source of truth for the `kessriga/homebrew-flamberge` tap
# (repo `kessriga/homebrew-flamberge`, path `Formula/flamberge.rb`). It installs
# the prebuilt release binary rather than compiling from source. The url + sha256
# pairs are regenerated for each tag by packaging/scripts/update-homebrew-formula.sh.
#
# Once the tap exists:  brew install kessriga/flamberge/flamberge
class Flamberge < Formula
  desc "Command-line DRM removal for ebooks (DeDRM_tools, reimplemented in Rust)"
  homepage "https://github.com/kessriga/flamberge"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/kessriga/flamberge/releases/download/v0.1.0/flamberge-v0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "084e6aa2c3ae01dfabde4090cd274ca7e4ae897665e576f3110139f022b954ab"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/kessriga/flamberge/releases/download/v0.1.0/flamberge-v0.1.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "b01bbff843eca2dc3da97507333b8e22501a17f6a22b190f3fe0b371fedf89a8"
    end
  end

  def install
    # The tarball unpacks to a single flamberge-<version>-<target>/ directory;
    # Homebrew changes into it automatically before `install` runs.
    bin.install "flamberge"
  end

  test do
    assert_match "flamberge", shell_output("#{bin}/flamberge --help")
  end
end
