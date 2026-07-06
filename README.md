# flamberge

**Remove DRM from ebooks you own — a fast, standalone Rust CLI.**

[![CI](https://github.com/kessriga/flamberge/actions/workflows/ci.yml/badge.svg)](https://github.com/kessriga/flamberge/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)

flamberge turns a locked book you bought — from Kindle, Kobo, Adobe/library
loans, Barnes & Noble, or eReader — into a plain, standard file (`.epub`,
`.mobi`, `.pdf`, …) that opens in any reader and is yours to keep and back up.
It's a from-scratch reimplementation of the
[DeDRM_tools](https://github.com/apprenticeharper/DeDRM_tools) Calibre plugins as
a single self-contained binary — no Calibre, no Python, no plugins.

> **Use only on books you own,** where removing DRM for personal use is lawful in
> your jurisdiction.

**New to any of this?** The [**User Guide**](docs/GUIDE.md) explains — from zero —
what DRM is, where your key comes from, and how to unlock your books store by
store. Start there if the terms "DRM" or "key" are unfamiliar.

## Why flamberge

- **One binary, no runtime.** A single static executable — no Calibre install,
  no Python, no plugin wrangling.
- **Every major store.** Kindle (Mobipocket/Topaz/KFX), Kobo, Adobe ADEPT
  (EPUB + PDF), Barnes & Noble (EPUB + PDF), and eReader.
- **Finds your keys for you.** `--auto-keys` pulls local Adobe/Kobo/Kindle keys
  off this machine; dedicated `keys` subcommands generate or extract them.
- **Batch-friendly.** Point it at a whole folder and get a per-file summary.
- **Private and safe.** Runs entirely offline, never touches your original file
  (output is always a new file), and is fully open-source and auditable.
- **Cross-platform.** Decryption is pure Rust on Linux, macOS, and Windows.

## Quickstart

```sh
# 1. Install (see Install below for every option)
cargo install flamberge

# 2. Unlock a book, supplying your key
flamberge decrypt book.azw  --serial B001234567890123   # Kindle device serial
flamberge decrypt book.epub --auto-keys                  # Adobe / library (finds your key)

# 3. Done — the unlocked book is written next to the original as book_nodrm.<ext>
```

Not sure where *your* key comes from? That's exactly what the
[User Guide](docs/GUIDE.md#part-3--walkthroughs-by-store) walks through, one
store at a time.

## Install

Pick your platform's package manager:

| Manager | Command | Platforms |
| --- | --- | --- |
| **cargo** (crates.io) | `cargo install flamberge` | any (builds from source) |
| **Nix** | `nix profile install github:kessriga/flamberge` (or `nix run github:kessriga/flamberge`) | Linux, macOS |
| **Homebrew** | `brew install kessriga/flamberge/flamberge` | macOS (Apple Silicon), Linux (`x86_64`) |
| **mise** | `mise use -g ubi:kessriga/flamberge` | Linux, macOS, Windows |
| **winget** | `winget install Kessriga.Flamberge` | Windows (`x86_64`) |
| **Scoop** | `scoop bucket add flamberge https://github.com/kessriga/scoop-flamberge` then `scoop install flamberge` | Windows (`x86_64`) |
| **Chocolatey** | `choco install flamberge` | Windows (`x86_64`) |
| **Arch (AUR)** | `yay -S flamberge-bin` | Linux (`x86_64`) |
| **Debian/Ubuntu** | `dpkg -i flamberge_<ver>_amd64.deb` (from Releases) | Linux (`x86_64`) |
| **Fedora/RHEL** | `rpm -i flamberge-<ver>-1.x86_64.rpm` (from Releases) | Linux (`x86_64`) |

> **Live now:** Nix, Scoop, mise, and the pre-built binaries (incl. `.deb`/`.rpm`).
> The crates.io, Homebrew, winget, Chocolatey, and AUR entries are still being
> registered (see [`packaging/README.md`](packaging/README.md)) — until each is
> live, use one of the above or build from source below.

**Pre-built binaries.** Every tagged release attaches an optimized `flamberge`
binary for Linux (`x86_64`), macOS (Apple Silicon), and Windows (`x86_64`), plus
`.deb`/`.rpm` packages and a `SHA256SUMS` file for verification. Grab the archive
for your platform from the
[Releases](https://github.com/kessriga/flamberge/releases) page, unpack it, and
put `flamberge` on your `PATH`.

**From source** (needs Rust ≥ 1.85):

```sh
cargo install flamberge                     # from crates.io
cargo install --path crates/flamberge-cli   # from a local checkout
cargo build --release                        # or just build in place → target/release/flamberge
```

## Usage

The scheme is chosen automatically by file extension, then every candidate key is
tried. Output defaults to `<name>_nodrm.<ext>` next to the input; your original is
never modified.

```sh
# Decrypt a single book with an explicit key
flamberge decrypt book.azw        --serial B001234567890123
flamberge decrypt book.epub       --adept-key adobekey.der
flamberge decrypt book.kepub.epub --kobo-db KoboReader.sqlite

# Best-effort: discover local Adobe/Kobo/Kindle keys on this host first
flamberge decrypt book.epub --auto-keys

# Batch: several files or a whole directory → per-file OK/SKIP/FAIL summary
flamberge decrypt ~/Books --output-dir ~/Books/nodrm --auto-keys

# Generate keys offline (from your name + card, or a Kindle serial)
flamberge keys ignoble --name "Jane Q. Reader" --cc "1234 5678 9012 3456"
flamberge keys ereader --name "Jane Q. Reader" --cc "4111 1111 1111 1111"
flamberge keys eink-pid --serial B001234567890123

# Extract keys from local DRM-app state
flamberge keys adobe                  # macOS Adobe Digital Editions activation.dat
flamberge keys kobo                   # Kobo device / desktop DB + network-card IDs
flamberge keys kindle --k4i my.k4i    # decode a Kindle .k4i / .kinf / Android artifact
```

Run `flamberge --help` or `flamberge <command> --help` for the full option list.
For a guided, store-by-store walkthrough, see the [User Guide](docs/GUIDE.md).

## Supported stores & formats

Decryption is pure Rust and runs on every platform; all schemes are implemented
and tested end-to-end. "Where the key comes from" is covered per store in the
[User Guide](docs/GUIDE.md#part-3--walkthroughs-by-store).

| Store | Format in → out | Where your key comes from |
|---|---|---|
| **Kindle** | `.azw` `.mobi` `.prc` → `.mobi`; `.azw1` `.tpz` → `.tpz`; `.kfx-zip` → `.kfx-zip` | Kindle serial / PID, or `--k4i` / `--android` |
| **Adobe & library** | `.epub` → `.epub`; `.pdf` → `.pdf` | Adobe key from `activation.dat` (`keys adobe`) |
| **Barnes & Noble** | `.epub` → `.epub`; `.pdf` → `.pdf` | Name + credit-card (`keys ignoble`) |
| **eReader** | `.pdb` → `.pmlz` | Name + credit-card (`keys ereader`) |
| **Kobo** | `.kepub.epub` → `.epub` | Kobo user key + library DB (`keys kobo` / `--kobo-db`) |

**Key extraction by platform.** Decryption works everywhere; only the *automatic*
gathering of another app's local key state is platform-dependent — notably, the
Adobe key auto-extracts on macOS but must be exported to a `.der` on Windows. The
full matrix is in the
[User Guide](docs/GUIDE.md#platform-support-at-a-glance).

## How it works

flamberge is a Cargo workspace; the CLI is a thin driver over layered libraries.

| Crate | Role |
|---|---|
| `flamberge-crypto` | Shared ciphers: PC1, Topaz, AES, DES, RC4, CRC-32, digests, PBKDF2, RSA |
| `flamberge-formats` | Container parsers: PalmDB, TPZ0, KFX-ZIP, ION, OCF/EPUB, PDF, PMLZ |
| `flamberge-keys` | Key acquisition: PID gen, B&N/eReader/Kobo keygen, platform extraction |
| `flamberge-schemes` | Per-scheme DRM removal + format dispatch |
| `flamberge` | The `flamberge` binary (in `crates/flamberge-cli`) |

Dependency direction: `crypto` ← `formats`, `keys` ← `schemes` ← `cli`. The
byte-level algorithm reference for every scheme lives in
[`docs/DEDRM_SCHEMES.md`](docs/DEDRM_SCHEMES.md).

Build and test the workspace:

```sh
cargo build            # or cargo build --release
cargo test             # unit + cross-scheme integration tests
```

## Documentation

- [**User Guide**](docs/GUIDE.md) — start here if you're new: what DRM is, and how
  to unlock your books store by store.
- [**Scheme reference**](docs/DEDRM_SCHEMES.md) — byte-level spec for every DRM
  scheme (offsets, constants, key derivation).
- [**Packaging runbook**](packaging/README.md) — how releases propagate to package
  managers.

## License

MIT — see [`LICENSE`](LICENSE).
