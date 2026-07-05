# flamberge

A standalone Rust CLI for removing DRM from ebooks — a reimplementation of the
[DeDRM_tools](https://github.com/apprenticeharper/DeDRM_tools) Calibre plugins.

> Use only on books you own, where removing DRM for personal use is lawful in
> your jurisdiction.

The scheme-by-scheme algorithm reference this project is built from lives in
[`docs/DEDRM_SCHEMES.md`](docs/DEDRM_SCHEMES.md).

## Workspace layout

| Crate | Role | Status |
|---|---|---|
| `flamberge-crypto` | Shared ciphers: PC1, Topaz, AES, DES, RC4, CRC-32, digests, PBKDF2, RSA | Implemented + tested |
| `flamberge-formats` | Container parsers: PalmDB, TPZ0, KFX-ZIP, ION, OCF/EPUB, PDF, PMLZ | Implemented + tested |
| `flamberge-keys` | Key acquisition: PID gen, B&N/eReader/Kobo offline keygen, platform extraction | Generators + Kindle/Adobe(macOS)/Kobo extraction done; on-host Kindle machine-value gathering & Adobe Windows DPAPI stubbed |
| `flamberge-schemes` | Per-scheme DRM removal, format dispatch | All schemes implemented + tested |
| `flamberge-cli` | The `flamberge` binary (batch mode, `--auto-keys`, `keys` subcommands) | Implemented + tested |

Dependency direction: `crypto` ← `formats`, `keys` ← `schemes` ← `cli`.

## Install

Pick your platform's package manager:

| Manager | Command | Platforms |
| --- | --- | --- |
| **cargo** (crates.io) | `cargo install flamberge-cli` | any (builds from source) |
| **Homebrew** | `brew install kessriga/flamberge/flamberge` | macOS (Apple Silicon), Linux (`x86_64`) |
| **mise** | `mise use -g ubi:kessriga/flamberge` | Linux, macOS, Windows |
| **winget** | `winget install Kessriga.Flamberge` | Windows (`x86_64`) |
| **Chocolatey** | `choco install flamberge` | Windows (`x86_64`) |
| **Arch (AUR)** | `yay -S flamberge-bin` | Linux (`x86_64`) |
| **Debian/Ubuntu** | `dpkg -i flamberge_<ver>_amd64.deb` (from Releases) | Linux (`x86_64`) |
| **Fedora/RHEL** | `rpm -i flamberge-<ver>-1.x86_64.rpm` (from Releases) | Linux (`x86_64`) |

> Some managers are in the process of being registered (see
> [`packaging/README.md`](packaging/README.md)). Until they are live, use the
> pre-built binaries or `cargo install --path` below.

**Pre-built binaries.** Each tagged release attaches an optimized `flamberge`
binary for Linux (`x86_64`), macOS (Apple Silicon), and Windows (`x86_64`),
along with `.deb`/`.rpm` packages and a `SHA256SUMS` file for verification.
Download the archive for your platform from the
[Releases](https://github.com/kessriga/flamberge/releases) page, unpack it, and
put `flamberge` on your `PATH`.

**From source** (needs Rust ≥ 1.85):

```sh
# Install the published CLI from crates.io
cargo install flamberge-cli

# …or install from a local checkout
cargo install --path crates/flamberge-cli

# …or just build/test the workspace in place
cargo build --release   # binary at target/release/flamberge
cargo test
```

Packaging definitions and the release-to-manager automation live under
[`packaging/`](packaging/); every tagged release propagates the new version and
checksums to the managers whose credentials are configured.

## Usage

The scheme is chosen by file extension, then every candidate key is tried. Output
defaults to `<stem>_nodrm.<ext>` next to the input.

```sh
# Decrypt a single book with an explicit key
flamberge decrypt book.azw  --serial B001234567890123
flamberge decrypt book.epub --adept-key adobekey.der
flamberge decrypt book.kepub.epub --kobo-db KoboReader.sqlite

# Batch: pass several files or a whole directory; a per-file OK/SKIP/FAIL summary
# is printed and the exit code is non-zero if any file failed.
flamberge decrypt ~/Books --output-dir ~/Books/nodrm

# Best-effort: discover local Adobe/Kobo/Kindle keys on this host first
flamberge decrypt book.epub --auto-keys

# Offline key generators
flamberge keys ignoble --name "John Smith" --cc "1234 5678 9012 3456"
flamberge keys ereader --name "Jane Doe" --cc "4111 1111 1111 1111"
flamberge keys eink-pid --serial B001234567890123

# Extract keys from local DRM-app state
flamberge keys adobe                 # macOS Adobe Digital Editions activation.dat
flamberge keys kobo                  # Kobo device / desktop DB + NIC MACs
flamberge keys kindle --k4i my.k4i   # decode a Kindle .k4i / .kinf / Android artifact
```

## Supported schemes

Decryption itself is pure Rust and runs on every platform; the "key source"
column is where the matching key comes from. All schemes are implemented and
unit-tested end-to-end.

| Scheme | Input | Output | Key source |
|---|---|---|---|
| Mobipocket | `.azw` / `.mobi` / `.prc` | `.mobi` | Kindle serial / PID, or `--k4i` / `--android` |
| Topaz | `.azw1` / `.tpz` | `.tpz` | Kindle serial / PID |
| KFX | `.kfx-zip` | `.kfx-zip` | Kindle serial / PID |
| Adobe ADEPT | `.epub` | `.epub` | Adobe private license key (`activation.dat`) |
| Adobe ADEPT | `.pdf` | `.pdf` | Adobe private license key (`activation.dat`) |
| Barnes & Noble | `.epub` | `.epub` | B&N key from name + credit-card (`keys ignoble`) |
| Barnes & Noble | `.pdf` | `.pdf` | B&N key from name + credit-card (`keys ignoble`) |
| eReader | `.pdb` | `.pmlz` | eReader key from name + credit-card (`keys ereader`) |
| Kobo | `.kepub.epub` | `.epub` | Kobo user key (device / desktop DB + NIC MACs) |

## Key extraction by platform

Offline generators (`keys ignoble` / `ereader` / `eink-pid`) and offline artifact
decoding are OS-independent. On-host extraction that reads another app's local
state depends on the platform:

| Source | Linux | macOS | Windows |
|---|---|---|---|
| Kindle `.k4i` / `.kinf` / Android artifact (offline decode) | ✅ | ✅ | ✅ |
| Kindle on-host machine-value gathering | ⛔ | ⛔ | ⛔ |
| Adobe ADEPT `activation.dat` | — | ✅ | ⛔ (live DPAPI) |
| Kobo device / desktop DB + NIC MACs | ✅ | ✅ | ✅ |

⛔ marks paths that are not reproducible offline — they need the target OS plus
the user's profile (Windows DPAPI, host-specific machine values). The decryption
algorithms for those paths are implemented and tested; only the live gathering
is stubbed.

## License

MIT — see [`LICENSE`](LICENSE).
