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

## Build & test

```sh
cargo build
cargo test
```

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

## Implementation status

All book-decryption schemes are implemented and unit-tested end-to-end:
**Mobipocket**, **Topaz**, **KFX**, **Adobe ADEPT** (EPUB + PDF), **Barnes &
Noble** (EPUB + PDF), **eReader** (`.pdb` → PMLZ), and **Kobo** (KEPUB). Key
acquisition is real for the offline generators and for Kindle (`.k4i`/`.kinf`/
Android), Adobe (macOS `activation.dat`), and Kobo (device/desktop DB + NIC
MACs) extraction.

What remains stubbed is on-host key *gathering* that isn't reproducible offline:
Kindle local machine-value collection and Adobe Windows live-DPAPI (both need the
target OS + user profile). A downloadable-binary release and a full
scheme/platform support matrix are tracked separately.
