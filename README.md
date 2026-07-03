# dedrm

A standalone Rust CLI for removing DRM from ebooks — a reimplementation of the
[DeDRM_tools](https://github.com/apprenticeharper/DeDRM_tools) Calibre plugins.

> Use only on books you own, where removing DRM for personal use is lawful in
> your jurisdiction.

The scheme-by-scheme algorithm reference this project is built from lives in
[`docs/DEDRM_SCHEMES.md`](docs/DEDRM_SCHEMES.md).

## Workspace layout

| Crate | Role | Status |
|---|---|---|
| `dedrm-crypto` | Shared ciphers: PC1, Topaz, AES, DES, RC4, CRC-32, digests, PBKDF2 | Implemented + tested |
| `dedrm-formats` | Container parsers: PalmDB, TPZ0, KFX-ZIP, ION, OCF/EPUB, PDF | PalmDB done; rest stubbed |
| `dedrm-keys` | Key acquisition: PID gen, B&N/eReader/Kobo offline keygen, platform extraction | Offline generators done; extraction stubbed |
| `dedrm-schemes` | Per-scheme DRM removal, format dispatch | Trait + dispatch wired; schemes stubbed |
| `dedrm-cli` | The `dedrm` binary | Wired |

Dependency direction: `crypto` ← `formats`, `keys` ← `schemes` ← `cli`.

## Build & test

```sh
cargo build
cargo test
```

## Usage

```sh
# Decrypt (schemes are stubbed for now — this reports "not yet implemented")
dedrm decrypt book.azw --serial B001234567890123
dedrm decrypt book.epub --adept-key adobekey.der

# Key helpers that already work offline:
dedrm keys ignoble --name "John Smith" --cc "1234 5678 9012 3456"
dedrm keys ereader --name "Jane Doe" --cc "4111 1111 1111 1111"
dedrm keys eink-pid --serial B001234567890123
```

## Implementation status

The crypto foundation and the offline key generators are real and unit-tested.
Each scheme's container/decryption logic is a documented stub (`todo!`-style
`Unimplemented` errors) pointing at the relevant `docs/DEDRM_SCHEMES.md` section,
ready to be filled in one scheme at a time. A good first vertical slice is
**Mobipocket** (§2): PalmDB + PC1 are already available, so only the record and
voucher logic remains.
