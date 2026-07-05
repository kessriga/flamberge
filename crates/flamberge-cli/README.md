# flamberge

`flamberge` is a standalone command-line tool that removes DRM from ebooks,
reimplementing the [DeDRM_tools](https://github.com/noDRM/DeDRM_tools) Calibre
plugins in Rust.

It supports the **Mobipocket**, **Topaz**, **KFX**, **Adobe ADEPT** (EPUB + PDF),
**Barnes & Noble** (EPUB + PDF), **eReader** (`.pdb`), and **Kobo KEPUB** schemes,
plus offline key generators and on-host key extraction for Kindle, Adobe, and Kobo.

## Install

```sh
cargo install flamberge      # installs the `flamberge` binary
```

Pre-built binaries, Homebrew, mise, winget, Chocolatey and Linux distro packages
are also available — see the [project README](https://github.com/kessriga/flamberge#install)
for the full install matrix.

## Usage

```sh
# Decrypt a single book with an explicit key
flamberge decrypt book.azw  --serial B001234567890123
flamberge decrypt book.epub --adept-key adobekey.der

# Batch a directory; discover local keys first
flamberge decrypt ~/Books --output-dir ~/Books/nodrm --auto-keys
```

See `flamberge --help` and the [project documentation](https://github.com/kessriga/flamberge)
for the complete command reference.

## License

MIT — see [LICENSE](https://github.com/kessriga/flamberge/blob/main/LICENSE).
