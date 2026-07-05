# homebrew-flamberge

A [Homebrew](https://brew.sh) tap for
[**flamberge**](https://github.com/kessriga/flamberge) — a command-line tool that
removes DRM from ebooks, reimplementing the DeDRM_tools Calibre plugins in Rust.

## Install

```sh
brew install kessriga/flamberge/flamberge
```

Or tap first, then install:

```sh
brew tap kessriga/flamberge
brew install flamberge
```

Prebuilt binaries are installed for macOS (Apple Silicon) and Linux (`x86_64`).

## Updating

```sh
brew update && brew upgrade flamberge
```

## Notes

`Formula/flamberge.rb` is generated automatically from each
[flamberge release](https://github.com/kessriga/flamberge/releases) — do not edit
it by hand. See the main repository for the source and the full install matrix
(cargo, mise, winget, Chocolatey, AUR, `.deb`/`.rpm`).

## License

MIT — see [LICENSE](LICENSE).
