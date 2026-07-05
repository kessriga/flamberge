# scoop-flamberge

A [Scoop](https://scoop.sh) bucket for
[**flamberge**](https://github.com/kessriga/flamberge) — a command-line tool that
removes DRM from ebooks, reimplementing the DeDRM_tools Calibre plugins in Rust.

## Install

```powershell
scoop bucket add flamberge https://github.com/kessriga/scoop-flamberge
scoop install flamberge
```

## Update

```powershell
scoop update flamberge
```

## Notes

- `bucket/flamberge.json` carries `checkver` + `autoupdate`, and the
  `.github/workflows/excavator.yml` workflow runs them on a schedule — so new
  [flamberge releases](https://github.com/kessriga/flamberge/releases) are picked
  up automatically (version, download URL, and SHA-256 from the release's
  `SHA256SUMS`), with no manual edits.

## License

MIT — see the [main repository](https://github.com/kessriga/flamberge/blob/main/LICENSE).
