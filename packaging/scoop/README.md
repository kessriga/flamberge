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

- `bucket/flamberge.json` carries `checkver` + `autoupdate`, so the manifest can
  auto-bump to new [flamberge releases](https://github.com/kessriga/flamberge/releases)
  (version, download URL, and SHA-256 read from the release's `SHA256SUMS`).
- To run the auto-update on a schedule, copy the `.github/workflows/` from
  [`ScoopInstaller/BucketTemplate`](https://github.com/ScoopInstaller/BucketTemplate)
  (the `excavator` workflow) into this repo.

## License

MIT — see the [main repository](https://github.com/kessriga/flamberge/blob/main/LICENSE).
