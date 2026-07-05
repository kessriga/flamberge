# Packaging & distribution runbook

This directory holds the package definitions and release automation for
`flamberge`. The in-repo pieces (checksums, `.deb`/`.rpm`, crates.io metadata,
and all the manifests below) are complete. What remains for each manager is
**account/registry setup that only the maintainer can do** — creating repos,
registering packages, and adding the tokens listed here as GitHub Actions
secrets. Once a secret exists, the matching CI job stops being a no-op and starts
propagating every tagged release automatically.

## What CI already does (no accounts needed)

`.github/workflows/release.yml`, on a `vX.Y.Z` tag push:

- builds the per-platform binaries and attaches the `.tar.gz`/`.zip` archives,
- builds a Linux **`.deb`** (`cargo-deb`) and **`.rpm`** (`cargo-generate-rpm`)
  from the `[package.metadata.deb]` / `[package.metadata.generate-rpm]` tables in
  `crates/flamberge-cli/Cargo.toml`, and attaches them,
- aggregates every asset's SHA-256 into a **`SHA256SUMS`** asset,
- runs the `crates.io` publish job (a no-op until `CARGO_REGISTRY_TOKEN` is set).

`.github/workflows/package-managers.yml`, on `release: published`, runs the
winget / Homebrew / Chocolatey jobs — each a no-op until its secret is set.

## Per-manager setup

Do the crates.io publish first: several other managers can point at it, and it
is the lowest-maintenance channel.

### 1. crates.io (`cargo install flamberge`)

The workspace is publish-ready: every crate has `description`, `license`,
`repository`, `keywords`, `categories`, and the internal deps carry
`version = "0.1.0"` alongside `path`. The CLI crate (dir `crates/flamberge-cli`)
publishes under the name **`flamberge`** — matching the binary — so
`cargo install flamberge` installs the `flamberge` command.

1. Log in at <https://crates.io> and create an API token with the
   **`publish-new`** and **`publish-update`** scopes (nothing else). Optionally
   restrict its crate scope to the patterns `flamberge` and `flamberge-*`.
2. Add it as the repo secret **`CARGO_REGISTRY_TOKEN`**
   (`gh secret set CARGO_REGISTRY_TOKEN`).
3. Push a tag — the `crates.io` job publishes the five crates in dependency
   order (`crypto → formats → keys → schemes → flamberge`).

To publish once by hand instead:

```sh
for c in flamberge-crypto flamberge-formats flamberge-keys flamberge-schemes flamberge; do
  cargo publish -p "$c"
done
```

The crate names (`flamberge`, `flamberge-crypto`, `flamberge-formats`,
`flamberge-keys`, `flamberge-schemes`) are unregistered as of writing; the first
publish claims them.

### 2. Homebrew (`brew install kessriga/flamberge/flamberge`)

1. Create a public repo **`kessriga/homebrew-flamberge`** (the `homebrew-`
   prefix makes it a tap).
2. Seed it once: `packaging/scripts/update-homebrew-formula.sh v0.1.0
   /path/to/tap/Formula/flamberge.rb`, commit, push. (The committed
   `packaging/homebrew/flamberge.rb` is the same content for reference.)
3. Create a fine-grained PAT with `contents: write` on the tap repo and add it
   as the secret **`HOMEBREW_TAP_TOKEN`**. The `homebrew` job then regenerates
   and pushes the formula on every release.

Users on macOS-arm64 and Linux-x86_64 are covered (the two release targets).

### 3. mise (`mise use ubi:kessriga/flamberge`)

Nothing to set up — mise's `ubi` backend installs straight from the GitHub
release using the conventional asset names + `SHA256SUMS` this repo already
produces. Optionally register a short name in the mise registry so
`mise use flamberge` works; until then the `ubi:` form is the documented path.

### 4. winget (`winget install Kessriga.Flamberge`)

1. Fork `microsoft/winget-pkgs`.
2. Submit the three manifests in `packaging/winget/` under
   `manifests/k/Kessriga/Flamberge/0.1.0/` (validate locally first with
   `winget validate` / `wingetcreate`).
3. Create a PAT with access to your `winget-pkgs` fork and add it as the secret
   **`WINGET_TOKEN`**. The `winget` job (using `winget-releaser`) then opens the
   bump PR for each subsequent release, preserving the nested-portable layout.

### 5. Chocolatey (`choco install flamberge`)

1. Register at <https://community.chocolatey.org> and create an API key.
2. Add it as the secret **`CHOCO_API_KEY`**.
3. On release, the `chocolatey` job rewrites the version + installer URL/checksum
   in `packaging/chocolatey/`, runs `choco pack`, and pushes. The first push
   goes through Chocolatey moderation (the `VERIFICATION.txt` documents the
   checksum provenance moderators check).

### 6. Linux distro packages

- **`.deb` / `.rpm`** — already attached to every release; install with
  `dpkg -i` / `rpm -i` or point an apt/dnf repo at them.
- **AUR (`flamberge-bin`)** — create an AUR git repo named `flamberge-bin` and
  push `packaging/aur/PKGBUILD` + `.SRCINFO`. Regenerate `.SRCINFO` after edits
  with `makepkg --printsrcinfo > .SRCINFO`.

## Propagating a new release

Every `vX.Y.Z` tag automatically: builds + attaches binaries/`.deb`/`.rpm`/
`SHA256SUMS`, publishes to crates.io, and — for each manager whose secret is
set — bumps winget, the Homebrew tap, and Chocolatey. The version and checksums
are read from the freshly built release, so no manual hash editing is needed.

Manual steps that remain per release: the **AUR** package (`.SRCINFO` +
`PKGBUILD` bump), and the **first-ever** submission to winget/Chocolatey/Homebrew
(subsequent bumps are automated). The checked-in manifests here always reflect
the latest released version so they can be copied as-is for a manual submission.
