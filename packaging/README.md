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

The only required file in the tap is `Formula/flamberge.rb`. A ready-to-commit
`README.md` and `LICENSE` for the tap live in `packaging/homebrew/tap/`.

```sh
# 1. create the public tap repo (the `homebrew-` prefix makes it a tap)
gh repo create kessriga/homebrew-flamberge --public -d "Homebrew tap for flamberge"

# 2. seed it: the formula + the ready-made README/LICENSE
git clone https://github.com/kessriga/homebrew-flamberge tap
mkdir -p tap/Formula
cp packaging/homebrew/flamberge.rb   tap/Formula/flamberge.rb
cp packaging/homebrew/tap/README.md  tap/README.md
cp packaging/homebrew/tap/LICENSE    tap/LICENSE
( cd tap && git add -A && git commit -m "flamberge 0.1.0" && git push )
```

3. Create a **fine-grained PAT** (Settings → Developer settings → Fine-grained
   tokens) scoped to **only the `kessriga/homebrew-flamberge` repo** with
   **Repository permissions → Contents: Read and write** (nothing else). Add it
   as the secret **`HOMEBREW_TAP_TOKEN`**:

   ```sh
   gh secret set HOMEBREW_TAP_TOKEN --repo kessriga/flamberge
   # paste the PAT when prompted (or: gh secret set HOMEBREW_TAP_TOKEN --repo kessriga/flamberge --body "<pat>")
   ```

   The `homebrew` job then regenerates and force-pushes `Formula/flamberge.rb`
   on every release (leaving the README/LICENSE untouched).

Users on macOS-arm64 and Linux-x86_64 are covered (the two release targets).

### 3. mise (`mise use ubi:kessriga/flamberge`)

Nothing to set up — mise's `ubi` backend installs straight from the GitHub
release using the conventional asset names + `SHA256SUMS` this repo already
produces. Optionally register a short name in the mise registry so
`mise use flamberge` works; until then the `ubi:` form is the documented path.

### 4. winget (`winget install Kessriga.Flamberge`)

Unlike Homebrew there is **no repo of your own to maintain** — manifests live in
`microsoft/winget-pkgs`, and the three files in `packaging/winget/` are exactly
what gets submitted. You do a one-time first submission; the `winget` job
(`winget-releaser`) opens the version-bump PR for every release after that.

1. **Fork winget-pkgs** — `winget-releaser` pushes its branch to your fork, then
   PRs upstream:

   ```sh
   gh repo fork microsoft/winget-pkgs --clone=false
   ```

2. **Submit the initial manifests once.** The package must exist upstream before
   automated bumps work. Validate, then submit the pre-written manifests:

   ```sh
   # cross-platform validator (Rust): https://github.com/russellbanks/Komac
   komac submit --path packaging/winget
   # …or on Windows with wingetcreate:
   wingetcreate submit --token <PAT> packaging/winget
   ```

   Either opens a PR placing the files at
   `manifests/k/Kessriga/Flamberge/0.1.0/`. (A hand-made PR to that path works
   too.)

3. **Token (`WINGET_TOKEN`).** `winget-releaser` needs a **classic PAT with the
   `public_repo` scope** — the fork-and-cross-repo-PR flow it uses does *not*
   work reliably with a fine-grained token, so this one differs from the
   Homebrew tap token. Create it under *Settings → Developer settings → Tokens
   (classic)* with only `public_repo` checked, then:

   ```sh
   gh secret set WINGET_TOKEN --repo kessriga/flamberge
   # paste the PAT when prompted
   ```

   The job preserves the nested-portable-zip layout across bumps, so you only
   author it once (step 2).

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
