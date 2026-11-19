# Releasing

Releases are built by [cargo-dist](https://github.com/axodotdev/cargo-dist) (`dist`) from `dist-workspace.toml` and `.github/workflows/release.yml`. The workflow runs only when a version tag is pushed, so it does not publish anything from pull requests. On pull requests it only runs `dist plan`, a read-only check with no secrets, which does not affect the required checks.

A release produces archives for six targets, `sha256.sum`, shell and PowerShell installers, a Homebrew formula, and a GitHub build provenance attestation for every archive.

| Target | Archive |
| --- | --- |
| `aarch64-apple-darwin` | `.tar.xz` |
| `x86_64-apple-darwin` | `.tar.xz` |
| `x86_64-pc-windows-msvc` | `.zip` |
| `aarch64-pc-windows-msvc` | `.zip` |
| `x86_64-unknown-linux-musl` | `.tar.xz` |
| `aarch64-unknown-linux-musl` | `.tar.xz` |

The workflow `reproducible.yml` builds the Linux musl binary twice in clean containers and fails if the two differ.

## One-time owner setup

1. Create the public repository `Haikeysgit/homebrew-skillsniff` with a `Formula/` directory (an initial commit with a README is enough).
2. Create a fine-grained personal access token limited to that repository with Contents: read and write. Add it to `Haikeysgit/skillsniff` as the Actions secret `HOMEBREW_TAP_TOKEN`.
3. Create the public repository `Haikeysgit/scoop-skillsniff` for the Scoop bucket. Put `bucket/skillsniff.json` in it after the first release (see below).
4. In the skillsniff repository settings, confirm Actions may create attestations (the default for public repositories).

## Cutting a release

1. Update `version` in `Cargo.toml` and the path-dependency version in `crates/skillsniff-cli/Cargo.toml`, move the `[Unreleased]` section of `CHANGELOG.md` under the new version, and merge to `main`.
2. Dry run: `dist plan` shows what a tag would build. Optionally tag a pre-release such as `v0.1.0-rc.1` first; dist marks it as a pre-release and does not publish the Homebrew formula for it.
3. Tag and push: `git tag v0.1.0 && git push origin v0.1.0`.
4. When the workflow finishes, check the release page for six archives, `sha256.sum` and the installers, then verify one:
   `gh attestation verify <archive> --repo Haikeysgit/skillsniff`
5. Confirm the Homebrew tap received `Formula/skillsniff.rb`, and that `brew install Haikeysgit/skillsniff/skillsniff` works.

## Scoop and winget

The manifests live in `packaging/` with placeholder hashes. After the release is published:

1. Download `sha256.sum` from the release and run `scripts/fill-packaging.sh 0.1.0 sha256.sum`.
2. The Windows zips are flat (`skillsniff.exe` at the archive root), so the manifests need no folder name. Check that again if the archive layout changes.
3. Scoop: copy `packaging/scoop/skillsniff.json` to `bucket/skillsniff.json` in `Haikeysgit/scoop-skillsniff` and push.
4. winget: validate with `winget validate packaging/winget`, then submit the three files in `packaging/winget/` as a pull request to `microsoft/winget-pkgs` under `manifests/h/Haikeysgit/skillsniff/<version>/`. Tools such as `wingetcreate` can do this.

None of these steps are automated, and none run from this repository's workflows.
