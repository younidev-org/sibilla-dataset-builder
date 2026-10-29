# Releases

[< Back to Sibilla Dataset Builder](../README.md) • [Documentation Hub](README.md)

## Use a packaged CLI

1. Open [project releases](https://github.com/younidev-org/sibilla-dataset-builder/releases).
2. If a published release is available, download its CLI archive and `SHA256SUMS`.
3. Verify the archive checksum, then extract it.
4. Run the included `sibilla-b` executable; start with `sibilla-b --help`.

| Item | What to expect |
| --- | --- |
| Archive name | `sibilla-b-VERSION-x86_64-unknown-linux-gnu.tar.gz` |
| Target | Linux x86-64 GNU, built on Ubuntu 24.04 |
| Contents | Only `sibilla-b`, a short usage `README.md`, and `LICENSE` |
| Permissions | Executable bit preserved in the archive |
| Other supported Linux systems | [Build from source](../README.md#development) |

The [bundled README](RELEASE_README.md) contains offline examples and essential safety notes. Full reference documentation stays online; architecture, artwork, benchmarks, and maintainer files are excluded.

A configured release workflow does not guarantee a published release exists. Drafts require maintainer review and publication.

## Maintainer reference

| Event or check | Behavior |
| --- | --- |
| Push to `main` | Run normal CI |
| Push a `v*` tag | Start release qualification |
| Version gate | Tag must equal `v` plus workspace version; currently `v0.1.0` |
| Commit gate | Tag must point to `main` HEAD |
| Qualification | Formatting, Clippy, nextest, optimized CLI build |
| Artifacts | CLI archive and `SHA256SUMS` |
| Publication | Draft GitHub release with generated notes |
| Manual trigger | Not available |
| Branch pushes or pull requests | Do not create releases |

Review the draft and its checksums before publishing. See the [release workflow](../.github/workflows/release.yml) for the exact checks.
