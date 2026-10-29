# Releases

[< Back to Sibilla Dataset Builder](../README.md) • [Documentation Hub](README.md)

## Use a packaged CLI

1. Open [project releases](https://github.com/younidev-org/sibilla-dataset-builder/releases).
2. Download `sibilla-b` directly, or choose the tar archive for the bundled usage guide and license.
3. Download `SHA256SUMS` and verify the checksum for your chosen asset.
4. For the archive, extract it. For the standalone download, enable executable permissions:

```sh
chmod +x sibilla-b
./sibilla-b --help
```

Both downloads are available only after a release is published.

| Item | What to expect |
| --- | --- |
| Standalone download | `sibilla-b`; no extraction required |
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
| Artifacts | Standalone `sibilla-b`, CLI archive, and `SHA256SUMS` |
| Publication | Draft GitHub release with generated notes |
| Manual trigger | Not available |
| Branch pushes or pull requests | Do not create releases |

Review the draft and its checksums before publishing. See the [release workflow](../.github/workflows/release.yml) for the exact checks.
