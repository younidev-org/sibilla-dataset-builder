# CI and releases

[< Back to Sibilla Dataset Builder](../README.md) • [Documentation Hub](README.md)

Normal CI runs only for pushes to `main`. Pushing a `v*` tag starts release
qualification; the tag must equal `v` plus the workspace version (currently
`v0.1.0`) and point to `main` HEAD. The workflow checks formatting, Clippy and
nextest before building the optimized CLI.

Successful qualification creates a **draft** GitHub release with generated notes,
`SHA256SUMS`, and a `sibilla-b-VERSION-x86_64-unknown-linux-gnu.tar.gz` archive.
The archive preserves executable permissions and includes the CLI, README,
license, security guidance and documentation. The binary is built on Ubuntu 24.04
for Linux x86-64 GNU; other supported Linux systems can build from source.
Release drafts require manual review/publication. There is no manual workflow
trigger and no release creation for branch pushes or pull requests.
