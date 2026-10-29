# CLI usage and safe demonstration

[< Back to Sibilla Dataset Builder](../README.md) • [Documentation Hub](README.md)

`sibilla-b` extracts static PDF features and builds reproducible datasets offline.
It never executes samples, renders PDFs, contacts URLs or trains models.
This is a development implementation: see the limitations below.

## Build

Linux 5.6+ (x86-64 or AArch64), Rust 1.88 or newer:

```sh
cargo build --release --locked
cargo nextest run --workspace --all-targets --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

The executable is `target/release/sibilla-b`. Commands below assume the binary is
on your `PATH`; otherwise use `target/release/sibilla-b` in place of `sibilla-b`.

```sh
sibilla-b extract pdf --input ./samples/benign --type benign \
  --output ./features/benign.parquet --workers 4
sibilla-b extract pdf --input ./samples/malicious --type malicious \
  --output ./features/malicious.csv --workers 4
sibilla-b dataset build --input ./features/benign.parquet \
  --input ./features/malicious.csv --output ./datasets/pdf-v1 \
  --split 70:15:15 --seed 42
sibilla-b benchmark pdf --input ./samples/benchmark --workers 1,2,4
sibilla-b extract pdf --schema-version
```

Input files are opened read-only; symlinks are skipped by default and nonregular files rejected.
`--follow-symlinks` resolves targets explicitly and detects directory cycles; it can
include files outside the original tree.
Directory scanning is recursive unless `--no-recursive` is supplied. Labels come
only from `--type benign|malicious|unknown` (0, 1, null). Unknown rows remain in
extraction tables but are excluded from labeled datasets.

Each parser process handles one file at a time and is reused. The coordinator
kills and replaces a timed-out or crashed process, emits a failure row, and keeps
processing. Byte statistics survive ordinary parse errors; semantic fields remain
null. A killed process cannot return statistics, so they remain null too.

CSV and Parquet contain the same typed flattened fields, including 256 histogram
columns. CSV uses `\N` for null and escapes a leading backslash in string values;
empty strings are preserved. `--format csv|parquet` overrides the file extension;
table readers recognize Parquet magic. `--failures PATH` writes non-success records
as a separate atomic JSONL sidecar. Sidecars are published independently before the
feature table; existing paths are refused. Existing output paths are never overwritten.
Final extraction tables and dataset directories are published atomically.
Extraction keeps synchronized per-record checkpoints beside the output in
`.OUTPUT.checkpoints/`. Resume with the original arguments plus `--resume`;
worker count may change. Source hashes and configuration are validated before reuse.
Failures without hashes are retried. Checkpoints are locked against concurrent runs
and retained after success; remove them yourself when no longer needed.

Dataset output contains `manifest.parquet`, `features.parquet`, `splits/`,
`dataset_metadata.json` and `report.json`. `sample_id` in features is a join key:
remove it before training. Labels, provenance, quality, hashes and timings are in
the manifest, not predictive feature columns. Exact duplicates with contradictory
labels fail unless `--conflict-policy quarantine` is supplied. Use
`--group-column collection_id` (or another existing column) only when it represents
meaningful related-file groups. Conflicting duplicate group memberships are
rejected. A random split without grouping does not establish family generalization.

See [schema](FEATURE_SCHEMA.md), [security](../SECURITY.md),
[architecture](ARCHITECTURE.md), and [dataset protocol](DATASET_PROTOCOL.md).
The optional `.fixtures` corpus is private and is not required by CI.

## Safe demonstration

```sh
cargo run -p sibilla-b-pdf --example generate_fixtures -- .local/demo/samples
sibilla-b extract pdf --input .local/demo/samples --type benign \
  --output .local/demo/features.parquet --source synthetic-demo \
  --collection-id safe-generated --workers 2
sibilla-b dataset build --input .local/demo/features.parquet \
  --output .local/demo/dataset --group-column collection_id
```

These three PDFs are generated locally. One shared group deliberately stays in one
partition; the demonstration is not an evaluation corpus. Outputs must not already
exist. The example generator checks that its generated PDFs parse to one page.

## Terminal output

Color is enabled by default. Use `sibilla-b --color never --help` or
`sibilla-b --help --no-color` to disable it; `--color auto` detects terminals.
`NO_COLOR=1` disables default colors; an explicit `--color` overrides it.
Progress bars/spinners use stderr on terminals and are hidden in pipes.
`-q` / `--quiet` suppresses progress and status; errors remain visible.
Benchmark JSON and schema-version stdout stay machine readable.
Use `-i` / `-o` for input/output and `-j` for extraction workers.
Install nextest if needed with `cargo install cargo-nextest --locked`.
