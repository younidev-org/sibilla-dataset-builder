# Sibilla Dataset Builder

`sibilla-b` extracts static PDF features and builds reproducible datasets offline.
It never executes samples, renders PDFs, contacts URLs or trains models.
This is a development implementation: see the limitations below.

## Build

Linux (x86-64 or AArch64), Rust 1.88 or newer:

```sh
cargo build --release --locked
cargo test --workspace --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

The executable is `target/release/sibilla-b`.

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

Input files are opened read-only; symlinks are skipped and nonregular files rejected.
Directory scanning is recursive unless `--no-recursive` is supplied. Labels come
only from `--type benign|malicious|unknown` (0, 1, null). Unknown rows remain in
extraction tables but are excluded from labeled datasets.

Each parser process handles one file at a time and is reused. The coordinator
kills and replaces a timed-out or crashed process, emits a failure row, and keeps
processing. Byte statistics survive ordinary parse errors; semantic fields remain
null. A killed process cannot return statistics, so they remain null too.

CSV and Parquet contain the same typed flattened fields, including 256 histogram
columns. CSV uses `\N` for null and escapes a leading backslash in string values;
empty strings are preserved. Existing output paths are never overwritten.
Final extraction tables and dataset directories are published atomically.

Dataset output contains `manifest.parquet`, `features.parquet`, `splits/`,
`dataset_metadata.json` and `report.json`. `sample_id` in features is a join key:
remove it before training. Labels, provenance, quality, hashes and timings are in
the manifest, not predictive feature columns. Exact duplicates with contradictory
labels fail unless `--conflict-policy quarantine` is supplied. Use
`--group-column collection_id` (or another existing column) only when it represents
meaningful related-file groups. Conflicting duplicate group memberships are
rejected. A random split without grouping does not establish family generalization.

## Current limitations

- Resume, explicit format override, failure sidecars, symlink following and temporal
  evaluation are rejected explicitly; they are not implemented yet.
- Byte statistics and initial PDF structural/raw/parsed-name counts work. The full
  specified PDF feature schema is unfinished; `pdf-v1` is not frozen.
- Paths and unique dataset rows are held in memory. Features are spooled to disk
  during extraction, but million-file scaling and external sorting are unfinished.
- Linux worker controls limit address space and descriptors and deny networking;
  they are not full filesystem/kernel isolation. Use a dedicated VM/container.
- A decompression ceiling applies per stream. Aggregate decompression accounting,
  CPU limits, recursion controls and stronger sandbox validation remain unfinished.
- Benchmarks measure complete extraction. Peak memory and storage type are not
  automatically measured; record them separately before performance comparisons.

See [schema](docs/FEATURE_SCHEMA.md), [security](SECURITY.md),
[architecture](docs/ARCHITECTURE.md), [dataset protocol](docs/DATASET_PROTOCOL.md),
and [implementation progress](docs/IMPLEMENTATION_PLAN.md).
The optional `.fixtures` corpus is private and is not required by CI.
