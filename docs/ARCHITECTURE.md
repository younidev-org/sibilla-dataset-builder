# Architecture

The CLI owns user arguments and labels. `sibilla-core` owns restricted subprocesses
and their newline-delimited JSON protocol. `sibilla-pdf` implements the extractor
trait and only consumes bytes and limits; it cannot see labels or split assignments.
`sibilla-common-features` computes shared byte statistics. `sibilla-schema` owns
versioned Rust records. `sibilla-output` owns typed Arrow/CSV tables and atomic
publication. `sibilla-dataset` validates tables, deduplicates samples and splits.

Extraction discovers files deterministically, feeds a shared job iterator to N
coordinator threads, each supervising one parser process, and receives results on
a bounded channel. Records are spooled individually to disk, then ordered by hash
(with deterministic input order tie-breaks) and streamed into the final table.
Parquet batches contain at most 512 rows. Output is synchronized and published
without overwriting existing paths. Current path/shard lists and dataset identity/group maps
still reside in RAM; full feature rows are spooled to disk; external manifests/sorting remain required for large corpora.

The worker uses Linux openat2 with RESOLVE_NO_SYMLINKS, rejecting symlinks in all
path components, and rejects nonregular files. Full filesystem isolation is not
provided. Explicit symlink following resolves paths during discovery. Worker stderr is suppressed so parser logs cannot expose sample content.
The protocol returns fixed failure codes rather than parser-supplied error text.

The feature schema is still in development. Do not silently merge artifacts from
future incompatible schema revisions. Other formats must implement the trait in
independent crates without coupling their parsers to orchestration or dataset code.

Feature values and record ordering are deterministic across worker counts; observed
extraction durations and benchmark timings naturally vary.
