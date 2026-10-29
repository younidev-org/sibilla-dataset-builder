# Implementation plan

Authority: `.local/SIBILLA_DATASET_BUILDER.md` (local specification).

1. Foundation: independent workspace crates, typed records, format extractor interface,
   clap commands, documentation and CI. Verify help, schema serialization, fmt, clippy.
2. PDF extraction: bounded reads, SHA-256, byte statistics and parsed/raw PDF features.
   Generate safe fixtures; test malformed, empty and encrypted inputs and null semantics.
3. Pipeline: restricted worker processes, supervised timeout/replacement, bounded queues,
   deterministic discovery, atomic CSV/Parquet finalization and validated resume checkpoints.
   Test timeout, failure, restart, output equivalence and deterministic workers.
4. Dataset: validate tables, deduplicate labels, grouping/temporal splits, manifests,
   predictive columns, artifact hashes and reporting. Test conflicts and split leakage.
5. Release checks: documentation, real fixture parsing and benchmark, format, tests,
   clippy and review. Record limitations and actual results.

## Progress

- Preflight: repository contains only LICENSE, ignore rules and local specification.
- Verified Rust toolchain and current lopdf/parquet package metadata through cargo.
- Worktree preference requested before source implementation.

## Shared interfaces

- Schema defines typed common/PDF features plus separate provenance and quality fields.
- Extractor accepts bytes and explicit resource limits, never a label or split.
- Output owns table schema and round-trip validation for extraction and dataset ingestion.
- Core owns process supervision; PDF never depends on CLI or dataset.
- Foundation milestone: workspace compiles, CLI help/schema-version verified, two
  tests pass, formatting and clippy pass. Remaining crates are intentionally empty
  until their implementation milestone; no extraction functionality claimed.
- Ruling: use requested current checkout on codex/implement-sibilla-b.
- User authorized milestone commits; use Codex attribution and Odoo-style messages.
- Parser milestone: generated one-page PDF, malformed, empty and oversized cases
  pass; all ten sampled local fixture PDFs returned successful parser records.
- Reusable Linux worker protocol implemented with memory/descriptor limits,
  no_new_privs, network denial, protocol errors and supervisor timeout handling.
  Worker reuse/missing-file and malformed-protocol integration tests pass.
- Remaining Stage 1 features and output are not complete. Do not freeze pdf-v1.
- Extraction/table/dataset milestone: bounded results channel, deterministic
  spooling, atomic typed CSV/Parquet, label-aware dedup, conflict quarantine,
  group-safe seeded allocation, manifest/features/splits/report/metadata and hashes.
- CLI benchmark measures real complete extraction with configurable worker counts.
- Ten local fixture PDFs passed extraction and dataset construction via both CSV
  and Parquet. Debug build benchmark: 11.65 files/s (1 worker), 22.38 files/s (2),
  1,573,576 input bytes, no non-success rows. Small warm-cache sample; no broad claim.
- Independent review: fixed broken-pipe crash recovery, duplicate group mismatch,
  CSV empty/null ambiguity and canonical hash validation. Regression tests added.
- Incomplete: resume/checkpoints, full PDF feature schema, explicit format/failure
  sidecars, temporal mode, external sort/discovery, CPU/aggregate decode accounting,
  expanded safe fixture matrix and full-corpus benchmarks. Public flags reject
  unsupported behavior rather than pretending to implement it.

- Checkpoint milestone: durable per-row shards, configuration/discovery validation,
  source hash validation on resume, process-level locking, and deterministic reuse.
  Failures without byte identity are retried. Checkpoint reuse/config/content tests
  pass, as do timeout kill and actual subprocess seccomp network-denial checks.
- Per-job CPU budgets now supplement supervising wall-clock limits. Dataset JSON
  metadata and report files are synchronized before directory publication.

- Expanded-feature milestone: loaded references/streams, catalog flags, typed embed
  counts, URI hosts, bounded decoded/raw stream statistics and filter summaries.
  Unsupported graph/revision measurements are explicitly null and documented.
- Review regressions fixed: empty-password encryption identity, password-required
  null semantics, empty-filter identity decoding, nonfinite input rejection.
- Format override, independent atomic failure JSONL, opt-in symlink traversal/cycle
  handling and CPU-aware worker default are implemented and tested.
- Dataset feature rows now spool to disk; only identity/group metadata stays in RAM.
  File opens reject symlinks in all components using Linux openat2.
- Generated and verified three safe one-page demo PDFs, extracted their features,
  and built .local/demo/dataset using a shared group; no real sample is required.
- Remaining release gaps: temporal inputs, external manifests/sort for million-file
  scale, advanced action/revision graphs, embedded-only size summaries, full-corpus
  benchmark/peak memory, cross-platform support and stronger sandbox evaluation.
- Latest verification: 23 top-level tests pass (plus the isolated network probe),
  all-target compilation, fmt and clippy pass. Expanded feature extraction on ten
  local PDFs produced six success and four partial rows in both formats; dataset
  builds succeeded. Observed debug throughput: 8.30 files/s with one worker and
  15.46 with two (tiny warm-cache corpus; see docs/benchmark-sample.json).
- This remains a development implementation, not completion of every original
  acceptance gate; the remaining release gaps above are explicit.

## CLI presentation and nextest milestone

- Tests now run with cargo nextest locally and in CI (nextest was already installed).
- Global --color always|auto|never (always default), --no-color and NO_COLOR handling
  cover help, errors, status, progress and benchmark subprocesses.
- Global -q/--quiet, -i/-o/-j shortcuts, command descriptions, option help and examples.
- Terminal-only stderr spinners/bars cover discovery, checkpoint verification,
  extraction, finalization, dataset assembly and benchmark configurations.
- Verified 26 tests with nextest; one isolated restriction probe is intentionally
  ignored by the harness and executed by its parent subprocess test. Clippy/fmt pass.
- Pseudo-terminal checks verified bars with and without color and clean stdout.
  Independent code review found no actionable issues. No full-corpus benchmark rerun.

## Crate naming, function docs and release automation

- Renamed all seven crate directories, package names, dependencies, Rust imports,
  lockfile entries and documentation references to sibilla-b-*; binary remains sibilla-b.
- All 84 Rust functions have a one-line rustdoc, including private functions, tests,
  examples, trait declarations and trait implementations; no runtime logic changed.
- CI now runs exclusively for main branch pushes. Release workflow mirrors local
  neutral-lang qualification/checksum/draft publication, but triggers only on v* tags.
- Tag must match the workspace version and main HEAD. Read-only qualification runs
  nextest/fmt/clippy and builds the optimized CLI; only draft publication has contents:write.
- Release asset is a Linux host archive containing the executable, license and docs,
  plus SHA256SUMS. No tags, pushes or remote release operations performed locally.
- Verification: 26 nextest tests pass; one intentionally ignored network probe is
  invoked by its parent test. Formatting/Clippy pass; all 84 functions audited for
  rustdoc, all seven package names and workflow triggers/permissions checked.
- Optimized CLI build and exact release packaging step pass locally. Archive
  checksum, executable permissions and included documentation verified; extracted
  executable successfully extracts synthetic PDFs and builds their grouped dataset.
- Independent review found only missing archive docs, which were included. GitHub
  runner execution and remote release upload remain untested; no remote side effects.
