# Implementation plan

Authority: `.local/SIBILLA_DATASET_BUILDER.md` (local specification).
Executable: `sibilla-b`. No commits or pushes authorized.

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
