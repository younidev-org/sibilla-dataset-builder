# Architecture reference

[< Back to Sibilla Dataset Builder](../README.md) • [Documentation Hub](README.md)

Contributor reference. For commands, start with [CLI usage](USAGE.md).

## Crate responsibilities

| Crate | Responsibility |
| --- | --- |
| `sibilla-b-cli` | Commands, presentation, user labels |
| `sibilla-b-core` | Worker processes, restrictions, supervision, JSON protocol |
| `sibilla-b-common-features` | Shared byte statistics |
| `sibilla-b-pdf` | Static PDF parsing; bytes and limits only |
| `sibilla-b-schema` | Versioned typed records |
| `sibilla-b-output` | Typed CSV/Arrow/Parquet tables and atomic publication |
| `sibilla-b-dataset` | Table validation, deduplication, grouped splits |

## Processing and storage

- Deterministic discovery feeds N coordinator threads.
- Each thread supervises one reusable parser process.
- Results pass through a bounded channel into per-record disk checkpoints.
- Records are ordered by hash, with input-order tie-breaks.
- Parquet batches contain at most 512 rows.
- Full feature rows spool to disk; paths and identity/group maps remain in RAM.
- External manifests and sorting are still needed for million-file scale.

## Boundaries

| Boundary | Rule |
| --- | --- |
| Extractor inputs | Bytes and limits; no label or split information |
| Sample opening | Linux `openat2` with `RESOLVE_NO_SYMLINKS`; reject nonregular files |
| Explicit symlink following | Resolve targets during discovery |
| Worker logs | Suppress stderr; return fixed failure codes |
| Isolation | Filesystem/kernel isolation remains incomplete |
| Output | Synchronize and publish without overwriting existing paths |
| Determinism | Feature values and ordering stable; observed durations vary |

Keep new format parsers in independent crates. Do not couple parsing to orchestration or dataset logic. Future incompatible schemas must not be silently merged.
