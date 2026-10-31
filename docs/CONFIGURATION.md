# Configure a run

[< Back to Sibilla Dataset Builder](../README.md) • [Documentation Hub](README.md)

## Start with a commented template

```sh
sibilla-b config init --format pdf -o extract.toml
sibilla-b config init --command dataset -o dataset.toml
```

Edit the paths and extraction label, then validate and run:

```sh
sibilla-b config check extract.toml
sibilla-b extract --config extract.toml
sibilla-b dataset build --config dataset.toml
```

Templates: [PDF extraction](../examples/config/extract-pdf.toml) · [Dataset build](../examples/config/dataset.toml).

`config check` validates settings without opening sample content, starting workers or creating outputs. It does not guarantee that input paths exist or that output permissions are sufficient. Template generation refuses an existing file.

## Override only what changes

```sh
sibilla-b extract --config extract.toml --limit 100 -j 2
sibilla-b extract --config extract.toml --no-decode-images
sibilla-b dataset build --config dataset.toml -i replacement.parquet -o new-dataset
```

Built-in defaults apply first, then the file, then explicitly supplied CLI flags. CLI `-i` replaces the configured input list. Use `--no-decode-images`, `--recursive`, `--no-follow-symlinks`, `--no-resume`, or `--no-quiet` to reverse the corresponding config setting. Existing `extract pdf ...` commands and global color/quiet flags remain available.

Paths in TOML are relative to the TOML file's directory. Relative CLI overrides use your current directory. There is no environment substitution, include mechanism, executable expression or plugin loading.

## Extraction settings

Every config requires `config_version = 1` and `command = "extract"` or `command = "dataset"`. Unknown keys, unsupported versions and wrong-command sections are errors. Only PDF extraction is implemented; `auto`, PE and JavaScript format sections are rejected rather than ignored.

The tables show TOML keys and their CLI equivalents. “Config only” means there is no inline flag. Defaults apply when the key is omitted; templates may set an explicit value instead.

### Extraction option table

| TOML key | Default / allowed values | CLI equivalent | What it controls |
| --- | --- | --- | --- |
| `input.path` | Required file or directory | `-i`, `--input` | Files to extract. |
| `input.format` | `pdf` | `extract pdf` | Parser selection; PDF is currently the only format. |
| `input.label` | Required: `benign`, `malicious`, `unknown` | `--type` | Assign a label to every input. Unknown samples cannot enter a labeled dataset. |
| `input.limit` | Omitted: no cap; positive integer | `--limit` | Process the first N sorted paths, not a random sample. Discovery still scans the tree. |
| `input.recursive` | `true` | `--recursive` / `--no-recursive` | Include subdirectories. |
| `input.follow_symlinks` | `false` | `--follow-symlinks` / `--no-follow-symlinks` | Allow resolved targets outside the input tree. |
| `output.path` | Required new file | `-o`, `--output` | Write the feature table; existing paths are refused. |
| `output.format` | Infer from `.parquet` or `.csv` | `--format` | Explicitly choose `parquet` or `csv` for extensionless paths. |
| `output.failures` | Omitted: no separate log | `--failures` | JSONL records for partial, failed and rejected inputs. |
| `runtime.workers` | CPU-based; 1–256 | `-j`, `--workers` | Concurrent parser processes; the template chooses 4. |
| `runtime.timeout_seconds` | `30`; positive | `--timeout-seconds` | Per-file wall-clock timeout. |
| `runtime.input_mib` | `64`; positive | `--max-size-mb` | Maximum input file size in MiB. |
| `runtime.resume` | `false` | `--resume` / `--no-resume` | Reuse compatible checkpoints and validate source hashes. |
| `runtime.quiet` | `false` | `--quiet` / `--no-quiet` | Hide progress and status messages. |
| `runtime.color` | `always`; `always`, `auto`, `never` | `--color`; `--no-color` | ANSI colors; `auto` detects terminals, `never` disables colors. |
| `provenance.source` | Omitted | `--source` | Collection source name, stored as metadata. |
| `provenance.collection_id` | Omitted | `--collection-id` | Related-document ID, stored as metadata. |
| `features.common.groups` | All common groups | Config only | Choose `size`, `entropy`, `byte_histogram`; `[]` disables them. |
| `formats.pdf.groups` | All PDF groups below | Config only | Choose which PDF feature families to measure; `[]` disables them. |
| `formats.pdf.stream_mode` | `decoded`; `decoded`, `structural` | `--stream-mode` | Attempt generic stream decoding or collect structural measurements. |
| `formats.pdf.decode_images` | `false` | `--decode-images` / `--no-decode-images` | Attempt bounded JPEG decoding; requires decoded mode and image metadata. |
| `formats.pdf.decoded_mib` | `128`; positive | `--max-decompressed-mb` | Per-stage decoded-data allowance in MiB. |

PDF groups: `structure`, `actions`, `javascript`, `attachments`, `links`, `image_metadata`, `stream_statistics`. Omitted group lists enable all current groups in that namespace; `groups = []` disables every optional group in that namespace. JavaScript requires actions. JPEG decoding requires image_metadata and decoded mode. Disabled measurements are exported as null; file identity, file validation and worker restrictions remain mandatory. Shared parsing may still support other selected groups.

Each analysis stage has its own decoded-byte allowance; this is not a whole-process memory cap. The worker's existing 512 MiB address-space ceiling and time/network restrictions remain unchanged.

## Dataset columns and aliases

```toml
config_version = 1
command = "dataset"

[input]
paths = ["benign.parquet", "malicious.parquet"]

[output]
path = "dataset"

[columns]
groups = ["common.entropy", "pdf.actions", "pdf.javascript"]
exclude = []

[aliases]
"common.entropy_global" = "byte_entropy"

[cleanup]
drop_all_null = true
drop_constant = false
```

### Dataset option table

Extraction-only settings are rejected in dataset configs. Dataset builds use existing feature tables; they do not parse the original PDFs again.

| TOML key | Default / allowed values | CLI equivalent | What it controls |
| --- | --- | --- | --- |
| `input.paths` | Required list of feature tables | Repeat `-i`, `--input` | Merge compatible labeled extractions; retain each extraction sidecar. |
| `output.path` | Required new directory | `-o`, `--output` | Destination for the dataset artifacts. |
| `runtime.workers` | CPU-based; 1–256 | `-j`, `--workers` | Writer limit; at most two concurrent writers, not parallel PDF extraction. The template chooses 2. |
| `runtime.quiet` | `false` | `--quiet` / `--no-quiet` | Hide progress/status. |
| `runtime.color` | `always`; `always`, `auto`, `never` | `--color`; `--no-color` | Control ANSI colors. |
| `split.percentages` | `[70, 15, 15]`; total 100 | `--split 70:15:15` | Train, validation and test allocation. Related groups may prevent exact percentages. |
| `split.seed` | `42` | `--seed` | Reproduce the allocation with the same inputs and settings. |
| `split.group_column` | Omitted | `--group-column` | Keep samples sharing a metadata group in one partition. Use meaningful group IDs. |
| `policy.conflict_policy` | `error`; `error`, `quarantine` | `--conflict-policy` | Stop or exclude contradictory labels for identical file hashes. |
| `columns.groups` | `[]`: all predictive groups | Config only | Select registered groups such as `common.entropy` or `pdf.actions`. |
| `columns.exclude` | `[]` | Config only | Remove specific features by canonical ID. |
| `aliases` | No renaming | Config only | Map quoted canonical IDs to exported names. |
| `cleanup.drop_all_null` | `true` in config builds | Config only | Remove features with no measured values in training rows. |
| `cleanup.drop_constant` | `false` | Config only | Remove features with one distinct non-null training value. |

Unlike extraction group lists, an empty dataset group list means **all predictive groups**. Dataset selection changes the exported columns; it cannot recover measurements disabled during extraction.

Use canonical IDs for exclusions and alias sources: `extraction_common_features_X` becomes `common.X`, `extraction_format_features_X` becomes `pdf.X`. `inspect --columns` shows the canonical mapping. Columns have registered types, roles, groups, units and missing-value definitions; aliases never change those meanings.

An empty dataset group list selects all predictive groups. Unknown IDs, duplicate/reserved names, aliases to excluded/nonpredictive fields, exclusion of mandatory metadata and empty feature exports are errors. The full manifest retains original columns and labels. Feature exports retain sample_id for joins; split files still contain only identities and split assignments.

All-null/constant cleanup is learned from training rows only and applied uniformly. A column with identical non-null training values is constant even if some training rows are null; all-null is separate. Cleanup without training rows is an error. No imputation or scaling is performed. Config-first builds default to dropping all-null training columns; legacy inline builds preserve columns unless configured otherwise.

## Reproduce or resume a run

Extraction publishes `.OUTPUT.config.json` beside its table and keeps the initial settings in the hidden checkpoint directory. Keep the sidecar when copying a 0.6.0 table: builds require it to distinguish disabled measurements from unavailable ones.

```sh
sibilla-b extract --config extract.toml --resume -j 2
```

Resolved settings contain absolute paths, a complete-run hash and a feature-profile hash. Comments, TOML ordering, or renaming a config in the same directory do not alter effective settings. Worker count may change on resume; selected groups, semantic limits, inputs and labels must match the checkpoint. An initial resolved sidecar can be recreated from checkpoints after interrupted publication. A conflicting sidecar is never overwritten. Sidecar and final table are separate atomic publications; failure can leave a sidecar without a final table.

Dataset output includes `resolved_config.json`, its artifact hash, projection mappings, and input profile information. Profile compatibility excludes source paths, labels, provenance, file-count caps and workers, while retaining format/schema, groups, decoding policy and semantic limits. Config-first and inline profiles are distinct; mixed profiles are rejected.

Legacy pdf-v5 tables from extractor 0.5.0 may be built without a sidecar under an explicit legacy profile. They cannot be mixed with newly profiled exports. Other old extractor versions are not silently accepted. Measurement schema remains pdf-v5; this release does not add non-PDF parsers.
