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

| Section | Settings |
| --- | --- |
| `input` | `path`, `format = "pdf"`, explicit `label`, optional positive `limit`, `recursive`, `follow_symlinks` |
| `output` | New `path`, optional `format = "csv"` or `"parquet"`, optional `failures` JSONL path |
| `runtime` | `workers` (1–256), positive `timeout_seconds`, positive `input_mib`, `resume`, `quiet`, `color` (always/auto/never) |
| `provenance` | Optional `source` and `collection_id`; never inferred |
| `features.common` | `groups`: size, entropy, byte_histogram |
| `formats.pdf` | `groups`, `stream_mode` (decoded/structural), `decode_images`, positive `decoded_mib` |

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

Dataset `runtime` supports workers/quiet/color. `split` supports percentages, seed and group_column; `policy.conflict_policy` is error or quarantine. Extraction-only settings are rejected in dataset configs.

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
