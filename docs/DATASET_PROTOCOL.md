# Build a dataset

[< Back to Sibilla Dataset Builder](../README.md) • [Documentation Hub](README.md)

Start with feature tables produced by `extract pdf`.

## 1. Combine your labeled tables

```sh
sibilla-b dataset build -i ./features/benign.parquet -i ./features/malicious.csv \
  -o ./datasets/pdf-v1 --split 70:15:15 --seed 42 -j 4
```

| Option | Meaning |
| --- | --- |
| `-i` | Input table; repeat for each CSV or Parquet file |
| `-o` | New dataset directory |
| `--split 70:15:15` | Train, validation, and test percentages |
| `--seed 42` | Reproduce the same group allocation |
| `-j`, `--workers` | Output writer limit; 1 runs sequentially, 2 or more allows both table writers |

Tables must match the current PDF format, column schema, schema version, and extractor version. Labels must be `0`, `1`, or null; sample identities use lowercase SHA-256 hex.

## 2. Keep related files together

Use `collection_id` only when it represents meaningful related-file groups.

- Set it during extraction with `--collection-id collection-a`.
- Extract each related collection separately and pass its table with `-i`.
- Every row needs a value for the chosen group column.

Then build the grouped dataset:

```sh
sibilla-b dataset build -i ./features/benign.parquet -i ./features/malicious.csv \
  -o ./datasets/pdf-grouped --group-column collection_id --split 70:15:15 --seed 42
```

- Every group stays in one partition.
- Duplicate identities with conflicting group memberships are rejected.
- Large groups and small classes may prevent exact split percentages.
- Without a group column, only exact duplicates are kept together.

> [!CAUTION]
> Exact deduplication does not detect near-duplicate or malware-family leakage. A random split alone does not demonstrate generalization to unknown families.

## 3. Resolve contradictory labels

By default, the same SHA-256 with different known labels stops the build.

Use `--conflict-policy quarantine` to exclude contradictory identities instead of choosing a label:

```sh
sibilla-b dataset build -i ./features/benign.parquet -i ./features/malicious.csv \
  -o ./datasets/pdf-quarantined --conflict-policy quarantine
```

Conflicts include failed records that still carry the same hash. Unknown labels and unavailable extraction results are excluded from the labeled dataset.

## 4. Check the output

| File | Use it to… |
| --- | --- |
| `report.json` | Review class/split counts, exclusions, duplicates, conflicts, and null rates |
| `dataset_metadata.json` | Record the seed, split strategy, versions, and artifact hashes |
| `manifest.parquet` | Inspect labels, provenance, and extraction quality |
| `features.parquet` | Load predictive measurements |
| `splits/train.parquet` | Select training identities |
| `splits/validation.parquet` | Select validation identities |
| `splits/test.parquet` | Select test identities |

Remove `sample_id` before training: it is a join key, not a predictive feature. Keep labels, provenance, hashes, quality fields, and timings out of model inputs.

Existing destination directories are refused. Publication is atomic and uses Linux no-replace rename.

## Reproducibility and limits

- Same seed and grouping reproduce split assignments.
- Groups are ordered by a seeded SHA-256 key and allocated using label-balance targets.
- Exact duplicates retain one feature row.
- Temporal evaluation is unavailable: the schema has no defensible first-seen timestamps.

## Performance

With `-j 2` or higher, manifest and feature-table writers run concurrently through bounded queues. The spool is read once for both tables and null statistics. With `-j 1`, tables are written sequentially using two read passes.

There are currently two heavy output tasks, so values above 2 do not add more table writers. Ingestion, deduplication and split assignment remain sequential; more workers do not guarantee maximum CPU use or a faster run on a slow disk.
