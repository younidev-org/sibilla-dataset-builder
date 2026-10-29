# Use the CLI

[< Back to Sibilla Dataset Builder](../README.md) • [Documentation Hub](README.md)

Examples assume `sibilla-b` is on your `PATH`. For a local build, use `target/release/sibilla-b` instead.

## Extract PDFs

### A folder of labeled files

```sh
sibilla-b extract pdf -i ./samples/benign --type benign -o ./features/benign.parquet -j 4
sibilla-b extract pdf -i ./samples/malicious --type malicious -o ./features/malicious.csv -j 4
```

### One PDF without a label

```sh
sibilla-b extract pdf -i ./sample.pdf -o ./features/sample.csv
```

The default label is `unknown`. Unknown rows are saved but excluded from labeled datasets.

| Option | What it does |
| --- | --- |
| `-i`, `--input` | Read one file or a directory |
| `-o`, `--output` | Write a new CSV or Parquet table |
| `--type benign` | Set label `0` |
| `--type malicious` | Set label `1` |
| `--type unknown` | Leave the label null |
| `-j`, `--workers` | Set the number of parser processes |
| `--no-recursive` | Skip subdirectories |
| `--follow-symlinks` | Follow resolved targets, including those outside the input tree |
| `--format csv` | Override the output filename extension |
| `--source`, `--collection-id` | Save provenance, not predictive features |

Input files are opened read-only. Labels are never inferred. Symlinks are skipped unless you opt in; nonregular files are rejected.

## Resume an interrupted run

During extraction, Ctrl+C stops new jobs, checkpoints in-flight results, and exits with code 130. Resume from the same working directory using the shell-quoted command printed to stderr. If a failure sidecar was already published, the printed command omits that existing sidecar.

Or repeat the original extraction command and add `--resume`:

```sh
sibilla-b extract pdf -i ./samples/benign --type benign \
  -o ./features/benign.parquet -j 4 --resume
```

- Keep the input, output, label, and provenance arguments unchanged.
- You may change the worker count.
- Keep the `.OUTPUT.checkpoints/` directory beside the output.
- Changed source hashes or configuration stop the resume.
- Records without a hash are retried.
- A checkpoint cannot be shared by simultaneous runs.

Existing final outputs are never overwritten. After a completed run, choose a new output path for another extraction. Checkpoints remain after success; remove them when no longer needed.

## Inspect a feature table

```sh
sibilla-b inspect ./features/benign.parquet
sibilla-b inspect ./features/benign.parquet --columns
sibilla-b inspect ./features/benign.parquet --json
```

- Reads every row of a CSV or Parquet extraction table, not a preview.
- Reports labels, statuses, error counts, missing values, and up to five sample errors.
- Uses shorter display names; `--columns` shows their exported equivalents.
- `--json` outputs the complete summary for scripts.

| Partial reason | Meaning |
| --- | --- |
| `unsupported_stream_filter` | The decoder does not support a stream's filter |
| `decode_budget_exceeded` | A decoded stream would exceed the remaining budget |
| `malformed_stream` | A supported decoder could not decode the stream |
| `invalid_filter_chain` | The stream's filter declaration is malformed |
| `feature_depth_limit` | A feature traversal reached its nesting limit |

Multiple reasons are stored in sorted `|`-separated form and counted separately. Older tables retain their original generic codes; run a new extraction to obtain the detailed reasons.

The final extraction summary separates rejected files, timeouts and crashes, and reports reused records, files/second, and error counts.

## Find extraction problems

```sh
sibilla-b extract pdf -i ./samples/benign --type benign \
  -o ./features/checked.parquet --failures ./features/failures.jsonl
```

| Result | What to do |
| --- | --- |
| `success` | Use the available measurements |
| `partial` | Inspect the error code; some measurements are null |
| `rejected` | Check the file type, size limit, and read permissions |
| `timeout` | Review the file or retry with a larger `--timeout-seconds` value |
| `failed` | Inspect the worker failure code before retrying |

Ordinary parse errors preserve byte features. A killed worker cannot return statistics, so those values remain null too.

| Limit | Set with |
| --- | --- |
| Input file size | `--max-size-mb` |
| Wall-clock time per file | `--timeout-seconds` |
| Explicit decoded stream budget | `--max-decompressed-mb` |

> [!NOTE]
> The JSONL sidecar is published separately before the feature table. If a later step fails, it may already exist. On resume, omit `--failures` or choose a new sidecar path; existing sidecars are refused.

Final tables are published atomically. Read [security limits](../SECURITY.md) before handling untrusted PDFs.

## Fix common command errors

| Message or situation | Next step |
| --- | --- |
| Output already exists | Choose a new output path |
| Checkpoint directory exists | Reuse the original arguments with `--resume` |
| Resume configuration or source content changed | Start a new run with a new output path |
| Another extraction owns the checkpoint | Wait for that run to finish |
| Incompatible feature tables | Use tables from the same schema and extractor version |
| No labeled extractable samples | Check labels and extraction status before building the dataset |

## Build a dataset

```sh
sibilla-b dataset build -i ./features/benign.parquet -i ./features/malicious.csv \
  -o ./datasets/pdf-v1 --split 70:15:15 --seed 42
```

See [Build a dataset](DATASET_PROTOCOL.md) for grouping, label conflicts, and output files.

## Terminal output

| I want to… | Use |
| --- | --- |
| Disable colors | `sibilla-b --no-color --help` |
| Disable colors with an explicit mode | `sibilla-b --color never --help` |
| Detect terminal color support | `--color auto` |
| Disable default colors through the environment | `NO_COLOR=1` |
| Hide progress and status | `-q` or `--quiet` |
| Read extraction help | `sibilla-b extract pdf --help` |

Colors default to `always`; an explicit `--color` overrides `NO_COLOR`. Progress uses stderr and is hidden in pipes. Errors remain visible in quiet mode.

Benchmark JSON and schema-version output stay clean on stdout. Use `-i`, `-o`, and `-j` as shortcuts for input, output, and extraction workers.

## Check the schema or benchmark a corpus

```sh
sibilla-b extract pdf --schema-version
sibilla-b benchmark pdf -i ./samples/benchmark --workers 1,2,4
```

Record the storage type and peak memory separately; the benchmark does not measure them automatically.

## Safe demonstration

Run these commands from the repository root. The output paths must not already exist.

```sh
cargo run -p sibilla-b-pdf --example generate_fixtures -- .local/demo/samples
sibilla-b extract pdf -i .local/demo/samples --type benign \
  -o .local/demo/features.parquet --source synthetic-demo \
  --collection-id safe-generated -j 2
sibilla-b dataset build -i .local/demo/features.parquet \
  -o .local/demo/dataset --group-column collection_id
```

- Generates three safe one-page PDFs and checks that they parse.
- Keeps the shared group in one partition.
- Demonstrates the commands; it is not an evaluation corpus.

The private `.fixtures` directory is optional and not required by CI.
