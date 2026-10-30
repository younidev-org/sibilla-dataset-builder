# Use Sibilla Dataset Builder

Run commands from this extracted directory. Linux x86-64 GNU binary, built on Ubuntu 24.04.

## Extract PDF features

```sh
./sibilla-b extract pdf -i ./samples --type benign -o ./features.parquet
```

Replace `./samples` with your PDF file or folder. `--type` is required. Set it to `benign`, `malicious`, or `unknown`; labels are never inferred. Existing output paths are refused.

For byte and structural features without optional stream decoding, add `--stream-mode structural`.
The default `decoded` mode attempts bounded decoding; unsupported image filters can produce partial results while structural features remain available.

Decoded mode also measures action relationships, scripts, attachment signatures and URL syntax without executing content. Inspect structure/payload analysis status before interpreting missing values.

## Build a dataset

```sh
./sibilla-b dataset build -i ./features.parquet -o ./dataset --split 70:15:15 --seed 42 -j 2
```

Repeat `-i` to combine tables from the same schema, extractor version, and stream mode. Check `dataset/report.json` before using the result. Unknown labels are excluded; related files need meaningful grouping to prevent split leakage.

## Inspect the result

```sh
./sibilla-b inspect ./features.parquet
./sibilla-b inspect ./features.parquet --json
```

Shows full row counts, labels, statuses, error reasons, missing measurements, decoding statuses and unsupported filter names. Use `--columns` for readable column names.

## Useful options

| Task | Option |
| --- | --- |
| Process at most 10,000 files | `--limit 10000` |
| Choose extraction workers | `-j 4` |
| Resume extraction with the original arguments | `--resume` |
| Disable colors | `--no-color` |
| Hide progress and status | `--quiet` |
| Save extraction problems | `--failures failures.jsonl` |
| Get command help | `./sibilla-b extract pdf --help` |

Keep the hidden checkpoint directory beside the output if you need to resume.

## Safety and results

- Use a dedicated VM/container for untrusted PDFs. Process restrictions are not complete isolation.
- The tool never executes or renders samples and never contacts extracted URLs.
- This is a development implementation; `pdf-v4` is not frozen.
- Older `pdf-v1`/`pdf-v2` tables/checkpoints require re-extraction to use this version.
- Partial results contain null measurements. Indicators are not a malware verdict.
- Remove `sample_id` before training; keep labels, provenance, and quality fields out of predictive inputs.

## Detailed help online

- [CLI usage](https://github.com/younidev-org/sibilla-dataset-builder/blob/main/docs/USAGE.md)
- [Feature meanings](https://github.com/younidev-org/sibilla-dataset-builder/blob/main/docs/FEATURE_SCHEMA.md)
- [Grouping and dataset rules](https://github.com/younidev-org/sibilla-dataset-builder/blob/main/docs/DATASET_PROTOCOL.md)
- [Security limits](https://github.com/younidev-org/sibilla-dataset-builder/blob/main/SECURITY.md)

Distributed under the BSD 3-Clause License; see the included `LICENSE`.
