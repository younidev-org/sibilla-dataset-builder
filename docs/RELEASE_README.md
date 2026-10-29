# Use Sibilla Dataset Builder

Run commands from this extracted directory. Linux x86-64 GNU binary, built on Ubuntu 24.04.

## Extract PDF features

```sh
./sibilla-b extract pdf -i ./samples --type benign -o ./features.parquet
```

Replace `./samples` with your PDF file or folder. Set `--type` to `benign`, `malicious`, or `unknown`; labels are never inferred. Existing output paths are refused.

## Build a dataset

```sh
./sibilla-b dataset build -i ./features.parquet -o ./dataset --split 70:15:15 --seed 42
```

Repeat `-i` to combine tables. Check `dataset/report.json` before using the result. Unknown labels are excluded; related files need meaningful grouping to prevent split leakage.

## Useful options

| Task | Option |
| --- | --- |
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
- This is a development implementation; `pdf-v1` is not frozen.
- Partial results contain null measurements. Indicators are not a malware verdict.
- Remove `sample_id` before training; keep labels, provenance, and quality fields out of predictive inputs.

## Detailed help online

- [CLI usage](https://github.com/younidev-org/sibilla-dataset-builder/blob/main/docs/USAGE.md)
- [Feature meanings](https://github.com/younidev-org/sibilla-dataset-builder/blob/main/docs/FEATURE_SCHEMA.md)
- [Grouping and dataset rules](https://github.com/younidev-org/sibilla-dataset-builder/blob/main/docs/DATASET_PROTOCOL.md)
- [Security limits](https://github.com/younidev-org/sibilla-dataset-builder/blob/main/SECURITY.md)

Distributed under the BSD 3-Clause License; see the included `LICENSE`.
