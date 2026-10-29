<a href="https://github.com/younidev-org/sibilla-dataset-builder"><img src="docs/assets/sibilla-dataset-builder-banner.svg" alt="Sibilla Dataset Builder" width="100%"></a>

<div align="center">

  <p align="center">
    <a href="https://www.kernel.org/"><img src="https://img.shields.io/badge/Linux-5.6%2B-FCC624?style=for-the-badge&amp;logo=linux&amp;logoColor=black" alt="Platform: Linux 5.6 or newer"></a>
    <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-1.88%2B-000000?style=for-the-badge&amp;logo=rust&amp;logoColor=white" alt="Rust: 1.88 or newer"></a>
    <a href="https://github.com/younidev-org/sibilla-dataset-builder/releases"><img src="https://img.shields.io/badge/Release-View_Releases-2EA44F?style=for-the-badge" alt="View project releases"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-BSD--3--Clause-2EA44F?style=for-the-badge" alt="License: BSD 3-Clause"></a>
    <a href="docs/README.md"><img src="https://img.shields.io/badge/Documentation%20Hub-0969DA?style=for-the-badge&amp;logo=mdbook&amp;logoColor=white" alt="Open the Sibilla Dataset Builder documentation hub"></a>
  </p>

  <p>An offline Rust CLI for extracting static PDF features and assembling reproducible datasets.</p>

  <p align="center">
    <a href="#features">Features</a> •
    <a href="#showcase">Showcase</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#development">Development</a> •
    <a href="#guides">Guides</a>
  </p>
</div>

---

## Features

- 🔎 **Static PDF features:** byte statistics, 256 histogram columns, structural measurements, and separate raw-token and parsed-name counts.
- ⚙️ **Supervised parsing:** reusable worker processes with timeouts, CPU and memory limits, and Linux network restrictions.
- 📊 **Typed output:** CSV and Parquet tables with explicit nulls, quality metadata, and optional JSONL failure sidecars.
- ♻️ **Validated resume:** source-hash checks, synchronized checkpoints, atomic publication, and refusal to overwrite existing outputs.
- 🧬 **Dataset construction:** exact deduplication, label-conflict handling, reproducible group-aware splits, manifests, reports, and artifact hashes.
- 🎛️ **Terminal controls:** colored help, progress bars, short options, quiet mode, and clean machine-readable stdout.
- 🧪 **Safe development:** generated nonmalicious fixtures, nextest checks, and real extraction benchmarks.

```mermaid
flowchart LR
    Inputs[Input files] --> Discovery[Discovery]
    Discovery --> Workers[Restricted workers]
    Workers --> Checkpoints[Checkpoints]
    Checkpoints --> Tables[CSV or Parquet]
    Tables --> Dataset[Dataset and splits]
```

> [!CAUTION]
> This is a development implementation: `pdf-v1` is not frozen. Worker restrictions are not full filesystem or kernel isolation; use a dedicated VM/container for untrusted inputs. The tool never executes samples, renders PDFs, contacts URLs, or trains models.

<details>
<summary><strong>Current limitations</strong></summary>

- Temporal evaluation is rejected because the schema has no defensible first-seen timestamps.
- The full specified PDF feature schema is unfinished; unsupported measurements remain null.
- Discovery paths and identity/group metadata remain in memory. Feature rows spool to disk, but million-file scaling and external sorting are unfinished.
- Worker memory, CPU, descriptor, and network controls do not provide complete isolation.
- Explicit stream measurements share an aggregate decode budget; parser-internal expansion is limited per stream and by process memory. Stronger sandbox and aggregate parser accounting remain unfinished.
- Benchmarks cover complete extraction; peak memory and storage type are not automatically measured and must be recorded separately.

</details>

## Showcase

No runtime screenshots are included; the [safe demonstration](docs/USAGE.md#safe-demonstration) generates three one-page PDFs and builds a grouped dataset from them.

## Quick start

The executable is `target/release/sibilla-b`. Provide your own input files; labels are supplied explicitly and never inferred. The optional private `.fixtures` corpus is not required by CI.

### Configuration overview

| Area | Configure | Available options |
| --- | --- | --- |
| Labels | `--type` | `benign`, `malicious`, `unknown` → `0`, `1`, null |
| Output | `--output`, `--format` | CSV or Parquet; explicit format overrides the extension |
| Traversal | `--no-recursive`, `--follow-symlinks` | Recursive by default; symlink following is opt-in |
| Terminal | `--color`, `--no-color`, `--quiet` | Color defaults to `always`; `auto` and `never` are available |

Files are opened read-only and existing outputs are refused. Symlink following can include files outside the input tree. See the [usage guide](docs/USAGE.md) for dataset commands, checkpoint behavior, failure handling, and the synthetic demonstration.

## Development

Install nextest if needed with `cargo install cargo-nextest --locked`.

| Need | Command |
| --- | --- |
| Run tests | `cargo nextest run --workspace --all-targets --locked` |
| Check formatting | `cargo fmt --all --check` |
| Run Clippy | `cargo clippy --workspace --all-targets --locked -- -D warnings` |
| Build the CLI | `cargo build --release --locked` |
| Generate safe fixtures | `cargo run -p sibilla-b-pdf --example generate_fixtures -- .local/demo/samples` |

Normal CI runs only on pushes to `main`. Version tags trigger qualification and a draft release; the tag must match the workspace version and `main` HEAD. See [CI and releases](docs/RELEASES.md) for checks, archives, checksums, and publication policy.

## Guides

Choose a guide by task, or browse the complete [documentation hub](docs/README.md):

| I want to… | Start here |
| --- | --- |
| Extract features, resume a run, or try the safe demo | [CLI usage](docs/USAGE.md) |
| Understand columns, nulls, and measurement limits | [Feature schema](docs/FEATURE_SCHEMA.md) |
| Build datasets and avoid split leakage | [Dataset protocol](docs/DATASET_PROTOCOL.md) |
| Understand worker and storage boundaries | [Architecture](docs/ARCHITECTURE.md) |
| Review input handling and isolation limits | [Security](SECURITY.md) |
| Understand CI and draft releases | [CI and releases](docs/RELEASES.md) |

## Tech stack

<p align="left">
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-1.88%2B-000000?style=for-the-badge&amp;logo=rust&amp;logoColor=white" alt="Rust 1.88 or newer"></a>
  <a href="https://www.kernel.org/"><img src="https://img.shields.io/badge/Linux-5.6%2B-FCC624?style=for-the-badge&amp;logo=linux&amp;logoColor=black" alt="Linux 5.6 or newer"></a>
  <a href="https://docs.rs/clap/4.6.7/clap/"><img src="https://img.shields.io/badge/clap-4.6.7-4479A1?style=for-the-badge" alt="clap 4.6.7 CLI argument parsing"></a>
  <a href="https://docs.rs/lopdf/0.46.0/lopdf/"><img src="https://img.shields.io/badge/lopdf-0.46.0-4479A1?style=for-the-badge" alt="lopdf 0.46.0 static PDF parsing"></a>
  <a href="https://arrow.apache.org/"><img src="https://img.shields.io/badge/Apache_Arrow-60.1.0-D22128?style=for-the-badge" alt="Apache Arrow 60.1.0 typed tables"></a>
  <a href="https://parquet.apache.org/"><img src="https://img.shields.io/badge/Apache_Parquet-60.1.0-D22128?style=for-the-badge" alt="Apache Parquet 60.1.0 table storage"></a>
  <a href="https://docs.rs/indicatif/0.18.6/indicatif/"><img src="https://img.shields.io/badge/indicatif-0.18.6-4479A1?style=for-the-badge" alt="indicatif 0.18.6 terminal progress"></a>
  <a href="https://nexte.st/"><img src="https://img.shields.io/badge/cargo_nextest-Test_runner-4479A1?style=for-the-badge" alt="cargo nextest test runner"></a>
</p>

---

## License

Distributed under the [BSD 3-Clause License](LICENSE).
