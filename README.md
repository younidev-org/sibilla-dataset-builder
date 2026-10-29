# Sibilla Dataset Builder

`sibilla-b` is an offline Rust CLI for static PDF feature extraction and
reproducible dataset construction. It never executes samples or trains models.

## Build and checks

Rust 1.88 or newer:

```sh
cargo build --release --locked
cargo test --workspace --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo run -p sibilla-cli -- --help
cargo run -p sibilla-cli -- extract pdf --schema-version
```

## Development status

Foundation implemented: seven independent workspace crates, typed extraction
contract, byte statistics, CLI argument contract, and CI. PDF parsing and reusable restricted Linux workers are implemented. Output,
extraction orchestration, dataset construction and benchmarking are being implemented;
commands that are not ready fail explicitly. No performance claims yet.

See [implementation plan](docs/IMPLEMENTATION_PLAN.md). The private `.fixtures`
corpus is optional and never required by CI. Treat all PDF bytes as untrusted.
