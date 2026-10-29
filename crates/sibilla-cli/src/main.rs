use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    name = "sibilla-b",
    version,
    about = "Offline static feature extraction and dataset construction"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Extract {
        #[command(subcommand)]
        format: Format,
    },
    Dataset {
        #[command(subcommand)]
        command: Dataset,
    },
    Benchmark {
        #[command(subcommand)]
        format: BenchmarkFormat,
    },
}
#[derive(Subcommand)]
enum Format {
    Pdf(Extract),
}
#[derive(Subcommand)]
enum BenchmarkFormat {
    Pdf(Benchmark),
}
#[derive(Subcommand)]
enum Dataset {
    Build(Build),
}
#[derive(Clone, Copy, ValueEnum)]
enum Label {
    Benign,
    Malicious,
    Unknown,
}
#[derive(Args)]
struct Extract {
    #[arg(long, required_unless_present = "schema_version")]
    input: Option<PathBuf>,
    #[arg(long = "type", value_enum, default_value = "unknown")]
    label: Label,
    #[arg(long, required_unless_present = "schema_version")]
    output: Option<PathBuf>,
    #[arg(long, default_value_t = 1)]
    workers: usize,
    #[arg(long, default_value_t = 64)]
    max_size_mb: u64,
    #[arg(long, default_value_t = 30)]
    timeout_seconds: u64,
    #[arg(long, default_value_t = 128)]
    max_decompressed_mb: u64,
    #[arg(long)]
    resume: bool,
    #[arg(long)]
    failures: Option<PathBuf>,
    #[arg(long)]
    quiet: bool,
    #[arg(long)]
    no_recursive: bool,
    #[arg(long)]
    follow_symlinks: bool,
    #[arg(long)]
    source: Option<String>,
    #[arg(long)]
    collection_id: Option<String>,
    #[arg(long)]
    schema_version: bool,
    #[arg(long)]
    format: Option<String>,
}
#[derive(Args)]
struct Build {
    #[arg(long, required = true)]
    input: Vec<PathBuf>,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value = "70:15:15")]
    split: String,
    #[arg(long, default_value_t = 42)]
    seed: u64,
    #[arg(long)]
    group_column: Option<String>,
    #[arg(long)]
    temporal_column: Option<String>,
    #[arg(long, default_value = "error")]
    conflict_policy: String,
}
#[derive(Args)]
struct Benchmark {
    #[arg(long)]
    input: PathBuf,
    #[arg(long, default_value = "1,4,8,12")]
    workers: String,
}
fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Extract {
            format: Format::Pdf(args),
        } if args.schema_version => println!("{}", sibilla_schema::SCHEMA_VERSION),
        _ => bail!(
            "This foundation build exposes the CLI contract; extraction, datasets and benchmarks are not implemented yet"
        ),
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_contract() {
        assert!(Cli::try_parse_from(["sibilla-b", "extract", "pdf", "--schema-version"]).is_ok());
        assert!(Cli::try_parse_from(["sibilla-b", "extract", "pdf"]).is_err());
        assert!(
            Cli::try_parse_from([
                "sibilla-b",
                "extract",
                "pdf",
                "--input",
                "samples",
                "--type",
                "malicious",
                "--output",
                "features.parquet"
            ])
            .is_ok()
        );
    }
}
