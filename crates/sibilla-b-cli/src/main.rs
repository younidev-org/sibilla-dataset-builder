mod benchmark;
mod extract;
mod ui;
use anyhow::{Result, bail};
use clap::{Args, ColorChoice, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    name = "sibilla-b",
    version,
    about = "Extract static PDF features and build reproducible datasets offline",
    arg_required_else_help = true,
    after_help = "Command options used below:\n  -i, --input PATH    PDF file or folder for extraction; feature table for dataset build\n  -o, --output PATH   New output file or dataset directory (existing paths are refused)\n                     Extraction: use .parquet or .csv, or pass --format\n  -j, --workers N     Parallel extraction workers\n  --type LABEL       benign, malicious, or unknown (default: unknown)\n\nFull command options:\n  sibilla-b extract pdf --help\n  sibilla-b dataset build --help\n  sibilla-b benchmark pdf --help\n\nExamples:\n  sibilla-b extract pdf -i samples -o features.parquet --type benign\n  sibilla-b dataset build -i features.parquet -o datasets/pdf-v1\n  sibilla-b benchmark pdf -i samples --workers 1,2,4\n  sibilla-b --color never extract pdf --help"
)]
struct Cli {
    /// Color output: enabled by default; auto detects terminals
    #[arg(long, global = true, value_enum, default_value = "always")]
    color: ColorChoice,
    /// Disable ANSI colors in help, errors and progress output
    #[arg(long, global = true, conflicts_with = "color")]
    no_color: bool,
    /// Hide progress and status messages
    #[arg(short = 'q', long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    #[command(hide = true)]
    Worker,
    /// Extract versioned feature tables from files or directories
    Extract {
        #[command(subcommand)]
        format: Format,
    },
    /// Assemble labeled datasets with deduplication and reproducible splits
    Dataset {
        #[command(subcommand)]
        command: Dataset,
    },
    /// Measure real extraction throughput at different worker counts
    Benchmark {
        #[command(subcommand)]
        format: BenchmarkFormat,
    },
}
#[derive(Subcommand)]
enum Format {
    /// Extract PDF byte, structural and active-content indicators
    #[command(
        after_help = "Output format:\n  Use an output ending in .parquet or .csv.\n  For a filename without an extension, pass --format parquet or --format csv.\n  Input files are read-only. Output paths must be new.\n\nExamples:\n  sibilla-b extract pdf -i sample.pdf -o features.parquet\n  sibilla-b extract pdf -i benign_pdf_candidates --type benign -o benign_pdf_output.parquet\n  sibilla-b extract pdf -i samples -o features.csv -j 4\n  sibilla-b extract pdf -i samples -o features.parquet --resume"
    )]
    Pdf(Extract),
}
#[derive(Subcommand)]
enum BenchmarkFormat {
    /// Benchmark the complete PDF extraction pipeline
    Pdf(Benchmark),
}
#[derive(Subcommand)]
enum Dataset {
    /// Validate tables, deduplicate samples and write train/validation/test splits
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
    /// Input file or directory (recursive by default)
    #[arg(short = 'i', long, required_unless_present = "schema_version")]
    input: Option<PathBuf>,
    /// Explicit label; never inferred from paths or content
    #[arg(long = "type", value_enum, default_value = "unknown")]
    label: Label,
    /// New .csv or .parquet file (or set --format); existing paths are refused
    #[arg(short = 'o', long, required_unless_present = "schema_version")]
    output: Option<PathBuf>,
    /// Parallel parser processes (1–256)
    #[arg(short='j',long, default_value_t = default_workers())]
    workers: usize,
    /// Maximum input file size in MiB
    #[arg(long, default_value_t = 64)]
    max_size_mb: u64,
    /// Wall-clock timeout per file in seconds
    #[arg(long, default_value_t = 30)]
    timeout_seconds: u64,
    /// Decoded stream measurement budget in MiB
    #[arg(long, default_value_t = 128)]
    max_decompressed_mb: u64,
    /// Reuse committed checkpoints after validating configuration and source hashes
    #[arg(long)]
    resume: bool,
    /// Write partial/failed/rejected records to an independent JSONL sidecar
    #[arg(long)]
    failures: Option<PathBuf>,
    /// Scan only the immediate directory
    #[arg(long)]
    no_recursive: bool,
    /// Resolve symlinks explicitly; targets may lie outside the input tree
    #[arg(long)]
    follow_symlinks: bool,
    /// Source name stored as provenance, never as a predictive feature
    #[arg(long)]
    source: Option<String>,
    /// Collection identifier stored as provenance
    #[arg(long)]
    collection_id: Option<String>,
    /// Print schema version without extracting files
    #[arg(long)]
    schema_version: bool,
    /// Choose csv or parquet explicitly; required if output has no recognized extension
    #[arg(long,value_parser=["csv","parquet"])]
    format: Option<String>,
}
#[derive(Args)]
struct Build {
    /// Feature table; repeat -i to merge multiple tables
    #[arg(short = 'i', long, required = true)]
    input: Vec<PathBuf>,
    /// New dataset directory; existing paths are refused
    #[arg(short = 'o', long)]
    output: PathBuf,
    /// Train:validation:test percentages, totaling 100
    #[arg(long, default_value = "70:15:15")]
    split: String,
    /// Seed for reproducible group allocation
    #[arg(long, default_value_t = 42)]
    seed: u64,
    /// Keep related samples from this metadata column in the same partition
    #[arg(long)]
    group_column: Option<String>,
    /// Reserved: first-seen timestamps are not available in this schema
    #[arg(long)]
    temporal_column: Option<String>,
    /// Handle contradictory labels for identical sample hashes
    #[arg(long, default_value = "error",value_parser=["error","quarantine"])]
    conflict_policy: String,
}
#[derive(Args)]
struct Benchmark {
    /// Corpus file or directory
    #[arg(short = 'i', long)]
    input: PathBuf,
    /// Comma-separated worker counts to compare
    #[arg(short = 'j', long, default_value = "1,4,8,12")]
    workers: String,
}
/// Choose a CPU-aware worker count capped at 32 parser processes.
fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(32)
}
/// Parse CLI options, initialize presentation and report command failures with an exit code.
fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args_os().collect();
    let color = ui::color_choice(&args);
    let styles = clap::builder::Styles::styled()
        .header(clap::builder::styling::AnsiColor::Cyan.on_default().bold())
        .usage(clap::builder::styling::AnsiColor::Cyan.on_default().bold())
        .literal(clap::builder::styling::AnsiColor::Green.on_default().bold());
    let matches = Cli::command()
        .color(color)
        .styles(styles)
        .get_matches_from(args);
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit());
    let ui = ui::Ui::new(color, cli.quiet);
    match run(cli, &ui) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "{} {error:#}",
                console::style("error:").red().bold().for_stderr()
            );
            std::process::ExitCode::FAILURE
        }
    }
}
/// Dispatch the selected CLI command without contaminating machine-readable stdout.
fn run(cli: Cli, ui: &ui::Ui) -> Result<()> {
    match cli.command {
        Command::Worker => sibilla_b_core::worker_loop(sibilla_b_pdf::PdfExtractor)?,
        Command::Extract {
            format: Format::Pdf(args),
        } if args.schema_version => println!("{}", sibilla_b_schema::SCHEMA_VERSION),
        Command::Extract {
            format: Format::Pdf(args),
        } => extract::run(args, ui)?,
        Command::Dataset {
            command: Dataset::Build(args),
        } => {
            if args.temporal_column.is_some() {
                bail!("temporal mode requires timestamps not present in the current schema");
            }
            let split: Vec<u64> = args
                .split
                .split(':')
                .map(str::parse)
                .collect::<std::result::Result<_, _>>()?;
            let split: [u64; 3] = split
                .try_into()
                .map_err(|_| anyhow::anyhow!("split requires TRAIN:VAL:TEST"))?;
            if !matches!(args.conflict_policy.as_str(), "error" | "quarantine") {
                bail!("invalid conflict policy");
            }
            let progress = ui.progress("Building dataset", None);
            sibilla_b_dataset::build(
                &args.input,
                &args.output,
                split,
                args.seed,
                args.group_column.as_deref(),
                args.conflict_policy == "quarantine",
            )?;
            progress.finish_and_clear();
            ui.success(&format!("Dataset saved to {}", args.output.display()));
        }
        Command::Benchmark {
            format: BenchmarkFormat::Pdf(args),
        } => benchmark::run(args, ui)?,
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    /// Check required arguments and schema-version-only invocation.
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
