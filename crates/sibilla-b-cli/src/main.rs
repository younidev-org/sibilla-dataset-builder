// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 younidev-org.

mod benchmark;
mod config;
mod extract;
mod inspect;
mod interrupt;
mod ui;
use anyhow::{Context, Result, bail};
use clap::{Args, ColorChoice, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    name = "sibilla-b",
    version,
    about = "Extract static PDF features and build reproducible datasets offline",
    arg_required_else_help = true,
    after_help = "Command options used below:\n  -i, --input PATH    PDF file or folder for extraction; feature table for dataset build\n  -o, --output PATH   New output file or dataset directory (existing paths are refused)\n                     Extraction: use .parquet or .csv, or pass --format\n  -j, --workers N     Parallel workers (extract: parsers; dataset: output writers)\n  --type LABEL       benign, malicious, or unknown (required for extraction)\n\nFull command options:\n  sibilla-b extract pdf --help\n  sibilla-b dataset build --help\n  sibilla-b benchmark pdf --help\n\nExamples:\n  sibilla-b extract pdf -i samples -o features.parquet --type benign\n  sibilla-b dataset build -i features.parquet -o datasets/pdf-v5\n  sibilla-b benchmark pdf -i samples --workers 1,2,4\n  sibilla-b --color never extract pdf --help"
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
    /// Show progress even when the config enables quiet mode
    #[arg(long, global = true, conflicts_with = "quiet")]
    no_quiet: bool,
    #[command(subcommand)]
    command: Command,
}
// Parsed once; owned variants keep the Clap interface simpler than boxed argument plumbing.
#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Inspect every row of an extraction table, including partial reasons and missing values
    Inspect {
        /// CSV or Parquet extraction table
        input: PathBuf,
        /// Print a machine-readable summary
        #[arg(long)]
        json: bool,
        /// Show readable column names alongside their exported names
        #[arg(long)]
        columns: bool,
    },
    #[command(hide = true)]
    Worker,
    /// Generate or validate commented configuration files
    Config {
        #[command(subcommand)]
        command: config::ConfigCommand,
    },
    /// Extract versioned feature tables using a config or an inline format command
    #[command(subcommand_negates_reqs = true, args_conflicts_with_subcommands = true)]
    Extract {
        #[command(flatten)]
        args: Extract,
        #[command(subcommand)]
        format: Option<Format>,
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
        after_help = "Output format:\n  Use an output ending in .parquet or .csv.\n  For a filename without an extension, pass --format parquet or --format csv.\n  Input files are read-only. Output paths must be new.\n\nExamples:\n  sibilla-b extract pdf -i sample.pdf --type unknown -o features.parquet\n  sibilla-b extract pdf -i benign_pdf_candidates --type benign -o benign_pdf_output.parquet\n  sibilla-b extract pdf -i samples --type unknown -o features.csv -j 4\n  sibilla-b extract pdf -i samples --type unknown -o features.parquet --resume"
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
#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Label {
    Benign,
    Malicious,
    Unknown,
}
#[derive(Args, Serialize, Deserialize)]
#[group(skip)]
struct Extract {
    /// Read extraction settings from a versioned TOML config
    #[arg(long)]
    config: Option<PathBuf>,
    /// Disable JPEG decoding explicitly, overriding config
    #[arg(long, conflicts_with = "decode_images")]
    no_decode_images: bool,
    /// Enable recursive scanning explicitly, overriding config
    #[arg(long, conflicts_with = "no_recursive")]
    recursive: bool,
    /// Skip symlinks explicitly, overriding config
    #[arg(long, conflicts_with = "follow_symlinks")]
    no_follow_symlinks: bool,
    #[arg(skip)]
    selection: sibilla_b_schema::profile::FeatureSelection,
    #[arg(skip)]
    snapshot: Option<serde_json::Value>,
    /// Attempt bounded JPEG image decoding in decoded mode
    #[arg(long)]
    decode_images: bool,
    /// Collect structure only, or also attempt bounded stream decoding
    #[arg(long, default_value = "decoded", value_parser = ["structural", "decoded"])]
    stream_mode: String,
    /// Input file or directory (recursive by default)
    #[arg(short = 'i', long, required_unless_present_any = ["schema_version", "config"])]
    input: Option<PathBuf>,
    /// Required explicit label; use unknown for unlabeled extraction
    #[arg(long = "type", value_enum, required_unless_present_any = ["schema_version", "config"])]
    label: Option<Label>,
    /// New .csv or .parquet file (or set --format); existing paths are refused
    #[arg(short = 'o', long, required_unless_present_any = ["schema_version", "config"])]
    output: Option<PathBuf>,
    /// Process at most N files, selected in sorted path order (N must be positive)
    #[arg(long)]
    limit: Option<std::num::NonZeroUsize>,
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
    /// Start a new run even when the config requests resume
    #[arg(long, conflicts_with = "resume")]
    no_resume: bool,
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
#[derive(Args, Serialize, Deserialize)]
struct Build {
    /// Read dataset settings from a versioned TOML config
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(skip)]
    projection: sibilla_b_dataset::projection::ProjectionOptions,
    #[arg(skip)]
    snapshot: Option<serde_json::Value>,
    /// Output writer limit (1–256); manifest and features use at most two writers
    #[arg(short='j',long,default_value_t=default_workers() as u16,value_parser=clap::value_parser!(u16).range(1..=256))]
    workers: u16,
    /// Feature table; repeat -i to merge multiple tables
    #[arg(short = 'i', long, required_unless_present = "config")]
    input: Vec<PathBuf>,
    /// New dataset directory; existing paths are refused
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
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
    let mut cli = Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit());
    if let Err(error) = config::presentation(&mut cli, &matches) {
        eprintln!("error: {error:#}");
        return std::process::ExitCode::FAILURE;
    }
    let color = if cli.no_color {
        ColorChoice::Never
    } else if cli.color == ColorChoice::Always {
        color
    } else {
        cli.color
    };
    let ui = ui::Ui::new(color, cli.quiet);
    match run(cli, &ui, &matches) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "{} {error:#}",
                console::style("error:").red().bold().for_stderr()
            );
            if error.is::<interrupt::Interrupted>() {
                std::process::ExitCode::from(130)
            } else {
                std::process::ExitCode::FAILURE
            }
        }
    }
}
/// Dispatch the selected CLI command without contaminating machine-readable stdout.
fn run(cli: Cli, ui: &ui::Ui, matches: &clap::ArgMatches) -> Result<()> {
    match cli.command {
        Command::Inspect {
            input,
            json,
            columns,
        } => inspect::run(&input, json, columns)?,
        Command::Worker => sibilla_b_core::worker_loop(sibilla_b_pdf::PdfExtractor)?,
        Command::Config { command } => config::command(command)?,
        Command::Extract { args, format } => {
            let extract_matches = matches
                .subcommand_matches("extract")
                .context("extract arguments")?;
            let (args, argument_matches) = match format {
                Some(Format::Pdf(args)) => (
                    args,
                    extract_matches
                        .subcommand_matches("pdf")
                        .context("PDF arguments")?,
                ),
                None => (args, extract_matches),
            };
            if args.schema_version {
                println!("{}", sibilla_b_schema::SCHEMA_VERSION);
            } else {
                extract::run(config::resolve_extract(args, argument_matches)?, ui)?;
            }
        }
        Command::Dataset {
            command: Dataset::Build(args),
        } => {
            let mut args = config::resolve_build(
                args,
                matches
                    .subcommand_matches("dataset")
                    .and_then(|m| m.subcommand_matches("build"))
                    .context("build arguments")?,
            )?;
            if let Some(snapshot) = args.snapshot.as_mut() {
                snapshot["settings"]["presentation"] =
                    serde_json::json!({"quiet":ui.quiet,"color_enabled":ui.color});
                snapshot["run_hash"] =
                    serde_json::Value::from(config::fingerprint(&snapshot["settings"])?);
            }
            let output = args.output.as_ref().context("output is required")?;
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
            sibilla_b_dataset::build_configured(
                &args.input,
                output,
                split,
                args.seed,
                args.group_column.as_deref(),
                args.conflict_policy == "quarantine",
                args.workers as usize,
                &args.projection,
                args.snapshot.as_ref(),
            )?;
            progress.finish_and_clear();
            ui.success(&format!("Dataset saved to {}", output.display()));
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
                "-i",
                "samples",
                "-o",
                "out.csv"
            ])
            .is_err()
        );
        for label in ["benign", "malicious", "unknown"] {
            assert!(
                Cli::try_parse_from([
                    "sibilla-b",
                    "extract",
                    "pdf",
                    "-i",
                    "samples",
                    "-o",
                    "out.csv",
                    "--type",
                    label
                ])
                .is_ok()
            );
        }
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
