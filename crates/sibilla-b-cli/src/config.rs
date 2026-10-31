// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 younidev-org.

//! Strict TOML resolution; CLI presence, not Clap defaults, determines override precedence.
use crate::{Build, Extract, Label};
use anyhow::{Context, Result, bail};
use clap::{ArgMatches, Subcommand, parser::ValueSource};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
};
/// Configuration utilities perform no extraction or worker dispatch.
#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Write a commented template to a new file
    Init {
        #[arg(long,default_value="pdf",value_parser=["pdf"])]
        format: String,
        #[arg(long,default_value="extract",value_parser=["extract","dataset"])]
        command: String,
        #[arg(short = 'o', long)]
        output: PathBuf,
    },
    /// Resolve and validate settings without creating output artifacts
    Check { path: PathBuf },
}
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Input {
    path: Option<PathBuf>,
    paths: Option<Vec<PathBuf>>,
    format: Option<String>,
    label: Option<Label>,
    limit: Option<std::num::NonZeroUsize>,
    recursive: Option<bool>,
    follow_symlinks: Option<bool>,
}
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Output {
    path: Option<PathBuf>,
    format: Option<String>,
    failures: Option<PathBuf>,
}
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Runtime {
    workers: Option<u16>,
    timeout_seconds: Option<u64>,
    input_mib: Option<u64>,
    resume: Option<bool>,
    quiet: Option<bool>,
    color: Option<String>,
}
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Provenance {
    source: Option<String>,
    collection_id: Option<String>,
}
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CommonFeatures {
    groups: Option<Vec<String>>,
}
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Features {
    common: CommonFeatures,
}
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Pdf {
    groups: Option<Vec<String>>,
    stream_mode: Option<String>,
    decode_images: Option<bool>,
    decoded_mib: Option<u64>,
}
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Formats {
    pdf: Pdf,
}
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Split {
    percentages: Option<[u64; 3]>,
    seed: Option<u64>,
    group_column: Option<String>,
}
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Policy {
    conflict_policy: Option<String>,
}
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Columns {
    groups: Vec<String>,
    exclude: Vec<String>,
}
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Cleanup {
    drop_all_null: bool,
    drop_constant: bool,
}
impl Default for Cleanup {
    /// Config-first datasets remove all-null training columns unless explicitly disabled.
    fn default() -> Self {
        Self {
            drop_all_null: true,
            drop_constant: false,
        }
    }
}
/// Versioned config sections are shared only where semantics really match across commands.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    config_version: u32,
    command: String,
    #[serde(default)]
    input: Input,
    #[serde(default)]
    output: Output,
    #[serde(default)]
    runtime: Runtime,
    #[serde(default)]
    provenance: Provenance,
    features: Option<Features>,
    formats: Option<Formats>,
    split: Option<Split>,
    policy: Option<Policy>,
    columns: Option<Columns>,
    aliases: Option<BTreeMap<String, String>>,
    cleanup: Option<Cleanup>,
}
/// Parse the schema before resolving paths; reject unsupported commands and irrelevant sections.
pub fn load(path: &Path) -> Result<ConfigFile> {
    let c: ConfigFile = toml::from_str(
        &std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?,
    )
    .context("invalid TOML configuration")?;
    if c.config_version != 1 {
        bail!(
            "unsupported config_version {}; expected 1",
            c.config_version
        );
    }
    if c.runtime
        .color
        .as_deref()
        .is_some_and(|v| !matches!(v, "always" | "auto" | "never"))
    {
        bail!("runtime.color must be always, auto, or never");
    }
    match c.command.as_str() {
        "extract" => {
            if c.split.is_some()
                || c.policy.is_some()
                || c.columns.is_some()
                || c.aliases.is_some()
                || c.cleanup.is_some()
                || c.input.paths.is_some()
            {
                bail!("dataset sections are not valid in an extraction config");
            }
        }
        "dataset" => {
            if c.formats.is_some()
                || c.features.is_some()
                || c.input.path.is_some()
                || c.input.format.is_some()
                || c.input.label.is_some()
                || c.input.limit.is_some()
                || c.input.recursive.is_some()
                || c.input.follow_symlinks.is_some()
                || c.output.format.is_some()
                || c.output.failures.is_some()
                || c.runtime.timeout_seconds.is_some()
                || c.runtime.input_mib.is_some()
                || c.runtime.resume.is_some()
                || c.provenance.source.is_some()
                || c.provenance.collection_id.is_some()
            {
                bail!("extraction sections are not valid in a dataset config");
            }
        }
        _ => bail!("unknown config command: {}", c.command),
    }
    if c.input.format.as_deref().is_some_and(|f| f != "pdf") {
        bail!("only format pdf is implemented; PE, JavaScript and auto routing are not available");
    }
    Ok(c)
}
/// Normalize paths lexically, without requiring output paths to exist or following symlinks.
fn absolute(path: &Path, base: &Path) -> PathBuf {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    };
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            c => out.push(c.as_os_str()),
        }
    }
    out
}
/// Identify only explicit flags; resolved defaults must never mask file settings.
fn explicit(matches: &ArgMatches, id: &str) -> bool {
    matches.try_get_raw(id).is_ok() && matches.value_source(id) == Some(ValueSource::CommandLine)
}
/// Canonically hash JSON so key order and TOML formatting cannot change fingerprints.
pub fn fingerprint(value: &Value) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}
/// Apply TOML values to the existing inline options unless an explicit flag overrides them.
pub fn resolve_extract(mut a: Extract, m: &ArgMatches) -> Result<Extract> {
    let cwd = std::env::current_dir()?;
    if let Some(path) = &a.config {
        let c = load(path)?;
        if c.command != "extract" {
            bail!("extraction requires command = extract");
        }
        let base = absolute(path, &cwd)
            .parent()
            .context("config directory")?
            .to_owned();
        macro_rules! scalar {
            ($id:ident,$value:expr) => {
                if !explicit(m, stringify!($id))
                    && let Some(v) = $value
                {
                    a.$id = v.into();
                }
            };
        }
        if !explicit(m, "input") {
            a.input = c.input.path.map(|p| absolute(&p, &base));
        }
        if !explicit(m, "output") {
            a.output = c.output.path.map(|p| absolute(&p, &base));
        }
        if !explicit(m, "label") {
            a.label = c.input.label;
        }
        if !explicit(m, "limit") {
            a.limit = c.input.limit;
        }
        if !explicit(m, "format") {
            a.format = c.output.format;
        }
        if !explicit(m, "failures") {
            a.failures = c.output.failures.map(|p| absolute(&p, &base));
        }
        if !explicit(m, "source") {
            a.source = c.provenance.source;
        }
        if !explicit(m, "collection_id") {
            a.collection_id = c.provenance.collection_id;
        }
        scalar!(workers, c.runtime.workers.map(usize::from));
        scalar!(timeout_seconds, c.runtime.timeout_seconds);
        scalar!(max_size_mb, c.runtime.input_mib);
        scalar!(resume, c.runtime.resume);
        if !explicit(m, "recursive")
            && !explicit(m, "no_recursive")
            && let Some(recursive) = c.input.recursive
        {
            a.no_recursive = !recursive;
        }
        if !explicit(m, "follow_symlinks")
            && !explicit(m, "no_follow_symlinks")
            && let Some(follow) = c.input.follow_symlinks
        {
            a.follow_symlinks = follow;
        }
        if let Some(features) = c.features
            && let Some(groups) = features.common.groups
        {
            a.selection.groups.retain(|g| !g.starts_with("common."));
            a.selection
                .groups
                .extend(groups.into_iter().map(|g| format!("common.{g}")));
        }
        if let Some(formats) = c.formats {
            let pdf = formats.pdf;
            scalar!(stream_mode, pdf.stream_mode);
            scalar!(max_decompressed_mb, pdf.decoded_mib);
            if !explicit(m, "decode_images")
                && !explicit(m, "no_decode_images")
                && let Some(v) = pdf.decode_images
            {
                a.decode_images = v;
            }
            if let Some(groups) = pdf.groups {
                a.selection.groups.retain(|g| !g.starts_with("pdf."));
                a.selection
                    .groups
                    .extend(groups.into_iter().map(|g| format!("pdf.{g}")));
            }
        }
    }
    if a.no_resume {
        a.resume = false;
    }
    if a.no_decode_images {
        a.decode_images = false;
    }
    if a.recursive {
        a.no_recursive = false;
    }
    if a.no_follow_symlinks {
        a.follow_symlinks = false;
    }
    a.input = Some(absolute(
        a.input.as_deref().context("input.path or -i is required")?,
        &cwd,
    ));
    a.output = Some(absolute(
        a.output
            .as_deref()
            .context("output.path or -o is required")?,
        &cwd,
    ));
    if let Some(p) = &a.failures {
        a.failures = Some(absolute(p, &cwd));
    }
    if a.label.is_none() {
        bail!("input.label or --type is required (benign, malicious or unknown)");
    }
    if !(1..=256).contains(&a.workers)
        || a.timeout_seconds == 0
        || a.max_size_mb == 0
        || a.max_decompressed_mb == 0
    {
        bail!("workers must be 1..256 and all limits must be positive");
    }
    if !matches!(a.stream_mode.as_str(), "structural" | "decoded") {
        bail!("unknown stream_mode");
    }
    if let Some(format) = &a.format
        && !matches!(format.as_str(), "csv" | "parquet")
    {
        bail!("output.format must be csv or parquet");
    }
    let output = a.output.as_ref().unwrap();
    if a.format.is_none()
        && !output
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|f| matches!(f, "csv" | "parquet"))
    {
        bail!("output format required: .csv or .parquet, or output.format");
    }
    a.max_size_mb
        .checked_mul(1024 * 1024)
        .context("input_mib overflows bytes")?;
    a.max_decompressed_mb
        .checked_mul(1024 * 1024)
        .context("decoded_mib overflows bytes")?;
    a.selection
        .validate(a.decode_images, a.stream_mode == "structural")?;
    let profile = json!({"profile_kind":if a.config.is_some(){"configured"}else{"legacy"},"schema":sibilla_b_schema::SCHEMA_VERSION,"common_version":"common-v1","format":"pdf","selection":a.selection,"stream_mode":a.stream_mode,"decode_images":a.decode_images,"input_mib":a.max_size_mb,"decoded_mib":a.max_decompressed_mb,"timeout_seconds":a.timeout_seconds});
    let mut settings = serde_json::to_value(&a)?;
    let map = settings.as_object_mut().context("extract options")?;
    for key in [
        "config",
        "snapshot",
        "resume",
        "no_resume",
        "no_decode_images",
        "recursive",
        "no_follow_symlinks",
    ] {
        map.remove(key);
    }
    a.snapshot = Some(
        json!({"config_version":1,"command":"extract","settings":settings,"run_hash":fingerprint(&settings)?,"feature_profile":profile,"profile_hash":fingerprint(&profile)?}),
    );
    Ok(a)
}
/// Resolve dataset paths, explicit CLI overrides and canonical projection policy.
pub fn resolve_build(mut a: Build, m: &ArgMatches) -> Result<Build> {
    let cwd = std::env::current_dir()?;
    if let Some(path) = &a.config {
        let c = load(path)?;
        if c.command != "dataset" {
            bail!("dataset build requires command = dataset");
        }
        let base = absolute(path, &cwd)
            .parent()
            .context("config directory")?
            .to_owned();
        if !explicit(m, "input") {
            a.input = c
                .input
                .paths
                .unwrap_or_default()
                .iter()
                .map(|p| absolute(p, &base))
                .collect();
        }
        if !explicit(m, "output") {
            a.output = c.output.path.map(|p| absolute(&p, &base));
        }
        if !explicit(m, "workers")
            && let Some(w) = c.runtime.workers
        {
            a.workers = w;
        }
        if let Some(split) = c.split {
            if !explicit(m, "split")
                && let Some(s) = split.percentages
            {
                a.split = format!("{}:{}:{}", s[0], s[1], s[2]);
            }
            if !explicit(m, "seed")
                && let Some(s) = split.seed
            {
                a.seed = s;
            }
            if !explicit(m, "group_column") {
                a.group_column = split.group_column;
            }
        }
        if !explicit(m, "conflict_policy")
            && let Some(policy) = c.policy
            && let Some(p) = policy.conflict_policy
        {
            a.conflict_policy = p;
        }
        if let Some(columns) = c.columns {
            a.projection.groups = columns.groups;
            a.projection.exclude = columns.exclude;
        }
        a.projection.aliases = c.aliases.unwrap_or_default();
        let cleanup = c.cleanup.unwrap_or_default();
        a.projection.drop_all_null = cleanup.drop_all_null;
        a.projection.drop_constant = cleanup.drop_constant;
    }
    if a.input.is_empty() {
        bail!("input.paths or -i is required");
    }
    for p in &mut a.input {
        *p = absolute(p, &cwd);
    }
    a.output = Some(absolute(
        a.output
            .as_deref()
            .context("output.path or -o is required")?,
        &cwd,
    ));
    if !(1..=256).contains(&a.workers) {
        bail!("workers must be 1..256");
    }
    let split: Vec<u64> = a
        .split
        .split(':')
        .map(str::parse)
        .collect::<Result<_, _>>()?;
    if split.len() != 3 || split.iter().any(|v| *v > 100) || split.iter().sum::<u64>() != 100 {
        bail!("split requires three percentages totaling 100");
    }
    if !matches!(a.conflict_policy.as_str(), "error" | "quarantine") {
        bail!("unknown conflict policy");
    }
    if a.temporal_column.is_some() {
        bail!("temporal mode requires timestamps not present in the current schema");
    }
    sibilla_b_dataset::projection::validate(&a.projection)?;
    let mut settings = serde_json::to_value(&a)?;
    let map = settings.as_object_mut().context("build options")?;
    map.remove("config");
    map.remove("snapshot");
    a.snapshot = Some(
        json!({"config_version":1,"command":"dataset","settings":settings,"run_hash":fingerprint(&settings)?}),
    );
    Ok(a)
}
/// Execute init/check without starting workers; template and path collisions are explicit errors.
pub fn command(command: ConfigCommand) -> Result<()> {
    match command {
        ConfigCommand::Init {
            command, output, ..
        } => {
            use std::io::Write;
            let text = if command == "dataset" {
                include_str!("../../../examples/config/dataset.toml")
            } else {
                include_str!("../../../examples/config/extract-pdf.toml")
            };
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
        }
        ConfigCommand::Check { path } => {
            use clap::CommandFactory;
            let c = load(&path)?;
            let mut args = vec!["sibilla-b".into()];
            if c.command == "extract" {
                args.extend(["extract".into(), "--config".into(), path.into_os_string()]);
            } else {
                args.extend([
                    "dataset".into(),
                    "build".into(),
                    "--config".into(),
                    path.into_os_string(),
                ]);
            }
            let m = crate::Cli::command().try_get_matches_from(args)?;
            use clap::FromArgMatches;
            let cli = crate::Cli::from_arg_matches(&m)?;
            match cli.command {
                crate::Command::Extract { args, .. } => {
                    resolve_extract(args, m.subcommand_matches("extract").unwrap())?;
                }
                crate::Command::Dataset {
                    command: crate::Dataset::Build(args),
                } => {
                    resolve_build(
                        args,
                        m.subcommand_matches("dataset")
                            .unwrap()
                            .subcommand_matches("build")
                            .unwrap(),
                    )?;
                }
                _ => unreachable!(),
            };
            println!("Configuration is valid");
        }
    }
    Ok(())
}

/// Resolve global presentation before constructing UI, preserving explicit flags and NO_COLOR.
pub fn presentation(cli: &mut crate::Cli, m: &ArgMatches) -> Result<()> {
    let (path, command_matches) = match &cli.command {
        crate::Command::Extract { args, format } => {
            let root = m
                .subcommand_matches("extract")
                .context("extract arguments")?;
            match format {
                Some(crate::Format::Pdf(a)) => {
                    (a.config.as_ref(), root.subcommand_matches("pdf").unwrap())
                }
                None => (args.config.as_ref(), root),
            }
        }
        crate::Command::Dataset {
            command: crate::Dataset::Build(a),
        } => (
            a.config.as_ref(),
            m.subcommand_matches("dataset")
                .unwrap()
                .subcommand_matches("build")
                .unwrap(),
        ),
        _ => return Ok(()),
    };
    if let Some(path) = path {
        let c = load(path)?;
        if !explicit(command_matches, "quiet")
            && let Some(q) = c.runtime.quiet
        {
            cli.quiet = q;
        }
        if !explicit(command_matches, "color")
            && !explicit(command_matches, "no_color")
            && let Some(color) = c.runtime.color
        {
            cli.color = match color.as_str() {
                "always" => clap::ColorChoice::Always,
                "auto" => clap::ColorChoice::Auto,
                "never" => clap::ColorChoice::Never,
                _ => bail!("runtime.color must be always, auto, or never"),
            };
        }
    }
    if cli.no_quiet {
        cli.quiet = false;
    }
    if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
        && !explicit(command_matches, "color")
    {
        cli.no_color = true;
    }
    Ok(())
}
