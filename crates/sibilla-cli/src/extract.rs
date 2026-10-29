use crate::{Extract, Label};
use anyhow::{Context, Result, bail};
use sibilla_schema::{Limits, Record, Status};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex, mpsc},
    time::Instant,
};
fn discover(path: &Path, recursive: bool, files: &mut Vec<PathBuf>) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_file() {
        files.push(path.to_owned());
    } else if metadata.is_dir() {
        let mut entries = std::fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let kind = entry.file_type()?;
            if kind.is_file() || (recursive && kind.is_dir()) {
                discover(&entry.path(), recursive, files)?;
            }
        }
    }
    Ok(())
}
pub fn run(args: Extract) -> Result<()> {
    if args.resume || args.follow_symlinks || args.format.is_some() || args.failures.is_some() {
        bail!(
            "resume, symlink traversal, explicit format and failure sidecars are not available yet"
        );
    }
    if args.workers == 0 || args.workers > 256 || args.timeout_seconds == 0 {
        bail!("workers must be 1..256 and timeout must be positive");
    }
    let input = args.input.context("input required")?;
    let output = args.output.context("output required")?;
    if output.exists() {
        bail!("output already exists");
    }
    let limits = Limits {
        max_size_bytes: args
            .max_size_mb
            .checked_mul(1024 * 1024)
            .context("size overflow")?,
        max_decompressed_bytes: args
            .max_decompressed_mb
            .checked_mul(1024 * 1024)
            .context("decompression limit overflow")?,
        timeout_seconds: args.timeout_seconds,
    };
    let mut files = Vec::new();
    discover(&input, !args.no_recursive, &mut files)?;
    if files.is_empty() {
        bail!("no input files");
    }
    let total = files.len();
    // shortcut: paths are held in memory; use a disk discovery manifest for million-file corpora.
    let jobs = Arc::new(Mutex::new(files.into_iter().enumerate()));
    let spool = tempfile::tempdir()?;
    let executable = std::env::current_exe()?;
    let started = Instant::now();
    let (tx, rx) = mpsc::sync_channel(args.workers * 2);
    let label = match args.label {
        Label::Benign => Some(0),
        Label::Malicious => Some(1),
        Label::Unknown => None,
    };
    let root = if input.is_dir() {
        input.as_path()
    } else {
        input.parent().unwrap_or(Path::new("."))
    };
    std::thread::scope(|scope| -> Result<()> {
        for _ in 0..args.workers.min(total) {
            let jobs = jobs.clone();
            let tx = tx.clone();
            let executable = &executable;
            scope.spawn(move || {
                let mut worker = None;
                loop {
                    let next = jobs.lock().expect("job mutex").next();
                    let Some((index, path)) = next else {
                        break;
                    };
                    let start = Instant::now();
                    let result = (|| -> Result<_> {
                        if worker.is_none() {
                            worker = Some(sibilla_core::Worker::start(executable)?);
                        }
                        let active = worker.as_mut().context("worker unavailable")?;
                        let result = active.extract(&sibilla_core::Job {
                            path: path.clone(),
                            limits,
                        })?;
                        if !active.alive()? {
                            worker = None;
                        }
                        Ok(result)
                    })();
                    if tx
                        .send((index, path, start.elapsed().as_millis() as u64, result))
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
        drop(tx);
        let mut completed = 0;
        for (index, path, duration, result) in rx {
            let extraction = result?;
            let sample_id = extraction
                .common_features
                .as_ref()
                .map(|f| f.sha256.clone());
            let key = sample_id.clone().unwrap_or_else(|| format!("~{index:020}"));
            let record = Record {
                sample_id,
                label,
                file_format: "pdf".into(),
                feature_schema_version: sibilla_schema::SCHEMA_VERSION.into(),
                extractor_version: env!("CARGO_PKG_VERSION").into(),
                original_relative_path: Some(
                    path.strip_prefix(root)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .into_owned(),
                ),
                source_dataset: args.source.clone(),
                collection_id: args.collection_id.clone(),
                extraction_duration_ms: duration,
                extraction,
            };
            let file = std::fs::File::create(spool.path().join(format!("{key}-{index:020}.json")))?;
            serde_json::to_writer(file, &record)?;
            completed += 1;
            if !args.quiet && (completed % 100 == 0 || completed == total) {
                eprintln!(
                    "completed {completed}/{total}; {:.1} files/s",
                    completed as f64 / started.elapsed().as_secs_f64()
                );
            }
        }
        if completed != total {
            bail!("worker results missing");
        }
        Ok(())
    })?;
    let mut shards = std::fs::read_dir(spool.path())?.collect::<std::io::Result<Vec<_>>>()?;
    shards.sort_by_key(|e| e.file_name());
    let mut succeeded = 0;
    let mut partial = 0;
    let rows = shards.into_iter().map(|entry| -> Result<_> {
        let record: Record = serde_json::from_reader(std::fs::File::open(entry.path())?)?;
        match record.extraction.status {
            Status::Success => succeeded += 1,
            Status::Partial => partial += 1,
            _ => {}
        }
        sibilla_output::row(&record)
    });
    sibilla_output::write(&output, sibilla_output::extraction_schema(), rows)?;
    if !args.quiet {
        eprintln!(
            "discovered={total} success={succeeded} partial={partial} failed={} elapsed={:.3}s",
            total - succeeded - partial,
            started.elapsed().as_secs_f64()
        );
    }
    Ok(())
}
