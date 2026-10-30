use crate::{Extract, Label};
use anyhow::{Context, Result, bail};
use sibilla_b_schema::{Limits, Record, Status};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex, mpsc},
    time::Instant,
};
/// Collect input paths deterministically while respecting symlink and recursion policies.
fn discover(
    path: &Path,
    recursive: bool,
    files: &mut Vec<PathBuf>,
    skip: &Path,
    follow: bool,
    visited: &mut std::collections::BTreeSet<PathBuf>,
) -> Result<()> {
    if path == skip {
        return Ok(());
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        if follow {
            discover(
                &std::fs::canonicalize(path)?,
                recursive,
                files,
                skip,
                follow,
                visited,
            )?;
        }
        return Ok(());
    }
    if metadata.is_file() {
        files.push(path.to_owned());
    } else if metadata.is_dir() {
        if !visited.insert(std::fs::canonicalize(path)?) {
            return Ok(());
        }
        let mut entries = std::fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let kind = entry.file_type()?;
            if kind.is_file()
                || (recursive && kind.is_dir())
                || (follow && kind.is_symlink() && (recursive || entry.path().is_file()))
            {
                discover(&entry.path(), recursive, files, skip, follow, visited)?;
            }
        }
    }
    Ok(())
}
/// Extract PDFs with supervised workers, validated resume and atomic table publication.
pub fn run(args: Extract, ui: &crate::ui::Ui) -> Result<()> {
    let discovery = ui.progress("Discovering files", None);
    if args.workers == 0 || args.workers > 256 || args.timeout_seconds == 0 {
        bail!("workers must be 1..256 and timeout must be positive");
    }
    let input = args.input.context("input required")?;
    if std::fs::symlink_metadata(&input)?.file_type().is_symlink() && !args.follow_symlinks {
        bail!("input symlinks are not followed");
    }
    let input = std::fs::canonicalize(&input)
        .with_context(|| format!("cannot read input {}", input.display()))?;
    let output = args.output.context("output required")?;
    if output.exists() {
        bail!(
            "output {} already exists; choose a new output path",
            output.display()
        );
    }
    let format = args
        .format
        .as_deref()
        .or_else(|| output.extension().and_then(|e| e.to_str()))
        .context("output format required")?;
    if !matches!(format, "csv" | "parquet") {
        bail!("format must be csv or parquet");
    }
    if let Some(failures) = &args.failures
        && (failures.exists() || destination(failures)? == destination(&output)?)
    {
        bail!("failure sidecar already exists or aliases output");
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
        stream_mode: if args.stream_mode == "structural" {
            sibilla_b_schema::StreamMode::Structural
        } else {
            sibilla_b_schema::StreamMode::Decoded
        },
    };
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let checkpoint = std::fs::canonicalize(parent)?.join(format!(
        ".{}.checkpoints",
        output
            .file_name()
            .context("output file name")?
            .to_string_lossy()
    ));
    let mut files = Vec::new();
    discover(
        &input,
        !args.no_recursive,
        &mut files,
        &checkpoint,
        args.follow_symlinks,
        &mut Default::default(),
    )?;
    if files.is_empty() {
        bail!("no input files");
    }
    let total = files.len();
    discovery.set_message("Validating checkpoints");
    let label = match args.label.context("--type is required for extraction")? {
        Label::Benign => Some(0),
        Label::Malicious => Some(1),
        Label::Unknown => None,
    };
    let manifest = serde_json::json!({"schema":sibilla_b_schema::SCHEMA_VERSION,"version":env!("CARGO_PKG_VERSION"),"input":input,"files":files,"limits":limits,"label":label,"source":args.source,"collection_id":args.collection_id,"recursive":!args.no_recursive,"follow_symlinks":args.follow_symlinks,"format":format});
    if !args.resume {
        std::fs::create_dir(&checkpoint).context("checkpoint directory exists; use --resume")?;
    }
    let _lock = checkpoint_lock(&checkpoint)?;
    if args.resume {
        if std::fs::symlink_metadata(&checkpoint)?
            .file_type()
            .is_symlink()
        {
            bail!("checkpoint must not be a symlink");
        }
        let previous: serde_json::Value =
            serde_json::from_reader(std::fs::File::open(checkpoint.join("manifest.json"))?)?;
        if manifest != previous {
            bail!("resume configuration or discovery manifest changed");
        }
    } else {
        atomic_record(&checkpoint.join("manifest.json"), &manifest)?;
    }
    crate::interrupt::install()?;
    let mut pending = Vec::new();
    let mut reused = 0;
    for (index, path) in files.into_iter().enumerate() {
        crate::interrupt::check()?;
        let shard = checkpoint.join(format!("{index:020}.json"));
        if args.resume && shard.exists() {
            let record: Record = serde_json::from_reader(std::fs::File::open(&shard)?)?;
            if record.label != label
                || record.feature_schema_version != sibilla_b_schema::SCHEMA_VERSION
                || record.source_dataset != args.source
                || record.collection_id != args.collection_id
            {
                bail!("checkpoint record metadata mismatch");
            }
            if let Some(expected) = record.sample_id {
                if fingerprint(&path, limits.max_size_bytes)? != expected {
                    bail!("resume input content changed");
                }
                reused += 1;
                continue;
            }
        }
        pending.push((index, path));
    }
    discovery.finish_and_clear();
    let progress = ui.progress("Extracting PDFs", Some(total as u64));
    progress.set_position(reused as u64);
    // shortcut: paths are held in memory; use a disk discovery manifest for million-file corpora.
    let jobs = Arc::new(Mutex::new(pending.into_iter()));
    let executable = std::env::current_exe()?;
    let started = Instant::now();
    let (tx, rx) = mpsc::sync_channel(args.workers * 2);
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
                    if crate::interrupt::requested() {
                        break;
                    }
                    let next = jobs.lock().expect("job mutex").next();
                    let Some((index, path)) = next else {
                        break;
                    };
                    let start = Instant::now();
                    let result = (|| -> Result<_> {
                        if worker.is_none() {
                            worker = Some(sibilla_b_core::Worker::start(executable)?);
                        }
                        let active = worker.as_mut().context("worker unavailable")?;
                        let result = active.extract(&sibilla_b_core::Job {
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
        let mut completed = reused;
        for (index, path, duration, result) in rx {
            let extraction = result?;
            let sample_id = extraction
                .common_features
                .as_ref()
                .map(|f| f.sha256.clone());
            let record = Record {
                sample_id,
                label,
                file_format: "pdf".into(),
                feature_schema_version: sibilla_b_schema::SCHEMA_VERSION.into(),
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
            atomic_record(&checkpoint.join(format!("{index:020}.json")), &record)?;
            completed += 1;
            progress.set_position(completed as u64);
        }
        if crate::interrupt::requested() {
            progress.finish_and_clear();
            eprintln!(
                "Checkpointed {completed}/{total}. Resume from the same directory:\n{}",
                crate::interrupt::resume_command()
            );
            return Err(crate::interrupt::Interrupted.into());
        }
        if completed != total {
            bail!("worker results missing");
        }
        Ok(())
    })?;
    progress.finish_and_clear();
    let finalizing = ui.progress("Sorting and writing feature table", None);
    let mut shards = Vec::with_capacity(total);
    for index in 0..total {
        crate::interrupt::check()?;
        let path = checkpoint.join(format!("{index:020}.json"));
        let record: Record = serde_json::from_reader(std::fs::File::open(&path)?)?;
        let key = record.sample_id.unwrap_or_else(|| format!("~{index:020}"));
        shards.push((key, index, path));
    }
    shards.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
    crate::interrupt::check()?;
    if let Some(path) = &args.failures {
        use std::io::Write;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        for (_, _, shard) in &shards {
            crate::interrupt::check()?;
            let record: Record = serde_json::from_reader(std::fs::File::open(shard)?)?;
            if !matches!(record.extraction.status, Status::Success) {
                serde_json::to_writer(temporary.as_file_mut(), &record)?;
                writeln!(temporary)?;
            }
        }
        temporary.as_file().sync_all()?;
        crate::interrupt::check()?;
        temporary.persist_noclobber(path)?;
        std::fs::File::open(parent)?.sync_all()?;
    }
    let mut succeeded = 0;
    let mut partial = 0;
    let mut failed = 0;
    let mut rejected = 0;
    let mut timeouts = 0;
    let mut reasons = std::collections::BTreeMap::<String, usize>::new();
    let rows = shards.into_iter().map(|entry| -> Result<_> {
        crate::interrupt::check()?;
        let record: Record = serde_json::from_reader(std::fs::File::open(entry.2)?)?;
        match record.extraction.status {
            Status::Success => succeeded += 1,
            Status::Partial => partial += 1,
            Status::Rejected => rejected += 1,
            Status::Timeout => timeouts += 1,
            Status::Failed => failed += 1,
        }
        if let Some(code) = &record.extraction.error_code {
            for reason in code.split('|') {
                *reasons.entry(reason.into()).or_default() += 1;
            }
        }
        sibilla_b_output::row(&record)
    });
    sibilla_b_output::write_with_format(
        &output,
        sibilla_b_output::extraction_schema(),
        rows,
        format,
    )?;
    finalizing.finish_and_clear();
    if !ui.quiet {
        ui.success(&format!(
            "discovered={total} success={succeeded} partial={partial} rejected={rejected} timeout={timeouts} failed={failed} reused={reused} elapsed={:.3}s rate={:.1} files/s",
            started.elapsed().as_secs_f64(),
            (total-reused) as f64 / started.elapsed().as_secs_f64()
        ));
    }
    if !ui.quiet {
        for (reason, count) in reasons {
            eprintln!("  {reason}: {count}");
        }
    }
    Ok(())
}

/// Synchronize and atomically replace a checkpoint manifest or sample record.
fn atomic_record(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().context("checkpoint parent")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(temporary.as_file_mut(), value)?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).context("commit checkpoint")?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}
/// Hash a bounded regular source file to validate checkpoint reuse.
fn fingerprint(path: &Path, limit: u64) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = sibilla_b_core::open_sample(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > limit {
        bail!("resume input size changed");
    }
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    let mut size = 0;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        if size > limit {
            bail!("resume input size changed");
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

/// Acquire an exclusive process lock for a non-symlink checkpoint directory.
fn checkpoint_lock(path: &Path) -> Result<std::fs::File> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        bail!("checkpoint must not be a symlink");
    }
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path.join("lock"))?;
    use std::os::fd::AsRawFd;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!("another extraction owns this checkpoint");
    }
    Ok(file)
}

/// Resolve an output parent to detect paths that alias the same destination.
fn destination(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    Ok(std::fs::canonicalize(parent)?.join(path.file_name().context("output filename")?))
}
