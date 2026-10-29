use anyhow::{Result, bail};
use serde_json::json;
use std::{process::Command, time::Instant};
pub fn run(args: crate::Benchmark) -> Result<()> {
    let counts = args
        .workers
        .split(',')
        .map(str::parse::<usize>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if counts.is_empty() || counts.iter().any(|&n| n == 0 || n > 256) {
        bail!("workers must be comma-separated values in 1..256");
    }
    let directory = tempfile::tempdir()?;
    let mut measurements = Vec::new();
    for (index, workers) in counts.into_iter().enumerate() {
        let output = directory.path().join(format!("benchmark-{index}.parquet"));
        let start = Instant::now();
        let status = Command::new(std::env::current_exe()?)
            .args(["extract", "pdf", "--input"])
            .arg(&args.input)
            .arg("--output")
            .arg(&output)
            .arg("--workers")
            .arg(workers.to_string())
            .arg("--quiet")
            .status()?;
        if !status.success() {
            bail!("benchmark extraction failed");
        }
        let elapsed = start.elapsed().as_secs_f64();
        let mut records = 0;
        let mut bytes = 0;
        let mut failed = 0;
        sibilla_output::read(&output, sibilla_output::extraction_schema(), |row| {
            records += 1;
            bytes += row
                .get("extraction_common_features_size_bytes")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            if row
                .get("extraction_status")
                .and_then(serde_json::Value::as_str)
                != Some("success")
            {
                failed += 1;
            }
            Ok(())
        })?;
        measurements.push(json!({"workers":workers,"records":records,"non_success":failed,"bytes_with_statistics":bytes,"elapsed_seconds":elapsed,"files_per_second":records as f64/elapsed,"mib_per_second":bytes as f64/1048576.0/elapsed}));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"extractor_version":env!("CARGO_PKG_VERSION"),"schema":sibilla_schema::SCHEMA_VERSION,"profile":"64 MiB input; 128 MiB per-stream decompression; 30 seconds per sample; 512 MiB worker address space","measurement":"complete extraction including discovery, parser processes and Parquet publication","peak_memory":"not measured","storage_type":"not detected; record separately for comparisons","measurements":measurements})
        )?
    );
    Ok(())
}
