// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 younidev-org.

use std::process::Command;
/// Verify inspection summarizes records, reasons, missing values and readable column names.
#[test]
fn inspect_reports_full_table() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.pdf");
    std::fs::write(&input, b"%PDF-1.7\ninvalid %%EOF").unwrap();
    let table = dir.path().join("features.parquet");
    assert!(
        Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
            .args(["--quiet", "extract", "pdf", "--type", "unknown", "-i"])
            .arg(&input)
            .arg("-o")
            .arg(&table)
            .status()
            .unwrap()
            .success()
    );
    let mut original = None;
    sibilla_b_output::read(&table, sibilla_b_output::extraction_schema(), |row| {
        original = Some(row);
        Ok(())
    })
    .unwrap();
    let table = dir.path().join("many.csv");
    sibilla_b_output::write(
        &table,
        sibilla_b_output::extraction_schema(),
        std::iter::repeat_n(original.unwrap(), 1501).map(Ok),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
        .arg("inspect")
        .arg(&table)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["rows"], 1501);
    assert_eq!(report["statuses"]["partial"], 1501);
    assert_eq!(report["errors"]["pdf_parse_failed"], 1501);
    assert_eq!(report["sample_errors"].as_array().unwrap().len(), 5);
    assert!(
        report["missing"]["extraction_format_features_page_count"]
            .as_u64()
            .unwrap()
            > 0
    );
    let output = Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
        .arg("inspect")
        .arg(&table)
        .arg("--columns")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&output.stdout).contains("byte_histogram_001"));
}
/// Verify Ctrl+C preserves committed rows, reports a quoted resume command and exits 130.
#[test]
fn interruption_can_resume() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    std::fs::create_dir(&input).unwrap();
    for n in 0..300 {
        std::fs::write(input.join(format!("{n}.pdf")), b"%PDF-1.7\ninvalid %%EOF").unwrap();
    }
    let table = dir.path().join("features.csv");
    let args = [
        "--no-color",
        "extract",
        "pdf",
        "--type",
        "unknown",
        "-i",
        input.to_str().unwrap(),
        "-o",
        table.to_str().unwrap(),
        "-j",
        "1",
    ];
    let child = Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let start = std::time::Instant::now();
    while !dir
        .path()
        .join(".features.csv.checkpoints/00000000000000000000.json")
        .exists()
    {
        assert!(start.elapsed() < std::time::Duration::from_secs(10));
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(130));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--resume"));
    assert!(!table.exists());
    let output = Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
        .args(args)
        .arg("--resume")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut count = 0;
    sibilla_b_output::read(&table, sibilla_b_output::extraction_schema(), |_| {
        count += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(count, 300);
}
/// Verify the final summary separates rejected files and prints counted failure reasons.
#[test]
fn extraction_summary_separates_rejections() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("empty.pdf");
    std::fs::write(&input, b"").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
        .args(["--no-color", "extract", "pdf", "--type", "unknown", "-i"])
        .arg(&input)
        .arg("-o")
        .arg(dir.path().join("out.csv"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stderr).unwrap();
    for expected in [
        "rejected=1",
        "failed=0",
        "timeout=0",
        "reused=0",
        "files/s",
        "invalid_magic: 1",
    ] {
        assert!(text.contains(expected), "{text}");
    }
}
