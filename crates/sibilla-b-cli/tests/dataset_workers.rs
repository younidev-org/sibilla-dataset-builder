// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 younidev-org.

use std::process::Command;
/// Verify parallel dataset writers produce identical artifact bytes and reject zero workers.
#[test]
fn dataset_workers_preserve_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.pdf");
    std::fs::write(&input, b"%PDF-1.7\ninvalid %%EOF").unwrap();
    let table = dir.path().join("input.parquet");
    assert!(
        Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
            .args(["-q", "extract", "pdf", "-i"])
            .arg(&input)
            .arg("-o")
            .arg(&table)
            .args(["--type", "benign", "--collection-id", "group"])
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
    let table = dir.path().join("many.parquet");
    std::fs::copy(
        dir.path().join(".input.parquet.config.json"),
        dir.path().join(".many.parquet.config.json"),
    )
    .unwrap();
    let row = original.unwrap();
    let rows = (0..600).map(|i| {
        let mut row = row.clone();
        let id = format!("{i:064x}");
        row.insert("sample_id".into(), id.clone().into());
        row.insert("extraction_common_features_sha256".into(), id.into());
        Ok(row)
    });
    sibilla_b_output::write(&table, sibilla_b_output::extraction_schema(), rows).unwrap();
    for workers in [1, 4] {
        let result = Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
            .args(["-q", "dataset", "build", "-i"])
            .arg(&table)
            .arg("-o")
            .arg(dir.path().join(format!("dataset-{workers}")))
            .args(["--group-column", "collection_id", "-j"])
            .arg(workers.to_string())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    for file in [
        "manifest.parquet",
        "features.parquet",
        "report.json",
        "splits/train.parquet",
        "splits/validation.parquet",
        "splits/test.parquet",
    ] {
        assert_eq!(
            std::fs::read(dir.path().join("dataset-1").join(file)).unwrap(),
            std::fs::read(dir.path().join("dataset-4").join(file)).unwrap(),
            "{file}"
        );
    }
    let read_metadata = |name: &str| {
        let mut value: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join(name).join("dataset_metadata.json")).unwrap(),
        )
        .unwrap();
        value["artifact_sha256"]
            .as_object_mut()
            .unwrap()
            .remove("resolved_config.json");
        value
    };
    assert_eq!(read_metadata("dataset-1"), read_metadata("dataset-4"));
    assert!(
        !Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
            .args(["dataset", "build", "-i"])
            .arg(table)
            .arg("-o")
            .arg(dir.path().join("invalid"))
            .args(["-j", "0"])
            .output()
            .unwrap()
            .status
            .success()
    );
}
