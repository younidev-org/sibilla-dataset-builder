// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 younidev-org.

use serde_json::{Value, json};
use std::process::Command;
/// Config-first dataset export aliases predictive columns but preserves labels and split identities.
#[test]
fn dataset_config_exports_aliases_and_resolved_metadata() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.pdf"), b"%PDF-1.7\ninvalid %%EOF").unwrap();
    let binary = env!("CARGO_BIN_EXE_sibilla-b");
    let table = dir.path().join("features.parquet");
    assert!(
        Command::new(binary)
            .args(["--quiet", "extract", "pdf", "-i"])
            .arg(dir.path().join("a.pdf"))
            .args(["--type", "benign", "-o"])
            .arg(&table)
            .status()
            .unwrap()
            .success()
    );
    let config = dir.path().join("dataset.toml");
    std::fs::write(&config,"config_version=1\ncommand='dataset'\n[input]\npaths=['features.parquet']\n[output]\npath='dataset'\n[split]\npercentages=[100,0,0]\n[columns]\ngroups=['common.entropy']\n[aliases]\n'common.entropy_global'='byte_entropy'\n[cleanup]\ndrop_all_null=true\ndrop_constant=false\n").unwrap();
    let output = Command::new(binary)
        .args(["--quiet", "dataset", "build", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let root = dir.path().join("dataset");
    let report: Value =
        serde_json::from_slice(&std::fs::read(root.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["samples"], 1);
    assert!(
        report["projection"]["columns"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["output_name"] == "byte_entropy")
    );
    let options = sibilla_b_dataset::projection::ProjectionOptions {
        groups: vec!["common.entropy".into()],
        aliases: std::collections::BTreeMap::from([(
            "common.entropy_global".into(),
            "byte_entropy".into(),
        )]),
        ..Default::default()
    };
    let projection =
        sibilla_b_dataset::projection::learn_projection(std::iter::empty(), &options).unwrap();
    sibilla_b_output::read(
        &root.join("features.parquet"),
        projection.schema().unwrap(),
        |row| {
            assert!(row.contains_key("byte_entropy"));
            assert!(!row.contains_key("label"));
            assert!(row.contains_key("sample_id"));
            Ok(())
        },
    )
    .unwrap();
    sibilla_b_output::read(
        &root.join("manifest.parquet"),
        sibilla_b_output::extraction_schema(),
        |row| {
            assert_eq!(row["label"], json!(0));
            Ok(())
        },
    )
    .unwrap();
    assert!(root.join("resolved_config.json").exists());
    let metadata: Value =
        serde_json::from_slice(&std::fs::read(root.join("dataset_metadata.json")).unwrap())
            .unwrap();
    assert!(metadata["artifact_sha256"]["resolved_config.json"].is_string());
}
/// Different measurement profiles cannot be combined; reviewed old full-schema tables remain usable.
#[test]
fn profile_mismatch_and_legacy_compatibility() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("a.pdf");
    std::fs::write(&input, b"%PDF-1.7\ninvalid %%EOF").unwrap();
    let binary = env!("CARGO_BIN_EXE_sibilla-b");
    let mut tables = Vec::new();
    for size in [1, 2] {
        let out = dir.path().join(format!("{size}.csv"));
        assert!(
            Command::new(binary)
                .args(["--quiet", "extract", "pdf", "-i"])
                .arg(&input)
                .args(["--type", "benign", "-o"])
                .arg(&out)
                .args(["--max-size-mb", &size.to_string()])
                .status()
                .unwrap()
                .success()
        );
        tables.push(out);
    }
    let p = Command::new(binary)
        .args(["--quiet", "dataset", "build", "-i"])
        .arg(&tables[0])
        .arg("-i")
        .arg(&tables[1])
        .arg("-o")
        .arg(dir.path().join("mixed"))
        .output()
        .unwrap();
    assert!(!p.status.success());
    assert!(String::from_utf8_lossy(&p.stderr).contains("profiles"));
    let mut rows = Vec::new();
    sibilla_b_output::read(
        &tables[0],
        sibilla_b_output::extraction_schema(),
        |mut row| {
            row.insert("extractor_version".into(), json!("0.5.0"));
            rows.push(Ok(row));
            Ok(())
        },
    )
    .unwrap();
    let legacy = dir.path().join("legacy.csv");
    sibilla_b_output::write(&legacy, sibilla_b_output::extraction_schema(), rows).unwrap();
    let p = Command::new(binary)
        .args(["--quiet", "dataset", "build", "-i"])
        .arg(&legacy)
        .arg("-o")
        .arg(dir.path().join("legacy-dataset"))
        .output()
        .unwrap();
    assert!(p.status.success(), "{}", String::from_utf8_lossy(&p.stderr));
}
