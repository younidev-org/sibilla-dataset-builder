// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 younidev-org.

use std::process::Command;
/// Generate configuration from one binary and validate/execute it from a different directory.
#[test]
fn config_first_extraction_and_overrides() {
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("samples")).unwrap();
    for name in ["a.pdf", "b.pdf"] {
        std::fs::write(
            dir.path().join("samples").join(name),
            b"%PDF-1.7\ninvalid %%EOF",
        )
        .unwrap();
    }
    let config = dir.path().join("run.toml");
    std::fs::write(&config,"config_version = 1\ncommand = 'extract'\n[input]\npath = 'samples'\nformat = 'pdf'\nlabel = 'benign'\n[output]\npath = 'out.csv'\n[runtime]\nworkers = 1\n[formats.pdf]\ndecode_images = true\n").unwrap();
    let binary = env!("CARGO_BIN_EXE_sibilla-b");
    let checked = Command::new(binary)
        .args(["config", "check"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let output = Command::new(binary)
        .current_dir(elsewhere.path())
        .args(["extract", "--config"])
        .arg(&config)
        .args(["--limit", "1", "--no-decode-images", "--quiet"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut count = 0;
    sibilla_b_output::read(
        &dir.path().join("out.csv"),
        sibilla_b_output::extraction_schema(),
        |row| {
            assert_eq!(row["label"], 0);
            count += 1;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(count, 1);
    assert!(dir.path().join(".out.csv.config.json").exists());
}
/// Unknown keys and unimplemented formats fail before extraction creates an output.
#[test]
fn config_rejects_unknown_keys_and_formats() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bad.toml");
    for text in [
        "config_version=1\ncommand='extract'\ntypo=1\n",
        "config_version=1\ncommand='extract'\n[input]\nformat='pe'\npath='missing'\nlabel='benign'\n[output]\npath='out.csv'\n",
    ] {
        std::fs::write(&config, text).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
            .args(["config", "check"])
            .arg(&config)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!dir.path().join("out.csv").exists());
    }
}
/// Reformatting or renaming a config preserves resume; selected groups and stale sidecars do not.
#[test]
fn config_resume_identity_and_sidecar_recovery() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.pdf"), b"%PDF-1.7\ninvalid %%EOF").unwrap();
    let config = dir.path().join("run.toml");
    let text = "config_version=1\ncommand='extract'\n[input]\npath='a.pdf'\nlabel='benign'\n[output]\npath='out.csv'\n";
    std::fs::write(&config, text).unwrap();
    let run = |path: &std::path::Path, extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
            .args(["--no-color", "extract", "--config"])
            .arg(path)
            .args(extra)
            .output()
            .unwrap()
    };
    assert!(run(&config, &["-j", "1"]).status.success());
    let sidecar = dir.path().join(".out.csv.config.json");
    let before = std::fs::read(&sidecar).unwrap();
    std::fs::remove_file(dir.path().join("out.csv")).unwrap();
    std::fs::remove_file(&sidecar).unwrap();
    let renamed = dir.path().join("renamed.toml");
    std::fs::write(
        &renamed,
        format!("# only whitespace and comments changed\n{text}"),
    )
    .unwrap();
    assert!(run(&renamed, &["--resume", "-j", "2"]).status.success());
    assert_eq!(std::fs::read(&sidecar).unwrap(), before);
    std::fs::remove_file(dir.path().join("out.csv")).unwrap();
    std::fs::write(&renamed, format!("{text}\n[features.common]\ngroups=[]\n")).unwrap();
    assert!(!run(&renamed, &["--resume"]).status.success());
    std::fs::write(&renamed, text).unwrap();
    let mut stale: serde_json::Value = serde_json::from_slice(&before).unwrap();
    stale["settings"]["limit"] = serde_json::json!(99);
    std::fs::write(&sidecar, serde_json::to_vec(&stale).unwrap()).unwrap();
    assert!(!run(&renamed, &["--resume"]).status.success());
}
/// Generated commented templates validate without requiring data files and are never overwritten.
#[test]
fn generated_templates_are_valid_and_noclobber() {
    let dir = tempfile::tempdir().unwrap();
    for command in ["extract", "dataset"] {
        let path = dir.path().join(format!("{command}.toml"));
        let binary = env!("CARGO_BIN_EXE_sibilla-b");
        let init = || {
            Command::new(binary)
                .args(["config", "init", "--command", command, "-o"])
                .arg(&path)
                .output()
                .unwrap()
        };
        assert!(init().status.success());
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains('#'));
        assert!(
            Command::new(binary)
                .args(["config", "check"])
                .arg(&path)
                .output()
                .unwrap()
                .status
                .success()
        );
        assert!(!init().status.success());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), contents);
    }
}
/// Validation catches dependency errors, invalid numeric limits and command-specific section mistakes.
#[test]
fn invalid_policies_fail_before_output() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invalid.toml");
    let base = "config_version=1\ncommand='extract'\n[input]\npath='missing.pdf'\nlabel='unknown'\n[output]\npath='out.csv'\n";
    for extra in [
        "[runtime]\nworkers=0\n",
        "[runtime]\ninput_mib=0\n",
        "[input_typo]\npath='x'\n",
        "[formats.pdf]\ngroups=['javascript']\n",
        "[formats.pdf]\nstream_mode='structural'\ndecode_images=true\n",
        "[formats.pe]\ngroups=[]\n",
    ] {
        std::fs::write(&path, format!("{base}\n{extra}")).unwrap();
        let p = Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
            .args(["config", "check"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(!p.status.success(), "accepted {extra}");
        assert!(!dir.path().join("out.csv").exists());
    }
}
/// Disabling every optional group preserves file identity while exporting null feature values.
#[test]
fn empty_selection_preserves_identity_and_nulls() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.pdf"), b"%PDF-1.7\ninvalid %%EOF").unwrap();
    let config = dir.path().join("run.toml");
    std::fs::write(&config,"config_version=1\ncommand='extract'\n[input]\npath='a.pdf'\nlabel='benign'\n[output]\npath='out.csv'\n[features.common]\ngroups=[]\n[formats.pdf]\ngroups=[]\n").unwrap();
    let p = Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
        .args(["--quiet", "extract", "--config"])
        .arg(config)
        .output()
        .unwrap();
    assert!(p.status.success(), "{}", String::from_utf8_lossy(&p.stderr));
    sibilla_b_output::read(
        &dir.path().join("out.csv"),
        sibilla_b_output::extraction_schema(),
        |row| {
            assert!(row["sample_id"].is_string());
            assert!(row["extraction_common_features_entropy_global"].is_null());
            assert!(row["extraction_format_features_page_count"].is_null());
            assert_eq!(row["extraction_status"], "success");
            Ok(())
        },
    )
    .unwrap();
}
/// Provenance, labels, input-count caps and worker counts do not change semantic profile identity.
#[test]
fn profiles_ignore_provenance_and_performance_options() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("a.pdf");
    std::fs::write(&input, b"%PDF-1.7\ninvalid %%EOF").unwrap();
    let binary = env!("CARGO_BIN_EXE_sibilla-b");
    let mut snapshots = Vec::new();
    for (index, label) in [(1, "benign"), (2, "malicious")] {
        let path = dir.path().join(format!("{index}.csv"));
        let mut command = Command::new(binary);
        command
            .args(["--quiet", "extract", "pdf", "-i"])
            .arg(&input)
            .args([
                "--type",
                label,
                "--source",
                label,
                "-j",
                &index.to_string(),
                "-o",
            ])
            .arg(&path);
        if index == 1 {
            command.args(["--limit", "1"]);
        }
        assert!(command.status().unwrap().success());
        snapshots.push(
            serde_json::from_slice::<serde_json::Value>(
                &std::fs::read(dir.path().join(format!(".{index}.csv.config.json"))).unwrap(),
            )
            .unwrap(),
        );
    }
    assert_eq!(snapshots[0]["profile_hash"], snapshots[1]["profile_hash"]);
    assert_ne!(snapshots[0]["run_hash"], snapshots[1]["run_hash"]);
}
