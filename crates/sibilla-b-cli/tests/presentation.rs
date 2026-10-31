// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 younidev-org.

use std::process::Command;
/// Run the CLI with captured output and no inherited NO_COLOR setting.
fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
        .env_remove("NO_COLOR")
        .args(args)
        .output()
        .unwrap()
}
/// Verify descriptive help and global color suppression at every command level.
#[test]
fn help_is_descriptive_and_color_can_be_disabled_anywhere() {
    let default = cli(&["--help"]);
    assert!(default.status.success());
    assert!(default.stdout.contains(&0x1b));
    assert!(String::from_utf8_lossy(&default.stdout).contains("Examples:"));
    for args in [
        vec!["--color", "never", "--help"],
        vec!["extract", "pdf", "--no-color", "--help"],
        vec!["extract", "pdf", "--color=never", "--help"],
    ] {
        let output = cli(&args);
        assert!(output.status.success());
        assert!(!output.stdout.contains(&0x1b));
        assert!(!output.stderr.contains(&0x1b));
    }
}
/// Verify uncolored errors and NO_COLOR behavior for help output.
#[test]
fn no_color_applies_to_errors_and_no_color_environment_is_respected() {
    let error = cli(&[
        "extract",
        "pdf",
        "--input",
        "missing",
        "--output",
        "unused.csv",
        "--color",
        "never",
    ]);
    assert!(!error.status.success());
    assert!(!error.stderr.contains(&0x1b));
    assert!(String::from_utf8_lossy(&error.stderr).contains("error:"));
    let help = Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
        .env("NO_COLOR", "1")
        .arg("--help")
        .output()
        .unwrap();
    assert!(!help.stdout.contains(&0x1b));
}
/// Verify that successful quiet extraction emits neither status nor stdout noise.
#[test]
fn quiet_extraction_keeps_both_streams_clean() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.pdf");
    std::fs::write(&input, b"%PDF-1.7\nmalformed %%EOF").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
        .args(["extract", "pdf", "--type", "unknown", "-i"])
        .arg(input)
        .arg("-o")
        .arg(directory.path().join("out.csv"))
        .args(["--quiet", "--no-color"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}
/// Verify root help explains input, output and worker shortcuts without requiring nested help.
#[test]
fn root_help_explains_example_shortcuts() {
    let output = cli(&["--no-color", "--help"]);
    let text = String::from_utf8(output.stdout).unwrap();
    for description in [
        "-i, --input",
        "-o, --output",
        "-j, --workers",
        "PDF file or folder",
        "New output file or dataset directory",
        "extract pdf --help",
    ] {
        assert!(text.contains(description), "Missing help: {description}");
    }
}
/// Verify extraction help explains output extensions and provides practical examples.
#[test]
fn extraction_help_explains_output_format() {
    let output = cli(&["--no-color", "extract", "pdf", "--help"]);
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "Output format:",
        ".parquet",
        ".csv",
        "--format parquet",
        "--resume",
        "Examples:",
    ] {
        assert!(
            text.contains(expected),
            "Missing extraction help: {expected}"
        );
    }
}
