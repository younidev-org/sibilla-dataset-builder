use std::process::Command;
/// Verify stable feature rows across worker counts and refusal to overwrite outputs.
#[test]
fn extraction_is_deterministic_and_never_overwrites() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input");
    std::fs::create_dir(&input).unwrap();
    std::fs::write(input.join("partial.pdf"), b"%PDF-1.7\n/JavaScript %%EOF").unwrap();
    std::fs::write(input.join("empty.pdf"), b"").unwrap();
    let mut results = Vec::new();
    for workers in [1, 2] {
        let output = directory.path().join(format!("out-{workers}.parquet"));
        let args = [
            "extract",
            "pdf",
            "--input",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--workers",
            if workers == 1 { "1" } else { "2" },
            "--type",
            "benign",
            "--quiet",
        ];
        let status = Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
            .args(args)
            .status()
            .unwrap();
        assert!(status.success());
        let mut rows = Vec::new();
        sibilla_b_output::read(&output, sibilla_b_output::extraction_schema(), |mut row| {
            row.remove("extraction_duration_ms");
            rows.push(row);
            Ok(())
        })
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r["label"] == 0));
        results.push(rows);
        assert!(
            !Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
                .args(args)
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    assert_eq!(results[0], results[1]);
}
/// Verify checkpoint reuse and refusal of changed configuration or source bytes.
#[test]
fn resume_reuses_committed_rows_and_rejects_changed_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("sample.pdf");
    std::fs::write(&input, b"%PDF-1.7\n/JavaScript %%EOF").unwrap();
    let output = directory.path().join("features.csv");
    let args = [
        "extract",
        "pdf",
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--type",
        "benign",
        "--quiet",
    ];
    assert!(
        Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
            .args(args)
            .status()
            .unwrap()
            .success()
    );
    let original = std::fs::read(&output).unwrap();
    std::fs::remove_file(&output).unwrap();
    assert!(
        Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
            .args(args)
            .arg("--resume")
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(std::fs::read(&output).unwrap(), original);
    std::fs::remove_file(&output).unwrap();
    assert!(
        !Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
            .args(args)
            .args(["--resume", "--source", "changed"])
            .output()
            .unwrap()
            .status
            .success()
    );
    std::fs::write(&input, b"%PDF-1.7\nchanged %%EOF").unwrap();
    assert!(
        !Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
            .args(args)
            .arg("--resume")
            .output()
            .unwrap()
            .status
            .success()
    );
}
/// Verify explicit format selection and independent structured failure records.
#[test]
fn format_override_and_failure_sidecar() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("sample.pdf");
    std::fs::write(&input, b"%PDF-1.7\nmalformed %%EOF").unwrap();
    let output = directory.path().join("features.data");
    let failures = directory.path().join("failures.jsonl");
    assert!(
        Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
            .args(["extract", "pdf", "--type", "unknown", "--input"])
            .arg(&input)
            .arg("--output")
            .arg(&output)
            .args(["--format", "csv", "--failures"])
            .arg(&failures)
            .arg("--quiet")
            .status()
            .unwrap()
            .success()
    );
    let mut count = 0;
    sibilla_b_output::read(&output, sibilla_b_output::extraction_schema(), |_| {
        count += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        std::fs::read_to_string(&failures).unwrap().lines().count(),
        1
    );
}
/// Verify default symlink skipping and cycle-safe opt-in traversal.
#[test]
fn symlink_following_is_opt_in_and_cycles_stop() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input");
    std::fs::create_dir(&input).unwrap();
    let sample = input.join("sample.pdf");
    std::fs::write(&sample, b"%PDF-1.7\nmalformed %%EOF").unwrap();
    std::os::unix::fs::symlink(&sample, input.join("alias.pdf")).unwrap();
    std::os::unix::fs::symlink(&input, input.join("loop")).unwrap();
    for follow in [false, true] {
        let output = directory.path().join(format!("out-{follow}.parquet"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_sibilla-b"));
        command
            .args(["extract", "pdf", "--type", "unknown", "--input"])
            .arg(&input)
            .arg("--output")
            .arg(&output)
            .arg("--quiet");
        if follow {
            command.arg("--follow-symlinks");
        }
        assert!(command.status().unwrap().success());
        let mut count = 0;
        sibilla_b_output::read(&output, sibilla_b_output::extraction_schema(), |_| {
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, if follow { 2 } else { 1 });
    }
}
/// Verify capped extraction selects deterministic paths and resume rejects a changed cap.
#[test]
fn input_limit_is_deterministic_and_checked_on_resume() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("samples");
    std::fs::create_dir(&input).unwrap();
    for name in ["c.pdf", "a.pdf", "b.pdf"] {
        std::fs::write(input.join(name), b"%PDF-1.7\ninvalid %%EOF").unwrap();
    }
    let output = dir.path().join("limited.csv");
    let run = |limit: &str, resume: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sibilla-b"));
        command
            .args(["--quiet", "extract", "pdf", "--type", "unknown", "-i"])
            .arg(&input)
            .arg("-o")
            .arg(&output)
            .args(["--limit", limit]);
        if resume {
            command.arg("--resume");
        }
        command.output().unwrap()
    };
    assert!(!run("0", false).status.success());
    assert!(!output.exists());
    assert!(run("2", false).status.success());
    let mut paths = Vec::new();
    sibilla_b_output::read(&output, sibilla_b_output::extraction_schema(), |row| {
        paths.push(row["original_relative_path"].as_str().unwrap().to_owned());
        Ok(())
    })
    .unwrap();
    paths.sort();
    assert_eq!(paths, ["a.pdf", "b.pdf"]);
    let original = std::fs::read(&output).unwrap();
    std::fs::remove_file(&output).unwrap();
    assert!(run("2", true).status.success());
    assert_eq!(std::fs::read(&output).unwrap(), original);
    std::fs::remove_file(&output).unwrap();
    let changed = run("3", true);
    assert!(!changed.status.success());
    assert!(
        String::from_utf8_lossy(&changed.stderr)
            .contains("configuration or discovery manifest changed")
    );
}
