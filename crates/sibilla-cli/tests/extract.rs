use std::process::Command;
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
        sibilla_output::read(&output, sibilla_output::extraction_schema(), |mut row| {
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
