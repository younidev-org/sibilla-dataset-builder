// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 younidev-org.

use sibilla_b_core::{Job, Worker};
use sibilla_b_schema::{Limits, Status};
use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};
/// Verify worker reuse and fixed read-failure records across consecutive jobs.
#[test]
fn worker_protocol_reuses_process_and_preserves_failures() {
    let executable = Path::new(env!("CARGO_BIN_EXE_sibilla-b"));
    let mut worker = Worker::start(executable).unwrap();
    for _ in 0..2 {
        let row = worker
            .extract(&Job {
                selection: Default::default(),
                path: "/nonexistent-sibilla-test.pdf".into(),
                limits: Limits::default(),
            })
            .unwrap();
        assert_eq!(row.status, Status::Rejected);
        assert_eq!(row.error_code.as_deref(), Some("input_read_failed"));
        assert!(worker.alive().unwrap());
    }
}
/// Verify malformed worker requests terminate unsuccessfully.
#[test]
fn worker_rejects_invalid_protocol() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sibilla-b"))
        .arg("worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "invalid").unwrap();
    assert!(!child.wait().unwrap().success());
}
/// Verify a dead worker yields a failure record instead of aborting the caller.
#[test]
fn exited_worker_becomes_failure_record() {
    let mut worker = Worker::start(Path::new("/bin/false")).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(30));
    let row = worker
        .extract(&Job {
            selection: Default::default(),
            path: "unused".into(),
            limits: Limits::default(),
        })
        .unwrap();
    assert_eq!(row.status, Status::Failed);
    assert!(!worker.alive().unwrap());
}
/// Verify a timed-out worker is killed and reaped promptly.
#[test]
fn timed_out_process_is_killed() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("sleep-worker");
    std::fs::write(&executable, b"#!/bin/sh\nexec sleep 10\n").unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut worker = Worker::start(&executable).unwrap();
    let started = std::time::Instant::now();
    let row = worker
        .extract(&Job {
            selection: Default::default(),
            path: "unused".into(),
            limits: Limits {
                timeout_seconds: 0,
                ..Limits::default()
            },
        })
        .unwrap();
    assert_eq!(row.status, Status::Timeout);
    assert!(!worker.alive().unwrap());
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
}
/// Verify sample opening rejects symlinks in intermediate path components.
#[test]
fn sample_open_rejects_symlink_components() {
    let directory = tempfile::tempdir().unwrap();
    let real = directory.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::write(real.join("sample.pdf"), b"safe test bytes").unwrap();
    std::os::unix::fs::symlink(&real, directory.path().join("alias")).unwrap();
    assert!(sibilla_b_core::open_sample(&real.join("sample.pdf")).is_ok());
    assert!(sibilla_b_core::open_sample(&directory.path().join("alias/sample.pdf")).is_err());
}
