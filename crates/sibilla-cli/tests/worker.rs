use sibilla_core::{Job, Worker};
use sibilla_schema::{Limits, Status};
use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};
#[test]
fn worker_protocol_reuses_process_and_preserves_failures() {
    let executable = Path::new(env!("CARGO_BIN_EXE_sibilla-b"));
    let mut worker = Worker::start(executable).unwrap();
    for _ in 0..2 {
        let row = worker
            .extract(&Job {
                path: "/nonexistent-sibilla-test.pdf".into(),
                limits: Limits::default(),
            })
            .unwrap();
        assert_eq!(row.status, Status::Rejected);
        assert_eq!(row.error_code.as_deref(), Some("input_read_failed"));
        assert!(worker.alive().unwrap());
    }
}
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
#[test]
fn exited_worker_becomes_failure_record() {
    let mut worker = Worker::start(Path::new("/bin/false")).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(30));
    let row = worker
        .extract(&Job {
            path: "unused".into(),
            limits: Limits::default(),
        })
        .unwrap();
    assert_eq!(row.status, Status::Failed);
    assert!(!worker.alive().unwrap());
}
