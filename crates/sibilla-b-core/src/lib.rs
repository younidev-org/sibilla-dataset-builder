//! Worker protocol and OS restrictions. The coordinator never parses PDFs.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sibilla_b_schema::{Extraction, FormatExtractor, Limits};
use std::{
    io::{BufRead, Read, Write},
    path::PathBuf,
};
#[derive(Serialize, Deserialize)]
pub struct Job {
    pub path: PathBuf,
    pub limits: Limits,
}
/// Restrict the already-started worker before it sees any input.
#[cfg(target_os = "linux")]
pub fn restrict_worker() -> Result<()> {
    unsafe {
        for (resource, limit) in [
            (libc::RLIMIT_AS, 512 * 1024 * 1024),
            (libc::RLIMIT_CORE, 0),
            (libc::RLIMIT_NOFILE, 32),
        ] {
            let r = libc::rlimit {
                rlim_cur: limit,
                rlim_max: limit,
            };
            if libc::setrlimit(resource, &r) != 0 {
                bail!("worker resource restriction failed");
            }
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            bail!("no_new_privs failed");
        }
        // Deny socket creation and network operations, including inherited sockets.
        #[cfg(target_arch = "x86_64")]
        let arch = 0xc000003e;
        #[cfg(target_arch = "aarch64")]
        let arch = 0xc00000b7;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        bail!("unsupported seccomp architecture");
        // Validate the syscall ABI before matching syscall numbers.
        let mut filter = vec![
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 4,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 1,
                jf: 0,
                k: arch,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x80000000,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
            // Reject x32 syscall numbers, which share the x86_64 audit ABI.
            libc::sock_filter {
                code: 0x45,
                jt: 0,
                jf: 1,
                k: 0x40000000,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x80000000,
            },
        ];
        for syscall in [
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_sendto,
            libc::SYS_sendmsg,
            libc::SYS_recvfrom,
            libc::SYS_recvmsg,
        ] {
            filter.push(libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: syscall as u32,
            });
            filter.push(libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x00050000 | libc::EPERM as u32,
            });
        }
        filter.push(libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff0000,
        });
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        if libc::prctl(libc::PR_SET_SECCOMP, 2, &program) != 0 {
            bail!("worker network restriction failed");
        }
    }
    Ok(())
}
/// Apply worker process restrictions or reject unsupported operating systems.
#[cfg(not(target_os = "linux"))]
pub fn restrict_worker() -> Result<()> {
    bail!("restricted workers currently require Linux")
}

/// Serve bounded file-extraction jobs through the restricted worker protocol.
pub fn worker_loop(extractor: impl FormatExtractor) -> Result<()> {
    restrict_worker()?;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let job: Job = serde_json::from_str(&line?)?;
        set_cpu_budget(job.limits.timeout_seconds)?;
        let result = read_and_extract(&job, &extractor);
        serde_json::to_writer(&mut stdout, &result)?;
        writeln!(stdout)?;
        stdout.flush()?;
    }
    Ok(())
}
/// Refresh the per-job CPU ceiling using cumulative worker CPU usage.
fn set_cpu_budget(seconds: u64) -> Result<()> {
    unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        let mut current: libc::rlimit = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut usage) != 0
            || libc::getrlimit(libc::RLIMIT_CPU, &mut current) != 0
        {
            bail!("CPU usage unavailable");
        }
        let used = (usage.ru_utime.tv_sec as u64).saturating_add(usage.ru_stime.tv_sec as u64);
        current.rlim_cur = used
            .saturating_add(seconds)
            .saturating_add(2)
            .min(current.rlim_max);
        if libc::setrlimit(libc::RLIMIT_CPU, &current) != 0 {
            bail!("CPU restriction failed");
        }
    }
    Ok(())
}
/// Reject symlinks in every path component, including during races.
pub fn open_sample(path: &std::path::Path) -> Result<std::fs::File> {
    use std::os::{fd::FromRawFd, unix::ffi::OsStrExt};
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK) as u64,
        mode: 0,
        resolve: 0x04,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd as i32) })
}
/// Read a regular input within size limits and return features or a fixed failure code.
fn read_and_extract(job: &Job, extractor: &impl FormatExtractor) -> Extraction {
    let rejected = |code: &str| Extraction {
        common_features: None,
        format_features: None,
        status: sibilla_b_schema::Status::Rejected,
        error_code: Some(code.into()),
    };
    let result = (|| -> Result<Vec<u8>> {
        let file = open_sample(&job.path)?;
        if !file.metadata()?.is_file() {
            bail!("not regular");
        }
        let mut bytes = Vec::new();
        file.take(job.limits.max_size_bytes.saturating_add(1))
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    })();
    match result {
        Ok(bytes) => extractor.extract(&bytes, job.limits),
        Err(_) => rejected("input_read_failed"),
    }
}

/// One reusable parser process. A timed-out or crashed process is discarded.
pub struct Worker {
    child: std::process::Child,
    input: std::process::ChildStdin,
    results: std::sync::mpsc::Receiver<Result<Extraction, String>>,
}
impl Worker {
    /// Spawn a reusable parser process and connect its bounded result channel.
    pub fn start(executable: &std::path::Path) -> Result<Self> {
        use std::process::{Command, Stdio};
        let mut child = Command::new(executable)
            .arg("worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let input = child.stdin.take().context("worker stdin")?;
        let output = child.stdout.take().context("worker stdout")?;
        let (tx, results) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(output).lines() {
                let row = line
                    .map_err(|_| "worker_read_failed".to_owned())
                    .and_then(|s| {
                        serde_json::from_str(&s).map_err(|_| "worker_protocol_failed".into())
                    });
                if tx.send(row).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            input,
            results,
        })
    }
    /// Submit one job and convert worker timeout or death into a failure record.
    pub fn extract(&mut self, job: &Job) -> Result<Extraction> {
        let sent = (|| -> Result<()> {
            serde_json::to_writer(&mut self.input, job)?;
            writeln!(self.input)?;
            self.input.flush()?;
            Ok(())
        })();
        let received = if sent.is_ok() {
            self.results
                .recv_timeout(std::time::Duration::from_secs(job.limits.timeout_seconds))
        } else {
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
        };
        match received {
            Ok(Ok(row)) => Ok(row),
            result => {
                self.child.kill().ok();
                self.child.wait().ok();
                let timeout = matches!(result, Err(std::sync::mpsc::RecvTimeoutError::Timeout));
                Ok(Extraction {
                    common_features: None,
                    format_features: None,
                    status: if timeout {
                        sibilla_b_schema::Status::Timeout
                    } else {
                        sibilla_b_schema::Status::Failed
                    },
                    error_code: Some(
                        if timeout {
                            "worker_timeout"
                        } else {
                            "worker_crash"
                        }
                        .into(),
                    ),
                })
            }
        }
    }
    /// Report whether the worker process is still running.
    pub fn alive(&mut self) -> Result<bool> {
        Ok(self.child.try_wait()?.is_none())
    }
}
impl Drop for Worker {
    /// Kill and reap the parser process when its supervisor is dropped.
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}
#[cfg(test)]
mod tests {
    /// Run the irreversible network-restriction probe in an isolated subprocess.
    #[test]
    fn restricted_process_denies_network() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "tests::restriction_probe",
                "--test-threads=1",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    /// Verify that the restricted subprocess cannot create a network listener.
    #[test]
    #[ignore = "runs in a subprocess because restrictions are irreversible"]
    fn restriction_probe() {
        super::restrict_worker().unwrap();
        let error = std::net::TcpListener::bind("127.0.0.1:0").unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
    }
}
