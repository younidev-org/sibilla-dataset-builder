use std::sync::atomic::{AtomicBool, Ordering};
static STOP: AtomicBool = AtomicBool::new(false);
#[derive(Debug)]
pub struct Interrupted;
impl std::fmt::Display for Interrupted {
    /// Describe graceful interruption after committed checkpoints are safe.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "interrupted; committed checkpoints are preserved")
    }
}
impl std::error::Error for Interrupted {}
/// Set only a lock-free flag in the Unix signal handler.
extern "C" fn handle(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}
/// Install Ctrl+C handling in the coordinator after the checkpoint exists.
pub fn install() -> anyhow::Result<()> {
    if unsafe { libc::signal(libc::SIGINT, handle as *const () as libc::sighandler_t) }
        == libc::SIG_ERR
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
/// Report whether extraction should stop taking jobs.
pub fn requested() -> bool {
    STOP.load(Ordering::Relaxed)
}
/// Print a shell-quoted resume command preserving the current executable and arguments.
pub fn resume_command() -> String {
    let original: Vec<_> = std::env::args_os().collect();
    let mut retained = Vec::new();
    let mut index = 0;
    while index < original.len() {
        let arg = &original[index];
        if arg == "--failures"
            && original
                .get(index + 1)
                .is_some_and(|p| std::path::Path::new(p).exists())
        {
            index += 2;
            continue;
        }
        if arg
            .to_str()
            .and_then(|s| s.strip_prefix("--failures="))
            .is_some_and(|p| std::path::Path::new(p).exists())
        {
            index += 1;
            continue;
        }
        retained.push(arg.clone());
        index += 1;
    }
    let mut args: Vec<_> = retained
        .iter()
        .map(|a| format!("'{}'", a.to_string_lossy().replace('\'', "'\\''")))
        .collect();
    if !original.iter().any(|a| a == "--resume") {
        args.push("--resume".into());
    }
    args.join(" ")
}

/// Stop at a record boundary and print a usable resume command without publishing partial output.
pub fn check() -> anyhow::Result<()> {
    if requested() {
        eprintln!(
            "Committed checkpoints are preserved. Resume from the same directory:\n{}",
            resume_command()
        );
        return Err(Interrupted.into());
    }
    Ok(())
}
