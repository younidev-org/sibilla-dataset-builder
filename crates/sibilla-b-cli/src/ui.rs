use clap::ColorChoice;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::{ffi::OsString, io::IsTerminal, time::Duration};
// Help is rendered before clap returns parsed flags, so resolve presentation first.
/// Resolve global color flags and NO_COLOR before clap renders help or errors.
pub fn color_choice(args: &[OsString]) -> ColorChoice {
    if args.iter().any(|a| a == "--no-color") {
        return ColorChoice::Never;
    }
    let mut choice = if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        ColorChoice::Never
    } else {
        ColorChoice::Always
    };
    for (index, arg) in args.iter().enumerate().skip(1) {
        let value = arg
            .to_str()
            .and_then(|a| a.strip_prefix("--color="))
            .or_else(|| {
                if arg == "--color" {
                    args.get(index + 1).and_then(|a| a.to_str())
                } else {
                    None
                }
            });
        match value {
            Some("never") => choice = ColorChoice::Never,
            Some("auto") => choice = ColorChoice::Auto,
            Some("always") => choice = ColorChoice::Always,
            _ => {}
        }
    }
    choice
}
pub struct Ui {
    pub quiet: bool,
    pub color: bool,
}
impl Ui {
    /// Initialize terminal styling and quiet-mode behavior.
    pub fn new(choice: ColorChoice, quiet: bool) -> Self {
        let color = match choice {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            _ => std::io::stderr().is_terminal(),
        };
        console::set_colors_enabled_stderr(color);
        Self { quiet, color }
    }
    /// Create a terminal-only progress bar or spinner on stderr.
    pub fn progress(&self, message: &str, total: Option<u64>) -> ProgressBar {
        let bar = ProgressBar::new_spinner();
        if self.quiet || !std::io::stderr().is_terminal() {
            bar.set_draw_target(ProgressDrawTarget::hidden());
        }
        let template = match (total, self.color) {
            (Some(_), true) => {
                "{spinner:.cyan} {msg} [{wide_bar:.cyan/blue}] {pos}/{len} {per_sec} ETA {eta}"
            }
            (Some(_), false) => "{spinner} {msg} [{wide_bar}] {pos}/{len} {per_sec} ETA {eta}",
            (None, true) => "{spinner:.cyan} {msg} [{elapsed_precise}]",
            (None, false) => "{spinner} {msg} [{elapsed_precise}]",
        };
        bar.set_style(
            ProgressStyle::with_template(template)
                .expect("static progress template")
                .progress_chars("=>-"),
        );
        if let Some(total) = total {
            bar.set_length(total);
        }
        bar.set_message(message.to_owned());
        bar.enable_steady_tick(Duration::from_millis(100));
        bar
    }
    /// Print a styled completion message unless quiet mode is enabled.
    pub fn success(&self, message: &str) {
        if !self.quiet {
            eprintln!(
                "{} {message}",
                console::style("done:").green().bold().for_stderr()
            );
        }
    }
}
