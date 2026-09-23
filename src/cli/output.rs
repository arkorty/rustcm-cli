use colored::Colorize;
use std::io::IsTerminal;

fn stderr_is_tty() -> bool {
    std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

/// Errors go to stderr only.
pub fn error(msg: impl AsRef<str>) {
    if stderr_is_tty() {
        eprintln!("{} {}", "error:".bright_red(), msg.as_ref());
    } else {
        eprintln!("error: {}", msg.as_ref());
    }
}
