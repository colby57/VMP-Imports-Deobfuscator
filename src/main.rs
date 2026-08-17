#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
compile_error!("vid must be built for x86_64-pc-windows-msvc");

mod app;
pub mod emulator;
mod exports;
mod import_layout;
mod imports;
mod patches;
mod pe;
mod process;
mod transfers;

use std::process::ExitCode;

use spdlog::formatter::{PatternFormatter, pattern};

fn main() -> ExitCode {
    configure_logging();
    app::run()
}

fn configure_logging() {
    let formatter = Box::new(PatternFormatter::new(pattern!(
        "[{time}] [{^{level}}] {payload}{eol}"
    )));

    for sink in spdlog::default_logger().sinks() {
        sink.set_formatter(formatter.clone());
    }
}
