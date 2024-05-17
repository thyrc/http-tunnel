use crate::tunnel::{TunnelCtx, TunnelStats};
use log::{error, warn};
use simplelog::{
    ColorChoice, CombinedLogger, ConfigBuilder, LevelFilter, SharedLogger, TermLogger,
    TerminalMode, WriteLogger,
};
use std::fs::OpenOptions;
use tokio::io;

pub fn report_tunnel_metrics(ctx: TunnelCtx, stats: io::Result<TunnelStats>) {
    if let Ok(s) = stats {
        warn!(target: "metrics", "{}", serde_json::to_string(&s).expect("JSON serialization failed"));
    } else {
        error!("Failed to get stats for TID={}", ctx);
    }
}

pub fn init_logger(
    logfile: &Option<String>,
    verbosity: u8,
    quiet: bool,
) -> Result<(), std::io::Error> {
    let level = match (quiet, verbosity) {
        (true, _) => LevelFilter::Error,
        (_, 0) => LevelFilter::Warn,
        (_, 1) => LevelFilter::Info,
        (_, 2) => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    let logconfig = ConfigBuilder::new()
        .set_time_format_rfc3339()
        .set_time_offset_to_local()
        .unwrap_or_else(|v| v)
        .build();

    let logger: Vec<Box<dyn SharedLogger>> = match logfile {
        Some(file) => vec![WriteLogger::new(
            level,
            logconfig,
            OpenOptions::new().create(true).append(true).open(file)?,
        )],
        _ => vec![TermLogger::new(
            level,
            logconfig,
            TerminalMode::Stderr,
            ColorChoice::Auto,
        )],
    };

    if CombinedLogger::init(logger).is_err() {
        error!("Could not initialize logger.");
    };

    Ok(())
}
