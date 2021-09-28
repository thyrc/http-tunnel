use log::{debug, error, info, LevelFilter};
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Root};
use log4rs::Config;
use tokio::io;

use crate::tunnel::{TunnelCtx, TunnelStats};

pub fn report_tunnel_metrics(ctx: TunnelCtx, stats: io::Result<TunnelStats>) {
    if let Ok(s) = stats {
        info!(target: "metrics", "{}", serde_json::to_string(&s).expect("JSON serialization failed"));
    } else {
        error!("Failed to get stats for TID={}", ctx);
    }
}

pub fn init_logger(log_config_file: &Option<String>) {
    let logger_configuration = match log_config_file {
        Some(file) => file,
        _ => "./config/log4rs.yaml",
    };

    debug!(
        "Reading logging configuration from {}",
        logger_configuration
    );

    if let Err(e) = log4rs::init_file(
        logger_configuration,
        log4rs::config::Deserializers::default(),
    ) {
        println!(
            "Cannot initialize logger from {}, error=[{}]. Logging to the console.",
            logger_configuration, e
        );
        let config = Config::builder()
            .appender(
                Appender::builder()
                    .build("application", Box::new(ConsoleAppender::builder().build())),
            )
            .build(
                Root::builder()
                    .appender("application")
                    .build(LevelFilter::Info),
            )
            .unwrap();
        log4rs::init_config(config).expect("Bug: bad default config");
    }
}
