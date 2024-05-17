#![allow(clippy::module_name_repetitions)]

use clap::{Arg, ArgAction, Command};
use regex::Regex;
use std::fs;
use std::io::{Error, ErrorKind};
use std::time::Duration;
use tokio::io;
use toml::from_str;

use crate::relay::{RelayPolicy, NO_BANDWIDTH_LIMIT, NO_TIMEOUT};

#[derive(Deserialize, Clone, Debug)]
pub struct ClientConnectionConfig {
    #[serde(default = "default_timeout")]
    #[serde(with = "humantime_serde")]
    pub initiation_timeout: Duration,
    #[serde(default)]
    pub relay_policy: RelayPolicy,
}

#[derive(Deserialize, Clone, Debug)]
pub struct TargetConnectionConfig {
    #[serde(default = "default_timeout")]
    #[serde(with = "humantime_serde")]
    pub dns_cache_ttl: Duration,
    #[serde(default)]
    pub ipv4_only: bool,
    #[serde(default)]
    #[serde(with = "serde_regex")]
    pub allowed_targets: Option<Regex>,
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default = "default_timeout")]
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
    #[serde(default)]
    pub relay_policy: RelayPolicy,
}

#[derive(Deserialize, Clone, Debug)]
pub struct TunnelConfig {
    pub client_connection: ClientConnectionConfig,
    pub target_connection: TargetConnectionConfig,
}

#[derive(Clone, Debug)]
pub enum ProxyMode {
    Http,
    Tcp(String),
}

#[derive(Clone, Debug)]
pub struct ProxyConfiguration {
    pub mode: ProxyMode,
    pub bind_address: String,
    pub tunnel_config: TunnelConfig,
    pub verbosity: u8,
    pub quiet: bool,
    pub log_file: Option<String>,
    pub metrics_enabled: bool,
}

fn default_timeout() -> Duration {
    NO_TIMEOUT
}

impl Default for TunnelConfig {
    fn default() -> Self {
        // by default no restrictions
        Self {
            client_connection: ClientConnectionConfig {
                initiation_timeout: NO_TIMEOUT,
                relay_policy: RelayPolicy {
                    idle_timeout: NO_TIMEOUT,
                    min_rate_bpm: 0,
                    max_rate_bps: NO_BANDWIDTH_LIMIT,
                },
            },
            target_connection: TargetConnectionConfig {
                dns_cache_ttl: NO_TIMEOUT,
                ipv4_only: false,
                allowed_targets: None,
                allowed: vec![],
                connect_timeout: NO_TIMEOUT,
                relay_policy: RelayPolicy {
                    idle_timeout: NO_TIMEOUT,
                    min_rate_bpm: 0,
                    max_rate_bps: NO_BANDWIDTH_LIMIT,
                },
            },
        }
    }
}

impl TunnelConfig {
    fn build_allowed_targets(mut self) -> Result<TunnelConfig, regex::Error> {
        if !self.target_connection.allowed.is_empty() {
            let with_port = Regex::new(":[0-9]+$").expect("BUG: Bad port regex");
            let mut vec = Vec::new();
            let mut host: String;

            for i in &self.target_connection.allowed {
                let host_regex = i.replace('.', "\\.").replace('*', "[^.]+");
                if host_regex.starts_with("http://") {
                    host = host_regex.replace("http://", "");
                } else if host_regex.starts_with("https://") {
                    host = host_regex.replace("https://", "");
                    if !with_port.is_match(&host) {
                        host += ":443";
                    }
                } else {
                    host = host_regex;
                }

                if !with_port.is_match(&host) {
                    host += ":80";
                }
                vec.push(host.to_string());
            }

            let targets = "^(?i)(".to_owned() + &vec.join("|") + ")$";

            self.target_connection.allowed_targets = Some(Regex::new(&targets)?);
        }
        Ok(self)
    }
}

impl ProxyConfiguration {
    #[allow(clippy::too_many_lines)]
    pub fn from_command_line() -> io::Result<ProxyConfiguration> {
        let matches = Command::new("Simple HTTP(S) Tunnel")
            .version(env!("CARGO_PKG_VERSION"))
            .author(env!("CARGO_PKG_AUTHORS"))
            .about("A simple HTTP(S) tunnel")
            .arg(
                Arg::new("CONFIG")
                    .short('c')
                    .long("config")
                    .value_parser(clap::builder::NonEmptyStringValueParser::new())
                    .value_name("FILE")
                    .help("Configuration file")
                    .num_args(1),
            )
            .arg(
                Arg::new("LOG")
                    .long("log")
                    .value_parser(clap::builder::NonEmptyStringValueParser::new())
                    .value_name("FILE")
                    .help("Log file")
                    .num_args(1),
            )
            .arg(
                Arg::new("QUIET")
                    .short('q')
                    .long("quiet")
                    .action(ArgAction::SetTrue)
                    .conflicts_with("VERBOSE"),
            )
            .arg(
                Arg::new("VERBOSE")
                    .short('v')
                    .long("verbose")
                    .action(ArgAction::Count)
                    .conflicts_with("QUIET")
                    .conflicts_with("METRICS")
                    .help("Sets the level of verbosity")
                    .long_help(
                        "-v for log level INFO
-vv for log level DEBUG
more for TRACE log level",
                    ),
            )
            .arg(
                Arg::new("METRICS")
                    .long("metrics")
                    .action(ArgAction::SetTrue)
                    .help("Gather runtime metrics"),
            )
            .arg(
                Arg::new("TCP")
                    .long("tcp")
                    .action(ArgAction::SetTrue)
                    .requires("DEST")
                    .help("Enable TCP mode"),
            )
            .arg(
                Arg::new("BIND")
                    .long("bind")
                    .value_parser(clap::builder::NonEmptyStringValueParser::new())
                    .required(true)
                    .value_name("ADDRESS")
                    .help("Bind address, e.g. 0.0.0.0:8443")
                    .num_args(1),
            )
            .arg(
                Arg::new("DEST")
                    .short('d')
                    .long("destination")
                    .value_parser(clap::builder::NonEmptyStringValueParser::new())
                    .value_name("ADDRESS")
                    .help("Destination address for TCP mode, e.g. moepmoep.com:8118")
                    .num_args(1),
            )
            .get_matches();
        let config = matches.get_one("CONFIG").map(std::string::String::as_str);

        let log_file = matches
            .get_one::<String>("LOG")
            .map(std::string::ToString::to_string);

        let metrics_enabled = matches.get_flag("METRICS");

        let verbosity = matches
            .get_one::<u8>("VERBOSE")
            .expect("Count always defaulted");

        let quiet = matches.get_flag("QUIET");

        let bind_address = matches
            .get_one("BIND")
            .map(std::string::String::as_str)
            .expect("missing bind address")
            .to_string();

        let mode = if matches.get_flag("TCP") {
            let destination = matches
                .get_one("DEST")
                .map(std::string::String::as_str)
                .expect("misconfiguration for destination")
                .to_string();
            ProxyMode::Tcp(destination)
        } else {
            ProxyMode::Http
        };

        let tunnel_config = match config {
            None => TunnelConfig::default(),
            Some(config) => ProxyConfiguration::read_tunnel_config(config)?,
        };

        Ok(ProxyConfiguration {
            bind_address,
            mode,
            tunnel_config,
            verbosity: *verbosity,
            quiet,
            log_file,
            metrics_enabled,
        })
    }

    fn read_tunnel_config(filename: &str) -> io::Result<TunnelConfig> {
        let tomlfile = fs::read_to_string(filename).map_err(|e| {
            eprintln!("Error reading file {filename}: {e}");
            e
        })?;

        let result: TunnelConfig = from_str(&tomlfile).map_err(|e| {
            eprintln!("Error parsing toml {filename}: {e}");
            Error::from(ErrorKind::InvalidInput)
        })?;

        match result.build_allowed_targets() {
            Ok(tunnelconfig) => Ok(tunnelconfig),
            Err(e) => {
                eprintln!("Could not build list of allowed targets: {e}");
                Err(Error::from(ErrorKind::InvalidInput))
            }
        }
    }
}
