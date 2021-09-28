use clap::{App, Arg};
use regex::Regex;
use std::fs::File;
use std::io::{Error, ErrorKind, Read};
use std::time::Duration;
use tokio::io;

use crate::relay::{RelayPolicy, NO_BANDWIDTH_LIMIT, NO_TIMEOUT};

#[derive(Deserialize, Clone, Debug)]
pub struct ClientConnectionConfig {
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub initiation_timeout: Duration,
    #[serde(default)]
    pub relay_policy: RelayPolicy,
}

#[derive(Deserialize, Clone, Debug)]
pub struct TargetConnectionConfig {
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub dns_cache_ttl: Duration,
    #[serde(default)]
    pub ipv4_only: bool,
    #[serde(default)]
    #[serde(with = "serde_regex")]
    pub allowed_targets: Option<Regex>,
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default)]
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

#[derive(Clone, Builder, Debug)]
pub struct ProxyConfiguration {
    pub mode: ProxyMode,
    pub bind_address: String,
    pub tunnel_config: TunnelConfig,
    pub log_config_file: Option<String>,
    pub metrics_enabled: bool,
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
                let host_regex = i.replace(".", "\\.").replace("*", "[^.]+");
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

            let targets = "^(?i)(".to_owned() + &vec.join("|") + &")$".to_owned();

            self.target_connection.allowed_targets = Some(Regex::new(&targets)?);
        }
        Ok(self)
    }
}

impl ProxyConfiguration {
    pub fn from_command_line() -> io::Result<ProxyConfiguration> {
        let matches = App::new("Simple HTTP(S) Tunnel")
            .version(env!("CARGO_PKG_VERSION"))
            .author(env!("CARGO_PKG_AUTHORS"))
            .about("A simple HTTP(S) tunnel")
            .arg(
                Arg::with_name("CONFIG")
                    .short("c")
                    .long("config")
                    .value_name("FILE")
                    .help("Configuration file")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name("LOG")
                    .long("log")
                    .value_name("FILE")
                    .help("Log configuration file")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name("METRICS")
                    .long("metrics")
                    .value_name("METRICS")
                    .help("Gather runtime metrics via the `metrics` appender")
                    .takes_value(false),
            )
            .arg(
                Arg::with_name("TCP")
                    .long("tcp")
                    .requires("DEST")
                    .help("Enable TCP mode"),
            )
            .arg(
                Arg::with_name("BIND")
                    .long("bind")
                    .required(true)
                    .value_name("ADDRESS")
                    .help("Bind address, e.g. 0.0.0.0:8443")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name("DEST")
                    .short("d")
                    .long("destination")
                    .value_name("ADDRESS")
                    .help("Destination address for TCP mode, e.g. moepmoep.com:8118")
                    .takes_value(true),
            )
            .get_matches();
        let config = matches.value_of("CONFIG");

        let log_config_file = matches
            .value_of("LOG")
            .map(std::string::ToString::to_string);

        let metrics_enabled = matches.is_present("METRICS");

        let bind_address = matches
            .value_of("BIND")
            .expect("missing bind address")
            .to_string();

        let mode = if matches.is_present("TCP") {
            let destination = matches
                .value_of("DEST")
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

        Ok(ProxyConfigurationBuilder::default()
            .bind_address(bind_address)
            .mode(mode)
            .tunnel_config(tunnel_config)
            .log_config_file(log_config_file)
            .metrics_enabled(metrics_enabled)
            .build()
            .expect("ProxyConfigurationBuilder failed"))
    }

    fn read_tunnel_config(filename: &str) -> io::Result<TunnelConfig> {
        let mut file = File::open(filename).map_err(|e| {
            eprintln!("Error opening config file {}: {}", filename, e);
            e
        })?;

        let mut yaml = vec![];

        file.read_to_end(&mut yaml).map_err(|e| {
            eprintln!("Error reading file {}: {}", filename, e);
            e
        })?;

        let result: TunnelConfig = serde_yaml::from_slice(&yaml).map_err(|e| {
            eprintln!("Error parsing yaml {}: {}", filename, e);
            Error::from(ErrorKind::InvalidInput)
        })?;

        match result.build_allowed_targets() {
            Ok(tunnelconfig) => Ok(tunnelconfig),
            Err(e) => {
                eprintln!("Could not build list of allowed targets: {}", e);
                Err(Error::from(ErrorKind::InvalidInput))
            }
        }
    }
}
