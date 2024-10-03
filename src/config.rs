use std::fs;
use std::process;
use std::time::Duration;
use toml::from_str;

use crate::relay;

pub const NO_TIMEOUT: Duration = Duration::from_secs(300);
pub const NO_BANDWIDTH_LIMIT: u64 = 1_000_000_000_000_u64;

const HELP: &str = "\
A simple HTTP(S) tunnel

Usage: http-tunnel [OPTIONS] --bind <ADDRESS>

Options:
  -c, --config <FILE>          Configuration file
      --log <FILE>             Log file
  -q, --quiet
  -v, --verbose...             Sets the level of verbosity
      --metrics                Gather runtime metrics
      --tcp                    Enable TCP mode
      --bind <ADDRESS>         Bind address, e.g. 0.0.0.0:8443
  -d, --destination <ADDRESS>  Destination address for TCP mode, e.g. moepmoep.com:8118
  -h, --help                   Print help information (use `--help` for more detail)
  -V, --version                Print version information";

use std::{fmt, ops};

#[derive(Clone, Debug)]
pub struct Regex(regex_lite::Regex);

impl Regex {
    pub fn new(pattern: &str) -> Result<Regex, regex_lite::Error> {
        Ok(Regex(regex_lite::RegexBuilder::new(pattern).build()?))
    }
}

impl ops::Deref for Regex {
    type Target = regex_lite::Regex;
    fn deref(&self) -> &regex_lite::Regex {
        &self.0
    }
}

impl<'de> serde::Deserialize<'de> for Regex {
    fn deserialize<D>(de: D) -> Result<Regex, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, Visitor};

        struct RegexVisitor;

        impl<'de> Visitor<'de> for RegexVisitor {
            type Value = Regex;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a regular expression pattern")
            }

            fn visit_str<E: Error>(self, v: &str) -> Result<Regex, E> {
                regex_lite::Regex::new(v)
                    .map(Regex)
                    .map_err(|err| E::custom(err.to_string()))
            }
        }

        de.deserialize_str(RegexVisitor)
    }
}

impl fmt::Display for Regex {
    /// Shows the original regular expression.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct ClientConnection {
    #[serde(default = "default_timeout")]
    #[serde(with = "humantime_serde")]
    pub initiation_timeout: Duration,
    #[serde(default)]
    pub relay_policy: relay::Policy,
}

#[derive(Deserialize, Clone, Debug)]
pub struct TargetConnection {
    #[serde(default = "default_timeout", with = "humantime_serde")]
    pub dns_cache_ttl: Duration,
    #[serde(default)]
    pub ipv4_only: bool,
    #[serde(default)]
    pub allowed_targets: Option<Regex>,
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default = "default_timeout", with = "humantime_serde")]
    pub connect_timeout: Duration,
    #[serde(default)]
    pub relay_policy: relay::Policy,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Tunnel {
    pub client_connection: ClientConnection,
    pub target_connection: TargetConnection,
}

#[derive(Clone, Debug)]
pub enum ProxyMode {
    Http,
    Tcp(String),
}

#[derive(Clone, Debug)]
pub struct Proxy {
    pub mode: ProxyMode,
    pub bind_address: String,
    pub tunnel_config: Tunnel,
    pub verbosity: u8,
    pub quiet: bool,
    pub log_file: Option<String>,
    pub metrics_enabled: bool,
}

fn default_timeout() -> Duration {
    NO_TIMEOUT
}

impl Default for Tunnel {
    fn default() -> Self {
        // by default no restrictions
        Self {
            client_connection: ClientConnection {
                initiation_timeout: NO_TIMEOUT,
                relay_policy: relay::Policy {
                    idle_timeout: NO_TIMEOUT,
                    min_rate_bpm: 0,
                    max_rate_bps: NO_BANDWIDTH_LIMIT,
                },
            },
            target_connection: TargetConnection {
                dns_cache_ttl: NO_TIMEOUT,
                ipv4_only: false,
                allowed_targets: None,
                allowed: vec![],
                connect_timeout: NO_TIMEOUT,
                relay_policy: relay::Policy {
                    idle_timeout: NO_TIMEOUT,
                    min_rate_bpm: 0,
                    max_rate_bps: NO_BANDWIDTH_LIMIT,
                },
            },
        }
    }
}

impl Tunnel {
    fn build_allowed_targets(mut self) -> Result<Tunnel, regex_lite::Error> {
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

impl Proxy {
    pub fn from_command_line() -> Proxy {
        match parse_args() {
            Ok(args) => args,
            Err(e) => {
                eprintln!("ERROR: {e}");
                process::exit(1);
            }
        }
    }

    fn read_tunnel_config(filename: &str) -> Tunnel {
        let tomlfile = match fs::read_to_string(filename) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error reading file: {e}");
                process::exit(1);
            }
        };

        let result: Tunnel = match from_str(&tomlfile) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error parsing toml {filename}: {e}");
                process::exit(1);
            }
        };

        match result.build_allowed_targets() {
            Ok(tunnelconfig) => tunnelconfig,
            Err(e) => {
                eprintln!("Could not build list of allowed targets: {e}");
                process::exit(1);
            }
        }
    }
}

fn parse_args() -> Result<Proxy, lexopt::Error> {
    use lexopt::prelude::*;

    let mut config = None;
    let mut log_file = None;
    let mut quiet = false;
    let mut verbosity = 0;
    let mut metrics_enabled = false;
    let mut tcp = false;
    let mut bind_address = String::new();
    let mut destination = String::new();
    let mut mode = ProxyMode::Http;

    let mut parser = lexopt::Parser::from_env();

    while let Some(arg) = parser.next()? {
        match arg {
            Short('q') | Long("quiet") => {
                quiet = true;
            }
            Short('v') | Long("verbose") => {
                verbosity += 1;
            }
            Short('c') | Long("config") => {
                config = Some(parser.value()?.string()?);
            }
            Long("log") => {
                log_file = Some(parser.value()?.string()?);
            }
            Long("metrics") => {
                metrics_enabled = true;
            }
            Long("tcp") => {
                tcp = true;
            }
            Long("bind") => {
                bind_address = parser.value()?.parse()?;
            }
            Short('d') | Long("destination") => {
                destination = parser.value()?.string()?;
            }
            Short('h') | Long("help") => {
                println!("{HELP}");
                process::exit(0);
            }
            Short('V') | Long("version") => {
                println!("{} {}", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"));
                process::exit(0);
            }
            _ => return Err(arg.unexpected()),
        }
    }

    if bind_address.is_empty() {
        eprintln!("--bind <ADDRESS> argument is required.");
        process::exit(1);
    }

    let tunnel_config = match config {
        None => Tunnel::default(),
        Some(config) => Proxy::read_tunnel_config(&config),
    };

    if tcp {
        if destination.is_empty() {
            eprintln!("--destination <ADDRESS> argument is required w/ --tcp.");
            process::exit(1);
        }
        mode = ProxyMode::Tcp(destination);
    }

    Ok(Proxy {
        mode,
        bind_address,
        tunnel_config,
        verbosity,
        quiet,
        log_file,
        metrics_enabled,
    })
}
