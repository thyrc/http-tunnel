#![allow(clippy::module_name_repetitions)]

use core::fmt;
use log::{debug, error, info};
use std::future::Future;
use std::time::{Duration, Instant};
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::time::timeout;

use crate::tunnel::TunnelCtx;

pub const NO_TIMEOUT: Duration = Duration::from_secs(300);
pub const NO_BANDWIDTH_LIMIT: u64 = 1_000_000_000_000_u64;
const BUFFER_SIZE: usize = 16 * 1024;

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub enum RelayShutdownReasons {
    /// If a reader connection was gracefully closed
    GracefulShutdown,
    ReadError,
    WriteError,
    ReaderTimeout,
    WriterTimeout,
    TooSlow,
    TooFast,
}

/// Relays traffic from one stream to another in a single direction.
/// To relay two sockets in full-duplex mode you need to create two `Relays` in both directions.
/// It doesn't really matter what is the protocol, as it only requires `AsyncReadExt`
/// and `AsyncWriteExt` traits from the source and the target.
#[allow(clippy::struct_field_names)]
#[derive(Clone)]
pub struct Relay {
    pub name: &'static str,
    pub relay_policy: RelayPolicy,
    pub tunnel_ctx: TunnelCtx,
}

/// Stats after the relay is closed. Can be used for telemetry/monitoring.
#[derive(Clone, Debug, Serialize)]
pub struct RelayStats {
    pub shutdown_reason: RelayShutdownReasons,
    pub total_bytes: usize,
    pub event_count: usize,
    pub duration: Duration,
}

/// Relay policy is meant to protect targets and proxy servers from
/// different sorts of abuse. Currently it only checks too slow or too fast connections,
/// which may lead to different capacity issues.
#[derive(Clone, Debug, Deserialize)]
pub struct RelayPolicy {
    #[serde(default = "default_timeout")]
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,
    /// Min bytes-per-minute (bpm)
    #[serde(default = "default_min_rate")]
    pub min_rate_bpm: u64,
    // Max bytes-per-second (bps)
    #[serde(default = "default_max_rate")]
    pub max_rate_bps: u64,
}

impl Relay {
    /// Relays data in a single direction. E.g.
    /// ```ignore
    /// let upstream = tokio::spawn(async move {
    ///     upstream_relay.relay_data(client_recv, target_send).await
    /// });
    /// let downstream = tokio::spawn(async move {
    ///     downstream_relay.relay_data(target_recv, client_send).await
    /// });
    /// let downstream_stats = downstream.await??;
    /// let upstream_stats = upstream.await??;
    /// ```
    pub async fn relay_data<R: AsyncReadExt + Sized, W: AsyncWriteExt + Sized>(
        self,
        mut source: ReadHalf<R>,
        mut dest: WriteHalf<W>,
    ) -> io::Result<RelayStats> {
        let mut buffer = [0; BUFFER_SIZE];

        let mut total_bytes = 0;
        let mut event_count = 0;
        let start_time = Instant::now();
        let shutdown_reason;

        loop {
            let read_result = self
                .relay_policy
                .timed_operation(source.read(&mut buffer))
                .await;

            if read_result.is_err() {
                shutdown_reason = RelayShutdownReasons::ReaderTimeout;
                break;
            }

            let n = match read_result.unwrap() {
                Ok(0) => {
                    shutdown_reason = RelayShutdownReasons::GracefulShutdown;
                    break;
                }
                Ok(n) => n,
                Err(e) => {
                    error!(
                        "{} failed to read. Err = {:?}, CTX={}",
                        self.name, e, self.tunnel_ctx
                    );
                    shutdown_reason = RelayShutdownReasons::ReadError;
                    break;
                }
            };

            let write_result = self
                .relay_policy
                .timed_operation(dest.write_all(&buffer[..n]))
                .await;

            if write_result.is_err() {
                shutdown_reason = RelayShutdownReasons::WriterTimeout;
                break;
            }

            if let Err(e) = write_result.unwrap() {
                error!(
                    "{} failed to write {} bytes. Err = {:?}, CTX={}",
                    self.name, n, e, self.tunnel_ctx
                );
                shutdown_reason = RelayShutdownReasons::WriteError;
                break;
            }

            total_bytes += n;
            event_count += 1;

            if let Err(rate_violation) = self
                .relay_policy
                .check_transmission_rates(&start_time, total_bytes)
            {
                shutdown_reason = rate_violation;
                break;
            }
        }

        self.shutdown(&mut dest, &shutdown_reason).await;

        let duration = Instant::now().duration_since(start_time);

        let stats = RelayStats {
            shutdown_reason,
            total_bytes,
            event_count,
            duration,
        };

        info!("{} closed: {}, CTX={}", self.name, stats, self.tunnel_ctx);

        Ok(stats)
    }

    async fn shutdown<W: AsyncWriteExt + Sized>(
        &self,
        dest: &mut WriteHalf<W>,
        reason: &RelayShutdownReasons,
    ) {
        match dest.shutdown().await {
            Ok(()) => {
                debug!(
                    "{} shutdown due do {:?}, CTX={}",
                    self.name, reason, self.tunnel_ctx
                );
            }
            Err(e) => {
                error!(
                    "{} failed to shutdown. Err = {:?}, CTX={}",
                    self.name, e, self.tunnel_ctx
                );
            }
        }
    }
}

impl RelayPolicy {
    /// Basic rate limiting. Placeholder for more sophisticated policy handling,
    /// e.g. sliding windows, detecting heavy hitters, etc.
    pub fn check_transmission_rates(
        &self,
        start: &Instant,
        total_bytes: usize,
    ) -> Result<(), RelayShutdownReasons> {
        if self.min_rate_bpm == 0 && self.max_rate_bps >= NO_BANDWIDTH_LIMIT {
            return Ok(());
        }
        let elapsed = Instant::now().duration_since(*start);
        #[allow(clippy::cast_precision_loss)]
        if elapsed.as_secs_f32() > 5. && total_bytes as u64 / elapsed.as_secs() > self.max_rate_bps
        {
            // prevent bandwidth abuse
            Err(RelayShutdownReasons::TooFast)
        } else if elapsed.as_secs_f32() >= 30.
            && total_bytes as f64 / elapsed.as_secs_f64() / 60. < self.min_rate_bpm as f64
        {
            Err(RelayShutdownReasons::TooSlow)
        } else {
            Ok(())
        }
    }

    /// Each async operation must be time-bound.
    pub async fn timed_operation<T: Future>(&self, f: T) -> Result<<T as Future>::Output, ()> {
        if self.idle_timeout >= NO_TIMEOUT {
            return Ok(f.await);
        }
        let result = timeout(self.idle_timeout, f).await;

        if let Ok(r) = result {
            Ok(r)
        } else {
            Err(())
        }
    }
}

impl fmt::Display for RelayStats {
    #[allow(clippy::cast_precision_loss)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "shutdown_reason={:?}, bytes={}, event_count={}, duration={:?}, rate_kbps={:.3}",
            self.shutdown_reason,
            self.total_bytes,
            self.event_count,
            self.duration,
            self.total_bytes as f64 / 1024. / self.duration.as_secs_f64()
        )
    }
}

fn default_timeout() -> Duration {
    NO_TIMEOUT
}

fn default_min_rate() -> u64 {
    0
}

fn default_max_rate() -> u64 {
    NO_BANDWIDTH_LIMIT
}

impl Default for RelayPolicy {
    fn default() -> Self {
        // by default no restrictions
        Self {
            idle_timeout: NO_TIMEOUT,
            min_rate_bpm: 0,
            max_rate_bps: NO_BANDWIDTH_LIMIT,
        }
    }
}

#[cfg(test)]
mod test_relay_policy {
    extern crate tokio;

    use std::ops::Sub;
    use std::time::{Duration, Instant};

    use tokio_test::io::Builder;
    use tokio_test::io::Mock;

    use crate::relay::{RelayPolicy, RelayShutdownReasons};

    use self::tokio::io::{AsyncReadExt, Error, ErrorKind};

    #[test]
    fn test_enforce_policy_ok() {
        let relay_policy: RelayPolicy = RelayPolicy {
            min_rate_bpm: 1000,
            max_rate_bps: 100_000,
            idle_timeout: Duration::from_secs(1),
        };
        let start = Instant::now().sub(Duration::from_secs(10));
        // 100k in 10 second is OK
        let result = relay_policy.check_transmission_rates(&start, 100_000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_enforce_policy_too_fast() {
        let relay_policy: RelayPolicy = RelayPolicy {
            min_rate_bpm: 1000,
            max_rate_bps: 100_000,
            idle_timeout: Duration::from_secs(1),
        };
        let start = Instant::now().sub(Duration::from_secs(10));
        // 10m in 10 second is way too fast
        let result = relay_policy.check_transmission_rates(&start, 10_000_000);
        assert!(result.is_err());
        assert_eq!(RelayShutdownReasons::TooFast, result.unwrap_err());
    }

    #[test]
    fn test_enforce_policy_too_slow() {
        let relay_policy: RelayPolicy = RelayPolicy {
            min_rate_bpm: 1000,
            max_rate_bps: 100_000,
            idle_timeout: Duration::from_secs(1),
        };
        // 100 bytes in 40 seconds is too slow
        let start = Instant::now().sub(Duration::from_secs(40));
        let result = relay_policy.check_transmission_rates(&start, 100);
        assert!(result.is_err());
        assert_eq!(RelayShutdownReasons::TooSlow, result.unwrap_err());
    }

    #[tokio::test]
    async fn test_timed_operation_ok() {
        let data = b"data on the wire";
        let mut mock_connection: Mock = Builder::new().read(data).build();

        let relay_policy: RelayPolicy = RelayPolicy {
            min_rate_bpm: 1000,
            max_rate_bps: 100_000,
            idle_timeout: Duration::from_secs(5),
        };

        let mut buf = [0; 1024];
        let timed_future = relay_policy
            .timed_operation(mock_connection.read(&mut buf))
            .await;
        assert!(timed_future.is_ok());
        assert_eq!(data, &buf[..timed_future.unwrap().unwrap()])
    }

    #[tokio::test]
    async fn test_timed_operation_failed_io() {
        let mut mock_connection: Mock = Builder::new()
            .read_error(Error::from(ErrorKind::BrokenPipe))
            .build();

        let relay_policy: RelayPolicy = RelayPolicy {
            min_rate_bpm: 1000,
            max_rate_bps: 100_000,
            idle_timeout: Duration::from_secs(5),
        };

        let mut buf = [0; 1024];
        let timed_future = relay_policy
            .timed_operation(mock_connection.read(&mut buf))
            .await;
        assert!(timed_future.is_ok()); // no timeout
        assert!(timed_future.unwrap().is_err()); // but io-error
    }

    #[tokio::test]
    async fn test_timed_operation_timeout() {
        let time_duration = 1;
        let mut mock_connection: Mock = Builder::new()
            .wait(Duration::from_secs(time_duration * 2))
            .build();

        let relay_policy: RelayPolicy = RelayPolicy {
            min_rate_bpm: 1000,
            max_rate_bps: 100_000,
            idle_timeout: Duration::from_secs(time_duration),
        };

        let mut buf = [0; 1024];
        let timed_future = relay_policy
            .timed_operation(mock_connection.read(&mut buf))
            .await;
        assert!(timed_future.is_err());
    }
}

#[cfg(test)]
mod test_relay {
    extern crate tokio;

    use std::time::Duration;

    use tokio::io;
    use tokio_test::io::Builder;
    use tokio_test::io::Mock;

    use crate::relay::{Relay, RelayPolicy, RelayShutdownReasons};

    use self::tokio::io::{Error, ErrorKind};
    use crate::tunnel::TunnelCtx;

    #[tokio::test]
    async fn test_relay_ok() {
        let data = b"data on the wire";
        let reader: Mock = Builder::new().read(data).read(data).read(data).build();
        let writer: Mock = Builder::new().write(data).write(data).write(data).build();

        let relay_policy: RelayPolicy = RelayPolicy {
            min_rate_bpm: 1000,
            max_rate_bps: 100_000,
            idle_timeout: Duration::from_secs(5),
        };

        let relay: Relay = build_relay(relay_policy);

        let (client_recv, _) = io::split(reader);
        let (_, target_send) = io::split(writer);

        let result = relay.relay_data(client_recv, target_send).await;

        assert!(result.is_ok());
        let stats = result.unwrap();

        assert_eq!(
            RelayShutdownReasons::GracefulShutdown,
            stats.shutdown_reason
        );

        assert_eq!(data.len() * 3, stats.total_bytes);
        assert_eq!(3, stats.event_count);
    }

    #[tokio::test]
    async fn test_relay_reader_error() {
        let data = b"data on the wire";
        let reader: Mock = Builder::new()
            .read(data)
            .read_error(Error::from(ErrorKind::BrokenPipe))
            .build();
        let writer: Mock = Builder::new().write(data).build();

        let relay_policy: RelayPolicy = RelayPolicy {
            min_rate_bpm: 1000,
            max_rate_bps: 100_000,
            idle_timeout: Duration::from_secs(5),
        };

        let relay: Relay = build_relay(relay_policy);

        let (client_recv, _) = io::split(reader);
        let (_, target_send) = io::split(writer);

        let result = relay.relay_data(client_recv, target_send).await;

        assert!(result.is_ok());
        let stats = result.unwrap();

        assert_eq!(RelayShutdownReasons::ReadError, stats.shutdown_reason);
    }

    #[tokio::test]
    async fn test_relay_reader_timeout() {
        let data = b"data on the wire";
        let reader: Mock = Builder::new()
            .read(data)
            .wait(Duration::from_secs(3))
            .build();
        let writer: Mock = Builder::new().write(data).build();

        let relay_policy: RelayPolicy = RelayPolicy {
            min_rate_bpm: 1000,
            max_rate_bps: 100_000,
            idle_timeout: Duration::from_secs(1),
        };

        let relay: Relay = build_relay(relay_policy);

        let (client_recv, _) = io::split(reader);
        let (_, target_send) = io::split(writer);

        let result = relay.relay_data(client_recv, target_send).await;

        assert!(result.is_ok());
        let stats = result.unwrap();

        assert_eq!(RelayShutdownReasons::ReaderTimeout, stats.shutdown_reason);
    }

    #[tokio::test]
    async fn test_relay_writer_error() {
        let data = b"data on the wire";
        let reader: Mock = Builder::new().read(data).read(data).build();
        let writer: Mock = Builder::new()
            .write(data)
            .write_error(Error::from(ErrorKind::BrokenPipe))
            .build();

        let relay_policy: RelayPolicy = RelayPolicy {
            min_rate_bpm: 1000,
            max_rate_bps: 100_000,
            idle_timeout: Duration::from_secs(5),
        };

        let relay: Relay = build_relay(relay_policy);

        let (client_recv, _) = io::split(reader);
        let (_, target_send) = io::split(writer);

        let result = relay.relay_data(client_recv, target_send).await;

        assert!(result.is_ok());
        let stats = result.unwrap();

        assert_eq!(RelayShutdownReasons::WriteError, stats.shutdown_reason);
    }

    #[tokio::test]
    async fn test_relay_writer_timeout() {
        let data = b"data on the wire";
        let reader: Mock = Builder::new().read(data).build();
        let writer: Mock = Builder::new().wait(Duration::from_secs(3)).build();

        let relay_policy: RelayPolicy = RelayPolicy {
            min_rate_bpm: 1000,
            max_rate_bps: 100_000,
            idle_timeout: Duration::from_secs(1),
        };

        let relay: Relay = build_relay(relay_policy);

        let (client_recv, _) = io::split(reader);
        let (_, target_send) = io::split(writer);

        let result = relay.relay_data(client_recv, target_send).await;

        assert!(result.is_ok());
        let stats = result.unwrap();

        assert_eq!(RelayShutdownReasons::WriterTimeout, stats.shutdown_reason);
    }

    #[tokio::test]
    async fn test_relay_reader_violates_rate_limits() {
        let data = b"waaaay too much data on the wire";
        let reader: Mock = Builder::new()
            .read(data)
            .wait(Duration::from_secs_f32(5.5))
            .read(data)
            .build();
        let writer: Mock = Builder::new().write(data).write(data).build();

        let relay_policy: RelayPolicy = RelayPolicy {
            min_rate_bpm: 1,
            max_rate_bps: 1,
            idle_timeout: Duration::from_secs(10),
        };

        let relay: Relay = build_relay(relay_policy);

        let (client_recv, _) = io::split(reader);
        let (_, target_send) = io::split(writer);

        let result = relay.relay_data(client_recv, target_send).await;

        assert!(result.is_ok());
        let stats = result.unwrap();

        assert_eq!(RelayShutdownReasons::TooFast, stats.shutdown_reason);

        assert_eq!(data.len() * 2, stats.total_bytes);
        assert_eq!(2, stats.event_count);
    }

    fn build_relay(relay_policy: RelayPolicy) -> Relay {
        let ctx: TunnelCtx = TunnelCtx::new();

        Relay {
            relay_policy: relay_policy,
            tunnel_ctx: ctx,
            name: "Test",
        }
    }
}
