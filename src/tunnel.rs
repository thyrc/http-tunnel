use futures::stream::SplitStream;
use futures::{SinkExt, StreamExt};
use log::{debug, error};
use rand::{thread_rng, Rng};
use std::fmt;
use std::time::Duration;
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tokio_util::codec::{Decoder, Encoder, Framed};

use crate::config;
use crate::relay;
use crate::target;

#[derive(Eq, PartialEq, Debug, Clone, Serialize)]
#[allow(dead_code)]
pub enum ConnectionResult {
    /// Successfully connected to target.  
    Ok,
    /// Successfully connected to target but has a nugget to send after connection establishment.
    OkWithNugget,
    /// Malformed request
    BadRequest,
    /// Target is not allowed
    Forbidden,
    /// Unsupported operation, however valid for the protocol.
    OperationNotAllowed,
    /// The client failed to send a tunnel request timely.
    RequestTimeout,
    /// Cannot connect to target.
    BadGateway,
    /// Connection attempt timed out.
    GatewayTimeout,
    /// Busy. Try again later.
    TooManyRequests,
    /// Any other error. E.g. an abrupt I/O error.
    ServerError,
}

/// A connection tunnel.
///
/// # Parameters
/// * `<H>` - proxy handshake codec for initiating a tunnel.
///    It extracts the request message, which contains the target, and, potentially policies.
///    It also takes care of encoding a response.
/// * `<C>` - a connection from from client.
/// * `<T>` - target connector. It takes result produced by the codec and establishes a connection
///           to a target.
///
/// Once the target connection is established, it relays data until any connection is closed or an
/// error happens.
pub struct Connection<H, C, T> {
    tunnel_request_codec: Option<H>,
    tunnel_ctx: Ctx,
    target_connector: T,
    client: Option<C>,
    tunnel_config: config::Tunnel,
}

pub trait Target {
    type Addr;
    fn target_addr(&self) -> Self::Addr;
    fn has_nugget(&self) -> bool;
    fn nugget(&self) -> &target::Nugget;
}

/// We need to be able to trace events in logs/metrics.
#[derive(Copy, Clone, Default, Serialize)]
pub struct Ctx {
    /// We can easily extend it, if necessary. For now just a random u128.
    id: u128,
}

impl Ctx {
    pub fn new() -> Self {
        Ctx {
            id: thread_rng().gen::<u128>(),
        }
    }
}

/// Statistics
#[allow(clippy::struct_field_names)]
#[derive(Serialize)]
pub struct Stats {
    tunnel_ctx: Ctx,
    result: ConnectionResult,
    upstream_stats: Option<relay::Stats>,
    downstream_stats: Option<relay::Stats>,
}

impl<H, C, T> Connection<H, C, T>
where
    H: Decoder<Error = ConnectionResult> + Encoder<ConnectionResult>,
    H::Item: Target + Sized + fmt::Display + Send + Sync,
    C: AsyncRead + AsyncWrite + Sized + Send + Unpin + 'static,
    T: target::Connector<Target = H::Item>,
{
    pub fn new(
        handshake_codec: H,
        target_connector: T,
        client: C,
        tunnel_config: config::Tunnel,
        tunnel_ctx: Ctx,
    ) -> Self {
        Self {
            tunnel_request_codec: Some(handshake_codec),
            target_connector,
            tunnel_ctx,
            client: Some(client),
            tunnel_config,
        }
    }

    /// Once the client connected we wait for a tunnel establishment handshake.
    /// For instance, an `HTTP/1.1 CONNECT` for HTTP tunnels.
    ///
    /// During handshake we obtained the target target, and if we were able to connect to it,
    /// a message indicating success is sent back to client (or an error response otherwise).
    ///
    /// At that point we start relaying data in full-duplex mode.
    ///
    /// # Note
    /// This method consumes `self` and thus can be called only once.
    pub async fn start(mut self) -> io::Result<Stats> {
        let stream = self.client.take().expect("downstream can be taken once");

        let tunnel_result = self
            .establish_tunnel(stream, self.tunnel_config.clone())
            .await;

        if let Err(error) = tunnel_result {
            return Ok(Stats {
                tunnel_ctx: self.tunnel_ctx,
                result: error,
                upstream_stats: None,
                downstream_stats: None,
            });
        }

        let (client, target) = tunnel_result.unwrap();
        relay_connections(
            client,
            target,
            self.tunnel_ctx,
            self.tunnel_config.client_connection.relay_policy,
            self.tunnel_config.target_connection.relay_policy,
        )
        .await
    }

    async fn establish_tunnel(
        &mut self,
        stream: C,
        configuration: config::Tunnel,
    ) -> Result<(C, T::Stream), ConnectionResult> {
        debug!("Accepting HTTP tunnel request: CTX={}", self.tunnel_ctx);

        let (mut write, mut read) = self
            .tunnel_request_codec
            .take()
            .expect("establish_tunnel can be called only once")
            .framed(stream)
            .split();

        let (response, target) = self.process_tunnel_request(&configuration, &mut read).await;

        let response_sent = match response {
            ConnectionResult::OkWithNugget => true,
            _ => timeout(
                configuration.client_connection.initiation_timeout,
                write.send(response.clone()),
            )
            .await
            .is_ok(),
        };

        if response_sent {
            match target {
                None => Err(response),
                Some(u) => {
                    // lets take the original stream to either relay data, or to drop it on error
                    let framed = write.reunite(read).expect("Uniting previously split parts");
                    let original_stream = framed.into_inner();

                    Ok((original_stream, u))
                }
            }
        } else {
            Err(ConnectionResult::RequestTimeout)
        }
    }

    async fn process_tunnel_request(
        &mut self,
        configuration: &config::Tunnel,
        read: &mut SplitStream<Framed<C, H>>,
    ) -> (ConnectionResult, Option<<T as target::Connector>::Stream>) {
        let connect_request = timeout(
            configuration.client_connection.initiation_timeout,
            read.next(),
        )
        .await;

        let response;
        let mut target = None;

        if connect_request.is_err() {
            error!("Client established connection but failed to send a HTTP request within {:?}, CTX={}",
                   configuration.client_connection.initiation_timeout,
                   self.tunnel_ctx);
            response = ConnectionResult::RequestTimeout;
        } else if let Some(event) = connect_request.unwrap() {
            match event {
                Ok(decoded_target) => {
                    let has_nugget = decoded_target.has_nugget();
                    response = match self
                        .connect_to_target(
                            decoded_target,
                            configuration.target_connection.connect_timeout,
                        )
                        .await
                    {
                        Ok(t) => {
                            target = Some(t);
                            if has_nugget {
                                ConnectionResult::OkWithNugget
                            } else {
                                ConnectionResult::Ok
                            }
                        }
                        Err(e) => e,
                    }
                }
                Err(e) => {
                    response = e;
                }
            }
        } else {
            response = ConnectionResult::BadRequest;
        }

        (response, target)
    }

    async fn connect_to_target(
        &mut self,
        target: T::Target,
        connect_timeout: Duration,
    ) -> Result<T::Stream, ConnectionResult> {
        debug!(
            "Establishing HTTP tunnel target connection: {}, CTX={}",
            target, self.tunnel_ctx,
        );

        let timed_connection_result =
            timeout(connect_timeout, self.target_connector.connect(&target)).await;

        if timed_connection_result.is_err() {
            Err(ConnectionResult::GatewayTimeout)
        } else {
            match timed_connection_result.unwrap() {
                Ok(tcp_stream) => Ok(tcp_stream),
                Err(e) => Err(ConnectionResult::from(e)),
            }
        }
    }
}

pub async fn relay_connections<
    D: AsyncRead + AsyncWrite + Sized + Send + Unpin + 'static,
    U: AsyncRead + AsyncWrite + Sized + Send + 'static,
>(
    client: D,
    target: U,
    ctx: Ctx,
    downstream_relay_policy: relay::Policy,
    upstream_relay_policy: relay::Policy,
) -> io::Result<Stats> {
    let (client_recv, client_send) = io::split(client);
    let (target_recv, target_send) = io::split(target);

    let downstream_relay: relay::Relay = relay::Relay {
        name: "Downstream",
        tunnel_ctx: ctx,
        relay_policy: downstream_relay_policy,
    };

    let upstream_relay: relay::Relay = relay::Relay {
        name: "Upstream",
        tunnel_ctx: ctx,
        relay_policy: upstream_relay_policy,
    };

    let upstream_task = tokio::spawn(async move {
        Box::pin(downstream_relay.relay_data(client_recv, target_send)).await
    });

    let downstream_task =
        tokio::spawn(
            async move { Box::pin(upstream_relay.relay_data(target_recv, client_send)).await },
        );

    let downstream_stats = downstream_task.await??;
    let upstream_stats = upstream_task.await??;

    Ok(Stats {
        tunnel_ctx: ctx,
        result: ConnectionResult::Ok,
        upstream_stats: Some(upstream_stats),
        downstream_stats: Some(downstream_stats),
    })
}

impl fmt::Display for Ctx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

#[cfg(test)]
mod test {
    extern crate tokio;

    use self::tokio::io::{AsyncWriteExt, Error, ErrorKind};
    use std::time::Duration;
    use tokio::io;
    use tokio_test::io::Builder;
    use tokio_test::io::Mock;

    use crate::codec;
    use crate::config::{self, Regex};
    use crate::relay;
    use crate::target;
    use crate::tunnel::{self, Target};

    #[tokio::test]
    async fn test_tunnel_ok() {
        let handshake_request = b"CONNECT foo.bar:80 HTTP/1.1\r\n\r\n";
        let handshake_response = b"HTTP/1.1 200 OK\r\n\r\n";
        let tunneled_request = b"0: Some arbibrary request";
        let tunneled_response = b"1: Some arbibrary response";

        let client: Mock = Builder::new()
            .read(handshake_request)
            .write(handshake_response)
            .read(tunneled_request)
            .write(tunneled_response)
            .build();

        let target: Mock = Builder::new()
            .write(tunneled_request)
            .read(tunneled_response)
            .build();

        let ctx = tunnel::Ctx::new();

        let codec: codec::HttpTunnel = codec::HttpTunnel {
            tunnel_ctx: ctx,
            enabled_targets: Some(Regex::new(r"foo\.bar:80").unwrap()),
        };

        let connector = MockTargetConnector {
            target: "foo.bar:80".to_string(),
            mock: Some(target),
            delay: None,
            error: None,
        };

        let default_timeout = Duration::from_secs(5);
        let config = build_config(default_timeout);

        let result = tunnel::Connection::new(codec, connector, client, config, ctx)
            .start()
            .await;

        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.result, tunnel::ConnectionResult::Ok);
        assert!(stats.upstream_stats.is_some());
        assert!(stats.downstream_stats.is_some());

        let upstream_stats = stats.upstream_stats.unwrap();
        let downstream_stats = stats.downstream_stats.unwrap();

        assert_eq!(upstream_stats.total_bytes, tunneled_request.len());
        assert_eq!(downstream_stats.total_bytes, tunneled_response.len());
    }

    #[tokio::test]
    #[cfg(feature = "plain_text")]
    async fn test_tunnel_plain_text_ok() {
        let handshake_request =
            b"GET https://foo.bar/index.html HTTP/1.1\r\nHost: foo.bar:443\r\n\r\n";
        let tunneled_response = b"HTTP/1.1 200 OK\r\n\r\n";

        let client: Mock = Builder::new()
            .read(handshake_request)
            .write(tunneled_response)
            .build();

        let target: Mock = Builder::new()
            .write(handshake_request)
            .read(tunneled_response)
            .build();

        let ctx = tunnel::Ctx::new();

        let codec: codec::HttpTunnel = codec::HttpTunnel {
            tunnel_ctx: ctx,
            enabled_targets: Some(Regex::new(r"foo\.bar:443").unwrap()),
        };

        let connector = MockTargetConnector {
            target: "foo.bar:443".to_string(),
            mock: Some(target),
            delay: None,
            error: None,
        };

        let default_timeout = Duration::from_secs(5);
        let config = build_config(default_timeout);

        let result = tunnel::Connection::new(codec, connector, client, config, ctx)
            .start()
            .await;

        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.result, tunnel::ConnectionResult::Ok);
        assert!(stats.upstream_stats.is_some());
        assert!(stats.downstream_stats.is_some());

        let upstream_stats = stats.upstream_stats.unwrap();
        let downstream_stats = stats.downstream_stats.unwrap();

        assert_eq!(upstream_stats.total_bytes, 0);
        assert_eq!(downstream_stats.total_bytes, tunneled_response.len());
    }

    #[tokio::test]
    async fn test_tunnel_request_timeout() {
        let handshake_response = b"HTTP/1.1 408 TIMEOUT\r\n\r\n";

        let client: Mock = Builder::new()
            .wait(Duration::from_secs(2))
            .write(handshake_response)
            .build();

        let ctx = tunnel::Ctx::new();

        let codec: codec::HttpTunnel = codec::HttpTunnel {
            tunnel_ctx: ctx,
            enabled_targets: Some(Regex::new(r"foo\.bar:80").unwrap()),
        };

        let connector = MockTargetConnector {
            target: "foo.bar:80".to_string(),
            mock: None,
            delay: None,
            error: None,
        };

        let default_timeout = Duration::from_secs(1);
        let config = build_config(default_timeout);

        let result = tunnel::Connection::new(codec, connector, client, config, ctx)
            .start()
            .await;

        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.result, tunnel::ConnectionResult::RequestTimeout);
        assert!(stats.upstream_stats.is_none());
        assert!(stats.downstream_stats.is_none());
    }

    #[tokio::test]
    async fn test_tunnel_response_timeout() {
        let handshake_request = b"CONNECT foo.bar:80 HTTP/1.1\r\n\r\n";

        let client: Mock = Builder::new()
            .read(handshake_request)
            .wait(Duration::from_secs(2))
            .build();

        let target: Mock = Builder::new().build();

        let ctx = tunnel::Ctx::new();

        let codec: codec::HttpTunnel = codec::HttpTunnel {
            tunnel_ctx: ctx,
            enabled_targets: Some(Regex::new(r"foo\.bar:80").unwrap()),
        };

        let connector = MockTargetConnector {
            target: "foo.bar:80".to_string(),
            mock: Some(target),
            delay: None,
            error: None,
        };

        let default_timeout = Duration::from_secs(1);
        let config = build_config(default_timeout);

        let result = tunnel::Connection::new(codec, connector, client, config, ctx)
            .start()
            .await;

        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.result, tunnel::ConnectionResult::RequestTimeout);
        assert!(stats.upstream_stats.is_none());
        assert!(stats.downstream_stats.is_none());
    }

    #[tokio::test]
    async fn test_tunnel_upstream_timeout() {
        let handshake_request = b"CONNECT foo.bar:80 HTTP/1.1\r\n\r\n";
        let handshake_response = b"HTTP/1.1 504 GATEWAY_TIMEOUT\r\n\r\n";

        let client: Mock = Builder::new()
            .read(handshake_request)
            .write(handshake_response)
            .build();

        let target: Mock = Builder::new().build();

        let ctx = tunnel::Ctx::new();

        let codec: codec::HttpTunnel = codec::HttpTunnel {
            tunnel_ctx: ctx,
            enabled_targets: Some(Regex::new(r"foo\.bar:80").unwrap()),
        };

        let connector = MockTargetConnector {
            target: "foo.bar:80".to_string(),
            mock: Some(target),
            delay: Some(Duration::from_secs(3)),
            error: None,
        };

        let default_timeout = Duration::from_secs(1);
        let config = build_config(default_timeout);

        let result = tunnel::Connection::new(codec, connector, client, config, ctx)
            .start()
            .await;

        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.result, tunnel::ConnectionResult::GatewayTimeout);
        assert!(stats.upstream_stats.is_none());
        assert!(stats.downstream_stats.is_none());
    }

    #[tokio::test]
    async fn test_tunnel_bad_target() {
        let handshake_request = b"CONNECT disallowed.com:80 HTTP/1.1\r\n\r\n";
        let handshake_response = b"HTTP/1.1 403 FORBIDDEN\r\n\r\n";

        let client: Mock = Builder::new()
            .read(handshake_request)
            .write(handshake_response)
            .build();

        let target: Mock = Builder::new().build();

        let ctx = tunnel::Ctx::new();

        let codec: codec::HttpTunnel = codec::HttpTunnel {
            tunnel_ctx: ctx,
            enabled_targets: Some(Regex::new(r"foo\.bar:80").unwrap()),
        };

        let connector = MockTargetConnector {
            target: "foo.bar:80".to_string(),
            mock: Some(target),
            delay: None,
            error: None,
        };

        let default_timeout = Duration::from_secs(1);
        let config = build_config(default_timeout);

        let result = tunnel::Connection::new(codec, connector, client, config, ctx)
            .start()
            .await;

        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.result, tunnel::ConnectionResult::Forbidden);
        assert!(stats.upstream_stats.is_none());
        assert!(stats.downstream_stats.is_none());
    }

    #[tokio::test]
    async fn test_tunnel_bad_gateway() {
        let handshake_request = b"CONNECT foo.bar:80 HTTP/1.1\r\n\r\n";
        let handshake_response = b"HTTP/1.1 502 BAD_GATEWAY\r\n\r\n";

        let client: Mock = Builder::new()
            .read(handshake_request)
            .write(handshake_response)
            .build();

        let _target: Mock = Builder::new().build();

        let ctx = tunnel::Ctx::new();

        let codec: codec::HttpTunnel = codec::HttpTunnel {
            tunnel_ctx: ctx,
            enabled_targets: Some(Regex::new(r"foo\.bar:80").unwrap()),
        };

        let connector = MockTargetConnector {
            target: "foo.bar:80".to_string(),
            mock: None,
            delay: None,
            error: Some(ErrorKind::BrokenPipe),
        };

        let default_timeout = Duration::from_secs(1);
        let config = build_config(default_timeout);

        let result = tunnel::Connection::new(codec, connector, client, config, ctx)
            .start()
            .await;

        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.result, tunnel::ConnectionResult::BadGateway);
        assert!(stats.upstream_stats.is_none());
        assert!(stats.downstream_stats.is_none());
    }

    #[tokio::test]
    async fn test_tunnel_bad_request() {
        let handshake_request = b"CONNECT\tfoo.bar:80\tHTTP/1.1\r\n\r\n";
        let handshake_response = b"HTTP/1.1 400 BAD_REQUEST\r\n\r\n";

        let client: Mock = Builder::new()
            .read(handshake_request)
            .write(handshake_response)
            .build();

        let _target: Mock = Builder::new().build();

        let ctx = tunnel::Ctx::new();

        let codec: codec::HttpTunnel = codec::HttpTunnel {
            tunnel_ctx: ctx,
            enabled_targets: Some(Regex::new(r"foo\.bar:80").unwrap()),
        };

        let connector = MockTargetConnector {
            target: "foo.bar:80".to_string(),
            mock: None,
            delay: None,
            error: Some(ErrorKind::BrokenPipe),
        };

        let default_timeout = Duration::from_secs(1);
        let config = build_config(default_timeout);

        let result = tunnel::Connection::new(codec, connector, client, config, ctx)
            .start()
            .await;

        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.result, tunnel::ConnectionResult::BadRequest);
        assert!(stats.upstream_stats.is_none());
        assert!(stats.downstream_stats.is_none());
    }

    #[tokio::test]
    #[cfg(not(feature = "plain_text"))]
    async fn test_tunnel_not_allowed() {
        let handshake_request = b"GET foo.bar:80 HTTP/1.1\r\n\r\n";
        let handshake_response = b"HTTP/1.1 405 NOT_ALLOWED\r\n\r\n";

        let client: Mock = Builder::new()
            .read(handshake_request)
            .write(handshake_response)
            .build();

        let _target: Mock = Builder::new().build();

        let ctx = tunnel::Ctx::new();

        let codec: codec::HttpTunnel = codec::HttpTunnel {
            tunnel_ctx: ctx,
            enabled_targets: Some(Regex::new(r"foo\.bar:80").unwrap()),
        };

        let connector = MockTargetConnector {
            target: "foo.bar:80".to_string(),
            mock: None,
            delay: None,
            error: Some(ErrorKind::BrokenPipe),
        };

        let default_timeout = Duration::from_secs(1);
        let config = build_config(default_timeout);

        let result = tunnel::Connection::new(codec, connector, client, config, ctx)
            .start()
            .await;

        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.result, tunnel::ConnectionResult::OperationNotAllowed);
        assert!(stats.upstream_stats.is_none());
        assert!(stats.downstream_stats.is_none());
    }

    fn build_config(default_timeout: Duration) -> config::Tunnel {
        config::Tunnel {
            client_connection: config::ClientConnection {
                initiation_timeout: default_timeout,
                relay_policy: relay::Policy {
                    idle_timeout: default_timeout,
                    min_rate_bpm: 0,
                    max_rate_bps: 120410065,
                },
            },
            target_connection: config::TargetConnection {
                dns_cache_ttl: default_timeout,
                ipv4_only: false,
                allowed_targets: Some(Regex::new(r"foo\.bar:80").unwrap()),
                allowed: vec!["foo.bar:80".to_string()],
                connect_timeout: default_timeout,
                relay_policy: relay::Policy {
                    idle_timeout: default_timeout,
                    min_rate_bpm: 0,
                    max_rate_bps: 170310180,
                },
            },
        }
    }

    struct MockTargetConnector {
        target: String,
        mock: Option<Mock>,
        delay: Option<Duration>,
        error: Option<ErrorKind>,
    }

    impl target::Connector for MockTargetConnector {
        type Target = codec::HttpTunnelTarget;
        type Stream = Mock;

        async fn connect(&mut self, target: &Self::Target) -> io::Result<Self::Stream> {
            let target_addr = &target.target_addr();
            assert_eq!(&self.target, target_addr);

            if let Some(d) = self.delay {
                tokio::time::sleep(d).await;
            }

            match self.error {
                None => {
                    let mut stream = self.mock.take().unwrap();
                    if target.has_nugget() {
                        stream.write_all(&target.nugget().data()).await?;
                    }
                    Ok(stream)
                }
                Some(e) => Err(Error::from(e)),
            }
        }
    }
}
