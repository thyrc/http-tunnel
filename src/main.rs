#[macro_use]
extern crate serde_derive;

use log::{debug, error, info};
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

use crate::logging::{init_logger, report_tunnel_metrics};
use crate::target::{Connector, SimpleCachingDnsResolver, SimpleTcpConnector};

mod codec;
mod config;
mod logging;
mod relay;
mod target;
mod tunnel;

type DnsResolver = SimpleCachingDnsResolver;

#[tokio::main]
async fn main() -> io::Result<()> {
    let proxy_configuration = config::Proxy::from_command_line();

    init_logger(
        &proxy_configuration.log_file,
        proxy_configuration.verbosity,
        proxy_configuration.quiet,
    )?;

    debug!("Starting with configuration: {:#?}", proxy_configuration);
    info!("Starting listener on: {}", proxy_configuration.bind_address);

    let dns_resolver = SimpleCachingDnsResolver::new(
        proxy_configuration
            .tunnel_config
            .target_connection
            .dns_cache_ttl,
        proxy_configuration
            .tunnel_config
            .target_connection
            .ipv4_only,
    );

    match &proxy_configuration.mode {
        config::ProxyMode::Http => {
            serve_plain_text(proxy_configuration, dns_resolver).await?;
        }
        config::ProxyMode::Tcp(d) => {
            let destination = d.clone();
            serve_tcp(proxy_configuration, dns_resolver, destination).await?;
        }
    };

    info!("Proxy stopped");

    Ok(())
}

async fn start_listening_tcp(config: &config::Proxy) -> Result<TcpListener, std::io::Error> {
    let bind_address = &config.bind_address;

    match TcpListener::bind(bind_address).await {
        Ok(s) => {
            info!("Serving requests on: {bind_address}");
            Ok(s)
        }
        Err(e) => {
            error!("Error binding TCP socket {bind_address}: {e}");
            Err(e)
        }
    }
}

async fn serve_plain_text(config: config::Proxy, dns_resolver: DnsResolver) -> io::Result<()> {
    let listener = start_listening_tcp(&config).await?;
    loop {
        // Asynchronously wait for an inbound socket.
        let socket = listener.accept().await;

        let dns_resolver_ref = dns_resolver.clone();

        match socket {
            Ok((stream, _)) => {
                stream.nodelay().unwrap_or_default();
                let config = config.clone();
                // handle accepted connections asynchronously
                tokio::spawn(async move { tunnel_stream(&config, stream, dns_resolver_ref).await });
            }
            Err(e) => error!("Failed TCP handshake {e}"),
        }
    }
}

async fn serve_tcp(
    config: config::Proxy,
    dns_resolver: DnsResolver,
    destination: String,
) -> io::Result<()> {
    let listener = start_listening_tcp(&config).await?;

    loop {
        // Asynchronously wait for an inbound socket.
        let socket = listener.accept().await;

        let dns_resolver_ref = dns_resolver.clone();
        let destination_copy = destination.clone();
        let config_copy = config.clone();

        match socket {
            Ok((stream, _)) => {
                let config = config.clone();
                stream.nodelay().unwrap_or_default();
                // handle accepted connections asynchronously
                tokio::spawn(async move {
                    let ctx = tunnel::Ctx::new();

                    let mut connector: SimpleTcpConnector<codec::HttpTunnelTarget, DnsResolver> =
                        SimpleTcpConnector::new(
                            dns_resolver_ref,
                            config.tunnel_config.target_connection.connect_timeout,
                            ctx,
                        );

                    match connector
                        .connect(&codec::HttpTunnelTarget {
                            target: destination_copy,
                            nugget: None,
                        })
                        .await
                    {
                        Ok(destination) => {
                            let stats = tunnel::relay_connections(
                                stream,
                                destination,
                                ctx,
                                config_copy.tunnel_config.client_connection.relay_policy,
                                config_copy.tunnel_config.target_connection.relay_policy,
                            )
                            .await;

                            if config.metrics_enabled {
                                report_tunnel_metrics(ctx, stats);
                            }
                        }
                        Err(e) => error!("Failed to establish TCP upstream connection {:?}", e),
                    }
                });
            }
            Err(e) => error!("Failed TCP handshake {e}"),
        }
    }
}

/// Tunnel via a client connection.
/// This method constructs `codec::HttpTunnelCodec` and `SimpleTcpConnector`
/// to create an `HTTP` tunnel.
async fn tunnel_stream<C: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    config: &config::Proxy,
    client: C,
    dns_resolver: DnsResolver,
) -> io::Result<()> {
    let ctx = tunnel::Ctx::new();

    let enabled_targets = config
        .tunnel_config
        .target_connection
        .allowed_targets
        .clone();

    // here it can be any codec.
    let codec: codec::HttpTunnel = codec::HttpTunnel {
        tunnel_ctx: ctx,
        enabled_targets,
    };

    // any `TargetConnector` would do.
    let connector: SimpleTcpConnector<codec::HttpTunnelTarget, DnsResolver> =
        SimpleTcpConnector::new(
            dns_resolver,
            config.tunnel_config.target_connection.connect_timeout,
            ctx,
        );

    let stats =
        tunnel::Connection::new(codec, connector, client, config.tunnel_config.clone(), ctx)
            .start()
            .await;

    if config.metrics_enabled {
        report_tunnel_metrics(ctx, stats);
    }

    Ok(())
}
