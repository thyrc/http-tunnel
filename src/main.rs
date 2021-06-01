#[macro_use]
extern crate derive_builder;
#[macro_use]
extern crate serde_derive;

use log::{debug, error, info};
use rand::{thread_rng, Rng};
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

use crate::codec::{HttpTunnelCodec, HttpTunnelCodecBuilder, HttpTunnelTarget};
use crate::config::{ProxyConfiguration, ProxyMode};
use crate::logging::{init_logger, report_tunnel_metrics};
use crate::target::{SimpleCachingDnsResolver, SimpleTcpConnector};
use crate::tunnel::{ConnectionTunnel, TunnelCtxBuilder};

mod codec;
mod config;
mod logging;
mod relay;
mod target;
mod tunnel;

type DnsResolver = SimpleCachingDnsResolver;

#[tokio::main]
async fn main() -> io::Result<()> {
    let proxy_configuration = ProxyConfiguration::from_command_line().map_err(|e| {
        println!("Failed to process parameters. See ./log/atp-tunnel.log for details");
        e
    })?;

    init_logger();

    debug!("Starting with configuration: {:#?}", proxy_configuration);
    info!("Starting listener on: {}", proxy_configuration.bind_address);

    let mut tcp_listener = TcpListener::bind(&proxy_configuration.bind_address)
        .await
        .map_err(|e| {
            error!(
                "Error binding address {}: {}",
                &proxy_configuration.bind_address, e
            );
            e
        })?;

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
        ProxyMode::Http => {
            serve_plain_text(proxy_configuration, &mut tcp_listener, dns_resolver).await?;
        }
    };

    info!("Proxy stopped");

    Ok(())
}

async fn serve_plain_text(
    config: ProxyConfiguration,
    listener: &mut TcpListener,
    dns_resolver: DnsResolver,
) -> io::Result<()> {
    info!("Serving requests on: {}", config.bind_address);
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
            Err(e) => error!("Failed TCP handshake {}", e),
        }
    }
}

/// Tunnel via a client connection.
/// This method constructs `HttpTunnelCodec` and `SimpleTcpConnector`
/// to create an `HTTP` tunnel.
async fn tunnel_stream<C: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    config: &ProxyConfiguration,
    client: C,
    dns_resolver: DnsResolver,
) -> io::Result<()> {
    let ctx = TunnelCtxBuilder::default()
        .id(thread_rng().gen::<u128>())
        .build()
        .expect("TunnelCtxBuilder failed");

    let enabled_targets = config
        .tunnel_config
        .target_connection
        .allowed_targets
        .as_ref()
        .cloned();

    // here it can be any codec.
    let codec: HttpTunnelCodec = HttpTunnelCodecBuilder::default()
        .tunnel_ctx(ctx)
        .enabled_targets(enabled_targets)
        .build()
        .expect("HttpTunnelCodecBuilder failed");

    // any `TargetConnector` would do.
    let connector: SimpleTcpConnector<HttpTunnelTarget, DnsResolver> = SimpleTcpConnector::new(
        dns_resolver,
        config.tunnel_config.target_connection.connect_timeout,
        ctx,
    );

    let stats = ConnectionTunnel::new(codec, connector, client, config.tunnel_config.clone(), ctx)
        .start()
        .await;

    report_tunnel_metrics(ctx, stats);

    Ok(())
}
