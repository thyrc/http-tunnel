use log::{debug, error, info, warn};
use rand::prelude::thread_rng;
use rand::Rng;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, Error, ErrorKind};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tokio::time::Duration;

use crate::tunnel::{self, Target};

pub trait Connector {
    type Target: Target + Send + Sync + Sized;
    type Stream: AsyncRead + AsyncWrite + Send + Sized + 'static;

    async fn connect(&mut self, target: &Self::Target) -> io::Result<Self::Stream>;
}

pub trait DnsResolver {
    async fn resolve(&mut self, target: &str) -> io::Result<SocketAddr>;
}

#[derive(Clone)]
pub struct SimpleTcpConnector<D, R: DnsResolver> {
    connect_timeout: Duration,
    tunnel_ctx: tunnel::Ctx,
    dns_resolver: R,
    _phantom_target: PhantomData<D>,
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct Nugget {
    data: Arc<Vec<u8>>,
}

type CachedSocketAddrs = (Vec<SocketAddr>, u128);

/// Caching DNS resolution results to minimize DNS lookups.
/// The cache implementation is relaxed, it allows concurrent lookups of the same key,
/// without any guarantees which result is going to be cached.
///
/// Given it's used for DNS lookups this trade-off seems to be reasonable.
#[derive(Clone)]
pub struct SimpleCachingDnsResolver {
    // mostly reads, occasional writes
    cache: Arc<RwLock<HashMap<String, CachedSocketAddrs>>>,
    start_time: Instant,
    ttl: Duration,
    ipv4: bool,
}

impl<D, R> Connector for SimpleTcpConnector<D, R>
where
    D: Target<Addr = String> + Send + Sync + Sized,
    R: DnsResolver + Send + Sync + 'static,
{
    type Target = D;
    type Stream = TcpStream;

    async fn connect(&mut self, target: &Self::Target) -> io::Result<Self::Stream> {
        let target_addr = &target.target_addr();

        let addr = self.dns_resolver.resolve(target_addr).await?;

        if let Ok(tcp_stream) = timeout(self.connect_timeout, TcpStream::connect(addr)).await {
            let mut stream = tcp_stream?;
            stream.nodelay()?;
            if target.has_nugget() {
                warn!(
                    "Establishing plain text connection to target: {}",
                    &target_addr
                );
                if let Ok(written_successfully) = timeout(
                    self.connect_timeout,
                    stream.write_all(&target.nugget().data()),
                )
                .await
                {
                    written_successfully?;
                } else {
                    error!(
                        "Timeout sending nugget to {}, {}, CTX={}",
                        addr, target_addr, self.tunnel_ctx
                    );
                    return Err(Error::from(ErrorKind::TimedOut));
                }
            }
            Ok(stream)
        } else {
            error!(
                "Timeout connecting to {}, {}, CTX={}",
                addr, target_addr, self.tunnel_ctx
            );
            Err(Error::from(ErrorKind::TimedOut))
        }
    }
}

impl DnsResolver for SimpleCachingDnsResolver {
    async fn resolve(&mut self, target: &str) -> io::Result<SocketAddr> {
        match self.try_find(target).await {
            Some(a) => Ok(a),
            _ => Ok(self.resolve_and_cache(target).await?),
        }
    }
}

impl<D, R> SimpleTcpConnector<D, R>
where
    R: DnsResolver,
{
    pub fn new(dns_resolver: R, connect_timeout: Duration, tunnel_ctx: tunnel::Ctx) -> Self {
        Self {
            dns_resolver,
            connect_timeout,
            tunnel_ctx,
            _phantom_target: std::marker::PhantomData,
        }
    }
}

impl SimpleCachingDnsResolver {
    pub fn new(ttl: Duration, ipv4: bool) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl,
            start_time: Instant::now(),
            ipv4,
        }
    }

    fn pick(addrs: &[SocketAddr]) -> SocketAddr {
        addrs[thread_rng().gen::<usize>() % addrs.len()]
    }

    async fn try_find(&mut self, target: &str) -> Option<SocketAddr> {
        let map = self.cache.read().await;

        let addr = match map.get(target) {
            None => None,
            Some((cached, expiration)) => {
                // expiration with jitter to avoid waves of expirations
                let expiration_jitter = *expiration + thread_rng().gen_range(0..5_000);
                if Instant::now().duration_since(self.start_time).as_millis() < expiration_jitter {
                    Some(SimpleCachingDnsResolver::pick(cached))
                } else {
                    None
                }
            }
        };

        addr
    }

    async fn resolve_and_cache(&mut self, target: &str) -> io::Result<SocketAddr> {
        let resolved = SimpleCachingDnsResolver::resolve(target, self.ipv4).await?;

        let mut map = self.cache.write().await;
        map.insert(
            target.to_string(),
            (
                resolved.clone(),
                Instant::now().duration_since(self.start_time).as_millis() + self.ttl.as_millis(),
            ),
        );

        Ok(SimpleCachingDnsResolver::pick(&resolved))
    }

    async fn resolve(target: &str, ipv4: bool) -> io::Result<Vec<SocketAddr>> {
        debug!("Resolving DNS {}", target);
        let mut resolved: Vec<SocketAddr> = tokio::net::lookup_host(target).await?.collect();
        if ipv4 {
            resolved.retain(std::net::SocketAddr::is_ipv4);
        }
        info!("Resolved DNS {} to {:?}", target, resolved);

        if resolved.is_empty() {
            error!("Cannot resolve DNS {}", target,);
            return Err(Error::from(ErrorKind::AddrNotAvailable));
        }

        Ok(resolved)
    }
}

impl Nugget {
    pub fn new<T: Into<Vec<u8>>>(v: T) -> Self {
        Self {
            data: Arc::new(v.into()),
        }
    }

    pub fn data(&self) -> Arc<Vec<u8>> {
        self.data.clone()
    }
}
