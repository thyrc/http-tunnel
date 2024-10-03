use bytes::BytesMut;
use core::fmt;
use log::{debug, warn};
use std::fmt::Write;
use std::str::Split;
use tokio::io::{Error, ErrorKind};
use tokio_util::codec::{Decoder, Encoder};

use crate::config;
use crate::target;
use crate::tunnel;

const REQUEST_END_MARKER: &[u8] = b"\r\n\r\n";
/// A reasonable value to limit possible header size.
const MAX_HTTP_REQUEST_SIZE: usize = 16384;

/// HTTP/1.1 request representation
/// Supports only `CONNECT` method
struct HttpConnectRequest {
    uri: String,
    nugget: Option<target::Nugget>,
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct HttpTunnelTarget {
    pub target: String,
    pub nugget: Option<target::Nugget>,
    // easily can be extended with something like
    // policies: Vec<TunnelPolicy>
}

/// Codec to extract `HTTP/1.1 CONNECT` requests and build a corresponding `HTTP` response.
#[derive(Clone)]
pub struct HttpTunnel {
    pub tunnel_ctx: tunnel::Ctx,
    pub enabled_targets: Option<config::Regex>,
}

impl Decoder for HttpTunnel {
    type Item = HttpTunnelTarget;
    type Error = tunnel::ConnectionResult;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if !got_http_request(src) {
            return Ok(None);
        }

        match HttpConnectRequest::parse(src) {
            Ok(parsed_request) => match &self.enabled_targets {
                Some(regex) if !regex.is_match(&parsed_request.uri) => {
                    warn!(
                        "Target `{}` is not allowed. Allowed: `{}`, CTX={}",
                        parsed_request.uri, regex, self.tunnel_ctx
                    );
                    Err(tunnel::ConnectionResult::Forbidden)
                }
                _ => Ok(Some(HttpTunnelTarget {
                    target: parsed_request.uri,
                    nugget: parsed_request.nugget,
                })),
            },
            Err(e) => Err(e),
        }
    }
}

impl Encoder<tunnel::ConnectionResult> for HttpTunnel {
    type Error = std::io::Error;

    fn encode(
        &mut self,
        item: tunnel::ConnectionResult,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        let (code, message) = match item {
            tunnel::ConnectionResult::Ok => (200, "OK"),
            tunnel::ConnectionResult::OkWithNugget => {
                // do nothing, upstream should respond instead
                return Ok(());
            }
            tunnel::ConnectionResult::BadRequest => (400, "BAD_REQUEST"),
            tunnel::ConnectionResult::Forbidden => (403, "FORBIDDEN"),
            tunnel::ConnectionResult::OperationNotAllowed => (405, "NOT_ALLOWED"),
            tunnel::ConnectionResult::RequestTimeout => (408, "TIMEOUT"),
            tunnel::ConnectionResult::TooManyRequests => (429, "TOO_MANY_REQUESTS"),
            tunnel::ConnectionResult::ServerError => (500, "SERVER_ERROR"),
            tunnel::ConnectionResult::BadGateway => (502, "BAD_GATEWAY"),
            tunnel::ConnectionResult::GatewayTimeout => (504, "GATEWAY_TIMEOUT"),
        };

        #[allow(clippy::cast_sign_loss)]
        dst.write_fmt(format_args!("HTTP/1.1 {} {message}\r\n\r\n", code as u32))
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::Other))
    }
}

impl tunnel::Target for HttpTunnelTarget {
    type Addr = String;

    fn target_addr(&self) -> Self::Addr {
        self.target.clone()
    }

    fn has_nugget(&self) -> bool {
        self.nugget.is_some()
    }

    fn nugget(&self) -> &target::Nugget {
        self.nugget
            .as_ref()
            .expect("Cannot use this method without checking `has_nugget`")
    }
}

impl fmt::Display for HttpTunnelTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.target)
    }
}

#[cfg(not(feature = "plain_text"))]
fn got_http_request(buffer: &BytesMut) -> bool {
    buffer.len() >= MAX_HTTP_REQUEST_SIZE || buffer.ends_with(REQUEST_END_MARKER)
}

#[cfg(feature = "plain_text")]
fn got_http_request(buffer: &BytesMut) -> bool {
    buffer.len() >= MAX_HTTP_REQUEST_SIZE
        || buffer
            .windows(REQUEST_END_MARKER.len())
            .any(|w| w == REQUEST_END_MARKER)
}

impl From<Error> for tunnel::ConnectionResult {
    fn from(e: Error) -> Self {
        match e.kind() {
            ErrorKind::TimedOut => tunnel::ConnectionResult::GatewayTimeout,
            _ => tunnel::ConnectionResult::BadGateway,
        }
    }
}

/// Basic HTTP Request parser which only purpose is to parse `CONNECT` requests.
impl HttpConnectRequest {
    pub fn parse(http_request: &[u8]) -> Result<Self, tunnel::ConnectionResult> {
        HttpConnectRequest::precondition_size(http_request)?;
        HttpConnectRequest::precondition_legal_characters(http_request)?;

        let http_request_as_string =
            String::from_utf8(http_request.to_vec()).expect("Contains only ASCII");

        let mut lines = http_request_as_string.split("\r\n");

        let request_line = HttpConnectRequest::parse_request_line(
            lines
                .next()
                .expect("At least a single line is present at this point"),
        )?;

        let has_nugget = request_line.3;

        if has_nugget {
            let uri = HttpConnectRequest::extract_destination_host(&mut lines, request_line.1)
                .unwrap_or_else(|| request_line.1.to_string());
            Ok(Self {
                uri,
                nugget: Some(target::Nugget::new(http_request)),
            })
        } else {
            Ok(Self {
                uri: request_line.1.to_string(),
                nugget: None,
            })
        }
    }

    fn extract_destination_host(lines: &mut Split<&str>, endpoint: &str) -> Option<String> {
        const HOST_HEADER: &str = "host:";

        lines
            .find(|line| line.to_ascii_lowercase().starts_with(HOST_HEADER))
            .map(|line| line[HOST_HEADER.len()..].trim())
            .map(|host| {
                let mut host = String::from(host);
                if host.rfind(':').is_none() {
                    let default_port = if endpoint.to_ascii_lowercase().starts_with("https://") {
                        ":443"
                    } else {
                        ":80"
                    };
                    host.push_str(default_port);
                }
                host
            })
    }

    fn parse_request_line(
        request_line: &str,
    ) -> Result<(&str, &str, &str, bool), tunnel::ConnectionResult> {
        let request_line_items = request_line.split(' ').collect::<Vec<&str>>();
        HttpConnectRequest::precondition_well_formed(request_line, &request_line_items)?;

        let method = request_line_items[0];
        let uri = request_line_items[1];
        let version = request_line_items[2];

        let has_nugget = HttpConnectRequest::check_method(method)?;
        HttpConnectRequest::check_version(version)?;

        Ok((method, uri, version, has_nugget))
    }

    fn precondition_well_formed(
        request_line: &str,
        request_line_items: &[&str],
    ) -> Result<(), tunnel::ConnectionResult> {
        if request_line_items.len() == 3 {
            Ok(())
        } else {
            debug!("Bad request line: `{:?}`", request_line,);
            Err(tunnel::ConnectionResult::BadRequest)
        }
    }

    fn check_version(version: &str) -> Result<(), tunnel::ConnectionResult> {
        if version == "HTTP/1.1" {
            Ok(())
        } else {
            debug!("Bad version '{}'", version);
            Err(tunnel::ConnectionResult::BadRequest)
        }
    }

    #[cfg(not(feature = "plain_text"))]
    fn check_method(method: &str) -> Result<bool, tunnel::ConnectionResult> {
        if method == "CONNECT" {
            Ok(false)
        } else {
            debug!("Method not allowed '{}'", method);
            Err(tunnel::ConnectionResult::OperationNotAllowed)
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    #[cfg(feature = "plain_text")]
    fn check_method(method: &str) -> Result<bool, tunnel::ConnectionResult> {
        Ok(method != "CONNECT")
    }

    fn precondition_legal_characters(http_request: &[u8]) -> Result<(), tunnel::ConnectionResult> {
        for b in http_request {
            match b {
                // non-ascii characters don't make sense in this context
                32..=126 | 9 | 10 | 13 => {}
                _ => {
                    debug!("Bad request header. Illegal character: {:#04x}", b);
                    return Err(tunnel::ConnectionResult::BadRequest);
                }
            }
        }
        Ok(())
    }

    fn precondition_size(http_request: &[u8]) -> Result<(), tunnel::ConnectionResult> {
        if http_request.len() >= MAX_HTTP_REQUEST_SIZE {
            debug!(
                "Bad request header. Size {} exceeds limit {}",
                http_request.len(),
                MAX_HTTP_REQUEST_SIZE
            );
            Err(tunnel::ConnectionResult::BadRequest)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};
    use tokio_util::codec::{Decoder, Encoder};

    use crate::codec;
    use crate::config::Regex;
    use crate::tunnel;

    #[cfg(feature = "plain_text")]
    use crate::target;

    #[test]
    fn test_got_http_request_partial() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        let result = codec.decode(&mut buffer);

        assert_eq!(result, Ok(None));

        buffer.put_slice(b"CONNECT foo.bar.com:443 HTTP/1.1");
        let result = codec.decode(&mut buffer);

        assert_eq!(result, Ok(None));
    }

    #[test]
    fn test_got_http_request_full() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        buffer.put_slice(b"CONNECT foo.bar.com:443 HTTP/1.1");
        buffer.put_slice(codec::REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);

        assert_eq!(
            result,
            Ok(Some(codec::HttpTunnelTarget {
                target: "foo.bar.com:443".to_string(),
                nugget: None
            }))
        );
    }

    #[test]
    fn test_got_http_request_exceeding() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        while buffer.len() <= codec::MAX_HTTP_REQUEST_SIZE {
            buffer.put_slice(b"CONNECT foo.bar.com:443 HTTP/1.1\r\n");
        }
        let result = codec.decode(&mut buffer);

        assert_eq!(result, Err(tunnel::ConnectionResult::BadRequest));
    }

    #[test]
    fn test_parse_valid() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        buffer.put_slice(b"CONNECT foo.bar.com:443 HTTP/1.1");
        buffer.put_slice(codec::REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_valid_with_headers() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        buffer.put_slice(
            b"CONNECT foo.bar.com:443 HTTP/1.1\r\n\
                   Host: ignored\r\n\
                   Auithorization: ignored",
        );
        buffer.put_slice(codec::REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(not(feature = "plain_text"))]
    fn test_parse_not_allowed_method() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        buffer.put_slice(b"GET foo.bar.com:443 HTTP/1.1");
        buffer.put_slice(codec::REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);

        assert_eq!(result, Err(tunnel::ConnectionResult::OperationNotAllowed));
    }

    #[test]
    #[cfg(feature = "plain_text")]
    fn test_parse_plain_text_method() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        buffer.put_slice(b"GET https://foo.bar.com:443/get HTTP/1.1\r\n");
        buffer.put_slice(b"connection: keep-alive\r\n");
        buffer.put_slice(b"Host: \tfoo.bar.com:443 \t\r\n");
        buffer.put_slice(b"User-Agent: whatever");
        buffer.put_slice(codec::REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().target, "foo.bar.com:443");
    }

    #[test]
    #[cfg(feature = "plain_text")]
    fn test_parse_plain_text_default_https_port() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        buffer.put_slice(b"GET https://foo.bar.com/get HTTP/1.1\r\n");
        buffer.put_slice(b"connection: keep-alive\r\n");
        buffer.put_slice(b"Host: \tfoo.bar.com \t\r\n");
        buffer.put_slice(b"User-Agent: whatever");
        buffer.put_slice(codec::REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().target, "foo.bar.com:443");
    }

    #[test]
    #[cfg(feature = "plain_text")]
    fn test_parse_plain_text_default_http_port() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        buffer.put_slice(b"GET http://foo.bar.com/get HTTP/1.1\r\n");
        buffer.put_slice(b"connection: keep-alive\r\n");
        buffer.put_slice(b"Host: \tfoo.bar.com \t\r\n");
        buffer.put_slice(b"User-Agent: whatever");
        buffer.put_slice(codec::REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().target, "foo.bar.com:80");
    }

    #[test]
    #[cfg(feature = "plain_text")]
    fn test_parse_plain_text_nugget() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        buffer.put_slice(b"GET https://foo.bar.com:443/get HTTP/1.1\r\n");
        buffer.put_slice(b"connection: keep-alive\r\n");
        buffer.put_slice(b"Host: \tfoo.bar.com:443 \t\r\n");
        buffer.put_slice(b"User-Agent: whatever");
        buffer.put_slice(codec::REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.nugget.is_some());
        let nugget = result.nugget.unwrap();
        assert_eq!(nugget, target::Nugget::new(buffer.to_vec()));
    }

    #[test]
    #[cfg(feature = "plain_text")]
    fn test_parse_plain_text_with_body() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        buffer.put_slice(b"POST https://foo.bar.com:443/get HTTP/1.1\r\n");
        buffer.put_slice(b"connection: keep-alive\r\n");
        buffer.put_slice(b"Host: \tfoo.bar.com:443 \t\r\n");
        buffer.put_slice(b"User-Agent: whatever");
        buffer.put_slice(codec::REQUEST_END_MARKER);
        buffer.put_slice(b"{body: 'some json body'}");
        let result = codec.decode(&mut buffer);

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.nugget.is_some());
        let nugget = result.nugget.unwrap();
        assert_eq!(nugget, target::Nugget::new(buffer.to_vec()));
    }

    #[test]
    #[cfg(feature = "plain_text")]
    fn test_parse_plain_text_method_forbidden_domain() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        buffer.put_slice(b"GET https://foo.bar.com:443/get HTTP/1.1\r\n");
        buffer.put_slice(b"connection: keep-alive\r\n");
        buffer.put_slice(b"Host: \tsome.uknown.site.com:443 \t\r\n");
        buffer.put_slice(b"User-Agent: whatever");
        buffer.put_slice(codec::REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);

        assert_eq!(result, Err(tunnel::ConnectionResult::Forbidden));
    }

    #[test]
    fn test_parse_bad_version() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        buffer.put_slice(b"CONNECT foo.bar.com:443 HTTP/1.0");
        buffer.put_slice(codec::REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);
        assert!(result.is_err());

        let code = result.err().unwrap();
        assert_eq!(code, tunnel::ConnectionResult::BadRequest);
    }

    #[test]
    fn test_parse_bad_requests() {
        let bad_requests = [
            "bad request\r\n\r\n",                       // 2 tokens
            "yet another bad request\r\n\r\n",           // 4 tokens
            "CONNECT foo.bar.cøm:443 HTTP/1.1\r\n\r\n",  // non-ascii
            "CONNECT  foo.bar.com:443 HTTP/1.1\r\n\r\n", // double-space
            "CONNECT foo.bar.com:443\tHTTP/1.1\r\n\r\n", // CTL
        ];
        bad_requests.iter().for_each(|r| {
            let mut codec = build_codec();

            let mut buffer = BytesMut::new();
            buffer.put_slice(r.as_bytes());
            let result = codec.decode(&mut buffer);

            assert_eq!(
                result,
                Err(tunnel::ConnectionResult::BadRequest),
                "Didn't reject {}",
                r
            );
        });
    }

    #[test]
    fn test_parse_request_exceeds_size() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        while !buffer.len() <= codec::MAX_HTTP_REQUEST_SIZE {
            buffer.put_slice(b"CONNECT foo.bar.com:443 HTTP/1.1\r\n");
        }

        buffer.put_slice(codec::REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);

        assert_eq!(result, Err(tunnel::ConnectionResult::BadRequest));
    }

    #[test]
    fn test_http_tunnel_encoder() {
        let mut codec = build_codec();

        let pattern = Regex::new(r"^HTTP/1\.1 ([2-5][\d]{2}) [A-Z_]{2,20}\r\n\r\n").unwrap();

        for code in &[
            tunnel::ConnectionResult::Ok,
            tunnel::ConnectionResult::BadGateway,
            tunnel::ConnectionResult::Forbidden,
            tunnel::ConnectionResult::GatewayTimeout,
            tunnel::ConnectionResult::OperationNotAllowed,
            tunnel::ConnectionResult::RequestTimeout,
            tunnel::ConnectionResult::ServerError,
            tunnel::ConnectionResult::TooManyRequests,
        ] {
            let mut buffer = BytesMut::new();
            let encoded = codec.encode(code.clone(), &mut buffer);
            assert!(encoded.is_ok());

            let str = String::from_utf8(Vec::from(&buffer[..])).expect("Must be valid ASCII");

            assert!(pattern.is_match(&str), "Malformed response `{:?}`", code);
        }
    }

    fn build_codec() -> codec::HttpTunnel {
        let ctx = tunnel::Ctx::new();

        codec::HttpTunnel {
            tunnel_ctx: ctx,
            enabled_targets: Some(Regex::new(r"foo\.bar\.com:(443|80)").unwrap()),
        }
    }
}
