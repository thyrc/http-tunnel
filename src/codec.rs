#![allow(clippy::module_name_repetitions)]

use bytes::BytesMut;
use core::fmt;
use log::{debug, warn};
use regex::Regex;
use std::fmt::Write;
use std::str::Split;
use tokio::io::{Error, ErrorKind};
use tokio_util::codec::{Decoder, Encoder};

use crate::target::Nugget;
use crate::tunnel::{EstablishTunnelResult, TunnelCtx, TunnelTarget};

const REQUEST_END_MARKER: &[u8] = b"\r\n\r\n";
/// A reasonable value to limit possible header size.
const MAX_HTTP_REQUEST_SIZE: usize = 16384;

/// HTTP/1.1 request representation
/// Supports only `CONNECT` method
struct HttpConnectRequest {
    uri: String,
    nugget: Option<Nugget>,
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct HttpTunnelTarget {
    pub target: String,
    pub nugget: Option<Nugget>,
    // easily can be extended with something like
    // policies: Vec<TunnelPolicy>
}

/// Codec to extract `HTTP/1.1 CONNECT` requests and build a corresponding `HTTP` response.
#[derive(Clone)]
pub struct HttpTunnelCodec {
    pub tunnel_ctx: TunnelCtx,
    pub enabled_targets: Option<Regex>,
}

impl Decoder for HttpTunnelCodec {
    type Item = HttpTunnelTarget;
    type Error = EstablishTunnelResult;

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
                    Err(EstablishTunnelResult::Forbidden)
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

impl Encoder<EstablishTunnelResult> for HttpTunnelCodec {
    type Error = std::io::Error;

    fn encode(
        &mut self,
        item: EstablishTunnelResult,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        let (code, message) = match item {
            EstablishTunnelResult::Ok => (200, "OK"),
            EstablishTunnelResult::OkWithNugget => {
                // do nothing, upstream should respond instead
                return Ok(());
            }
            EstablishTunnelResult::BadRequest => (400, "BAD_REQUEST"),
            EstablishTunnelResult::Forbidden => (403, "FORBIDDEN"),
            EstablishTunnelResult::OperationNotAllowed => (405, "NOT_ALLOWED"),
            EstablishTunnelResult::RequestTimeout => (408, "TIMEOUT"),
            EstablishTunnelResult::TooManyRequests => (429, "TOO_MANY_REQUESTS"),
            EstablishTunnelResult::ServerError => (500, "SERVER_ERROR"),
            EstablishTunnelResult::BadGateway => (502, "BAD_GATEWAY"),
            EstablishTunnelResult::GatewayTimeout => (504, "GATEWAY_TIMEOUT"),
        };

        #[allow(clippy::cast_sign_loss)]
        dst.write_fmt(format_args!("HTTP/1.1 {} {message}\r\n\r\n", code as u32))
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::Other))
    }
}

impl TunnelTarget for HttpTunnelTarget {
    type Addr = String;

    fn target_addr(&self) -> Self::Addr {
        self.target.clone()
    }

    fn has_nugget(&self) -> bool {
        self.nugget.is_some()
    }

    fn nugget(&self) -> &Nugget {
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

impl From<Error> for EstablishTunnelResult {
    fn from(e: Error) -> Self {
        match e.kind() {
            ErrorKind::TimedOut => EstablishTunnelResult::GatewayTimeout,
            _ => EstablishTunnelResult::BadGateway,
        }
    }
}

/// Basic HTTP Request parser which only purpose is to parse `CONNECT` requests.
impl HttpConnectRequest {
    pub fn parse(http_request: &[u8]) -> Result<Self, EstablishTunnelResult> {
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
                nugget: Some(Nugget::new(http_request)),
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
    ) -> Result<(&str, &str, &str, bool), EstablishTunnelResult> {
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
    ) -> Result<(), EstablishTunnelResult> {
        if request_line_items.len() == 3 {
            Ok(())
        } else {
            debug!("Bad request line: `{:?}`", request_line,);
            Err(EstablishTunnelResult::BadRequest)
        }
    }

    fn check_version(version: &str) -> Result<(), EstablishTunnelResult> {
        if version == "HTTP/1.1" {
            Ok(())
        } else {
            debug!("Bad version '{}'", version);
            Err(EstablishTunnelResult::BadRequest)
        }
    }

    #[cfg(not(feature = "plain_text"))]
    fn check_method(method: &str) -> Result<bool, EstablishTunnelResult> {
        if method == "CONNECT" {
            Ok(false)
        } else {
            debug!("Method not allowed '{}'", method);
            Err(EstablishTunnelResult::OperationNotAllowed)
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    #[cfg(feature = "plain_text")]
    fn check_method(method: &str) -> Result<bool, EstablishTunnelResult> {
        Ok(method != "CONNECT")
    }

    fn precondition_legal_characters(http_request: &[u8]) -> Result<(), EstablishTunnelResult> {
        for b in http_request {
            match b {
                // non-ascii characters don't make sense in this context
                32..=126 | 9 | 10 | 13 => {}
                _ => {
                    debug!("Bad request header. Illegal character: {:#04x}", b);
                    return Err(EstablishTunnelResult::BadRequest);
                }
            }
        }
        Ok(())
    }

    fn precondition_size(http_request: &[u8]) -> Result<(), EstablishTunnelResult> {
        if http_request.len() >= MAX_HTTP_REQUEST_SIZE {
            debug!(
                "Bad request header. Size {} exceeds limit {}",
                http_request.len(),
                MAX_HTTP_REQUEST_SIZE
            );
            Err(EstablishTunnelResult::BadRequest)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};
    use regex::Regex;
    use tokio_util::codec::{Decoder, Encoder};

    use crate::codec::{
        EstablishTunnelResult, HttpTunnelCodec, HttpTunnelTarget, MAX_HTTP_REQUEST_SIZE,
        REQUEST_END_MARKER,
    };
    #[cfg(feature = "plain_text")]
    use crate::target::Nugget;
    #[cfg(feature = "plain_text")]
    use crate::tunnel::EstablishTunnelResult::Forbidden;
    use crate::tunnel::TunnelCtx;

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
        buffer.put_slice(REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);

        assert_eq!(
            result,
            Ok(Some(HttpTunnelTarget {
                target: "foo.bar.com:443".to_string(),
                nugget: None
            }))
        );
    }

    #[test]
    fn test_got_http_request_exceeding() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        while buffer.len() <= MAX_HTTP_REQUEST_SIZE {
            buffer.put_slice(b"CONNECT foo.bar.com:443 HTTP/1.1\r\n");
        }
        let result = codec.decode(&mut buffer);

        assert_eq!(result, Err(EstablishTunnelResult::BadRequest));
    }

    #[test]
    fn test_parse_valid() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        buffer.put_slice(b"CONNECT foo.bar.com:443 HTTP/1.1");
        buffer.put_slice(REQUEST_END_MARKER);
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
        buffer.put_slice(REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(not(feature = "plain_text"))]
    fn test_parse_not_allowed_method() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        buffer.put_slice(b"GET foo.bar.com:443 HTTP/1.1");
        buffer.put_slice(REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);

        assert_eq!(result, Err(EstablishTunnelResult::OperationNotAllowed));
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
        buffer.put_slice(REQUEST_END_MARKER);
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
        buffer.put_slice(REQUEST_END_MARKER);
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
        buffer.put_slice(REQUEST_END_MARKER);
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
        buffer.put_slice(REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.nugget.is_some());
        let nugget = result.nugget.unwrap();
        assert_eq!(nugget, Nugget::new(buffer.to_vec()));
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
        buffer.put_slice(REQUEST_END_MARKER);
        buffer.put_slice(b"{body: 'some json body'}");
        let result = codec.decode(&mut buffer);

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.nugget.is_some());
        let nugget = result.nugget.unwrap();
        assert_eq!(nugget, Nugget::new(buffer.to_vec()));
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
        buffer.put_slice(REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);

        assert_eq!(result, Err(Forbidden));
    }

    #[test]
    fn test_parse_bad_version() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        buffer.put_slice(b"CONNECT foo.bar.com:443 HTTP/1.0");
        buffer.put_slice(REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);
        assert!(result.is_err());

        let code = result.err().unwrap();
        assert_eq!(code, EstablishTunnelResult::BadRequest);
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
                Err(EstablishTunnelResult::BadRequest),
                "Didn't reject {}",
                r
            );
        });
    }

    #[test]
    fn test_parse_request_exceeds_size() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        while !buffer.len() <= MAX_HTTP_REQUEST_SIZE {
            buffer.put_slice(b"CONNECT foo.bar.com:443 HTTP/1.1\r\n");
        }

        buffer.put_slice(REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);

        assert_eq!(result, Err(EstablishTunnelResult::BadRequest));
    }

    #[test]
    fn test_http_tunnel_encoder() {
        let mut codec = build_codec();

        let pattern = Regex::new(r"^HTTP/1\.1 ([2-5][\d]{2}) [A-Z_]{2,20}\r\n\r\n").unwrap();

        for code in &[
            EstablishTunnelResult::Ok,
            EstablishTunnelResult::BadGateway,
            EstablishTunnelResult::Forbidden,
            EstablishTunnelResult::GatewayTimeout,
            EstablishTunnelResult::OperationNotAllowed,
            EstablishTunnelResult::RequestTimeout,
            EstablishTunnelResult::ServerError,
            EstablishTunnelResult::TooManyRequests,
        ] {
            let mut buffer = BytesMut::new();
            let encoded = codec.encode(code.clone(), &mut buffer);
            assert!(encoded.is_ok());

            let str = String::from_utf8(Vec::from(&buffer[..])).expect("Must be valid ASCII");

            assert!(pattern.is_match(&str), "Malformed response `{:?}`", code);
        }
    }

    fn build_codec() -> HttpTunnelCodec {
        let ctx = TunnelCtx::new();

        HttpTunnelCodec {
            tunnel_ctx: ctx,
            enabled_targets: Some(Regex::new(r"foo\.bar\.com:(443|80)").unwrap()),
        }
    }
}
