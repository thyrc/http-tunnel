Based on xnuter's http-tunnel crate and HTTP proxy example.

Please refer to the original [http-tunnel](https://github.com/xnuter/http-tunnel) repository, [crates.io](https://crates.io/crates/http-tunnel) page or excellent [guide](https://medium.com/swlh/writing-a-modern-http-s-tunnel-in-rust-56e70d898700).

### Overview

An implementation of [HTTP Tunnel](https://en.wikipedia.org/wiki/HTTP_tunnel) in Rust.

This is a simplified version of the original, supporting only HTTP CONNECT, with a few changes to config file handling & regex building.
