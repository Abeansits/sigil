//! Forward proxy for domain-level network filtering in containers.
//!
//! Containers run with `--internal` network (no internet by default).
//! This proxy runs on the host, listens on a Unix socket published into
//! the container, and checks each outbound connection's target domain
//! against an allowlist. Allowed connections are tunneled; denied
//! connections receive an HTTP 403 response.
//!
//! Supports both HTTPS (via HTTP CONNECT) and plain HTTP forwarding.
//! Every connection attempt is an auditable event.
//!
//! Feature-gated behind `container`.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sigil_audit::AuditLogWriter;
use sigil_core::AuditEvent;
use sigil_core::action::PolicyDecision;
use sigil_core::id::{RequestId, SessionId};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::error::RuntimeError;

/// Maximum concurrent proxy connections.
const MAX_CONCURRENT_CONNECTIONS: usize = 128;

/// Timeout for reading the initial request line from the client.
const REQUEST_LINE_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for establishing a TCP connection to the upstream server.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum length of a single request/header line (16 KiB).
const MAX_LINE_LENGTH: usize = 16_384;

// ---------------------------------------------------------------------------
// Domain allowlist
// ---------------------------------------------------------------------------

/// A set of allowed domains for proxy filtering.
///
/// Entries starting with `.` match the domain itself and any subdomain:
/// `.github.com` matches `github.com` and `api.github.com` but not
/// `notgithub.com`.
///
/// Entries without a leading `.` match exactly.
#[derive(Clone, Debug)]
pub struct DomainAllowlist {
    domains: Vec<String>,
}

impl DomainAllowlist {
    /// Create a new allowlist from the given domain patterns.
    #[must_use]
    pub fn new(domains: Vec<String>) -> Self {
        // Normalize: lowercase all entries.
        let domains = domains
            .into_iter()
            .map(|d| d.to_ascii_lowercase())
            .collect();
        Self { domains }
    }

    /// Check whether `domain` is permitted by this allowlist.
    ///
    /// Raw IP addresses (IPv4/IPv6) are always denied to prevent
    /// allowlist bypass. Only domain names are matched.
    #[must_use]
    pub fn is_allowed(&self, domain: &str) -> bool {
        let domain = domain.to_ascii_lowercase();

        // Reject raw IP addresses — require domain names only.
        // Strip brackets for IPv6 literals like `[::1]`.
        let bare = domain.strip_prefix('[').and_then(|s| s.strip_suffix(']'));
        let ip_candidate = bare.unwrap_or(&domain);
        if ip_candidate.parse::<IpAddr>().is_ok() {
            return false;
        }

        for pattern in &self.domains {
            if let Some(suffix) = pattern.strip_prefix('.') {
                // Suffix pattern: `.github.com` matches `github.com` and
                // `api.github.com` but NOT `notgithub.com`.
                if domain == suffix || domain.ends_with(pattern.as_str()) {
                    return true;
                }
            } else {
                // Exact match.
                if domain == *pattern {
                    return true;
                }
            }
        }

        false
    }

    /// Returns `true` if the allowlist has no entries (blocks everything).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------

/// Parsed first line of an HTTP proxy request.
#[derive(Debug, PartialEq, Eq)]
enum ProxyRequest {
    /// `CONNECT host:port HTTP/1.x`
    Connect { host: String, port: u16 },
    /// `GET http://host/path HTTP/1.x` (or POST, PUT, etc.)
    Http {
        method: String,
        host: String,
        port: u16,
        path: String,
    },
}

/// Parse the first line of an HTTP proxy request.
///
/// Returns `None` if the line is not a valid proxy request.
fn parse_request_line(line: &str) -> Option<ProxyRequest> {
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    // Must have at least a version token (HTTP/1.x).
    let _version = parts.next()?;

    if method.eq_ignore_ascii_case("CONNECT") {
        // CONNECT host:port HTTP/1.x
        let (host, port) = parse_host_port(target)?;
        Some(ProxyRequest::Connect { host, port })
    } else if target.starts_with("http://") {
        // Absolute-form HTTP request: GET http://host[:port]/path HTTP/1.x
        let without_scheme = target.strip_prefix("http://")?;
        let (authority, path) = match without_scheme.find('/') {
            Some(idx) => (&without_scheme[..idx], &without_scheme[idx..]),
            None => (without_scheme, "/"),
        };
        let (host, port) = parse_host_port_default(authority, 80)?;
        Some(ProxyRequest::Http {
            method: method.to_owned(),
            host,
            port,
            path: path.to_owned(),
        })
    } else {
        None
    }
}

/// Parse `host:port` from a CONNECT target.
fn parse_host_port(s: &str) -> Option<(String, u16)> {
    let (host, port_str) = s.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;
    if host.is_empty() {
        return None;
    }
    Some((host.to_owned(), port))
}

/// Parse `host[:port]` with a default port.
fn parse_host_port_default(s: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some((host, port_str)) = s.rsplit_once(':') {
        let port: u16 = port_str.parse().ok()?;
        if host.is_empty() {
            return None;
        }
        Some((host.to_owned(), port))
    } else if s.is_empty() {
        None
    } else {
        Some((s.to_owned(), default_port))
    }
}

// ---------------------------------------------------------------------------
// DomainProxy
// ---------------------------------------------------------------------------

/// A forward proxy that filters outbound connections by domain.
///
/// Listens on a Unix socket (published into a container) and proxies
/// HTTP CONNECT tunnels and plain HTTP requests to the internet,
/// subject to a domain allowlist.
pub struct DomainProxy {
    allowlist: Arc<DomainAllowlist>,
    socket_path: PathBuf,
    audit: Option<Arc<AuditLogWriter>>,
    session_id: Option<SessionId>,
}

impl DomainProxy {
    /// Create a new domain-filtering proxy.
    ///
    /// - `allowlist` — domains to permit (e.g. `".anthropic.com"`,
    ///   `".github.com"`)
    /// - `socket_path` — Unix socket to listen on
    /// - `audit` — optional audit log writer for connection events
    /// - `session_id` — session this proxy belongs to (for audit)
    #[must_use]
    pub fn new(
        allowlist: Vec<String>,
        socket_path: PathBuf,
        audit: Option<Arc<AuditLogWriter>>,
        session_id: Option<SessionId>,
    ) -> Self {
        Self {
            allowlist: Arc::new(DomainAllowlist::new(allowlist)),
            socket_path,
            audit,
            session_id,
        }
    }

    /// The path the proxy will listen on.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Run the proxy until `shutdown` is triggered.
    ///
    /// The proxy binds to the Unix socket and accepts connections in a
    /// loop. Each connection is handled in a spawned task. When
    /// `shutdown` resolves, the listener stops accepting new connections
    /// but in-flight connections drain naturally.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Proxy`] if the socket cannot be bound.
    pub async fn run(
        &self,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), RuntimeError> {
        // Remove stale socket file if it exists.
        let _ = tokio::fs::remove_file(&self.socket_path).await;

        let listener = UnixListener::bind(&self.socket_path).map_err(|e| RuntimeError::Proxy {
            message: format!("failed to bind {}: {e}", self.socket_path.display()),
        })?;

        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

        info!(
            path = %self.socket_path.display(),
            domains = ?self.allowlist.domains,
            max_connections = MAX_CONCURRENT_CONNECTIONS,
            "proxy listening"
        );

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, _addr)) => {
                            let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                                warn!("proxy connection limit reached, dropping connection");
                                continue;
                            };
                            let allowlist = Arc::clone(&self.allowlist);
                            let audit = self.audit.clone();
                            let session_id = self.session_id;
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(
                                    stream, &allowlist, audit.as_deref(), session_id,
                                ).await {
                                    debug!(error = %e, "proxy connection error");
                                }
                                drop(permit);
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "proxy accept error");
                        }
                    }
                }
                () = shutdown_signal(&shutdown) => {
                    info!("proxy shutting down");
                    break;
                }
            }
        }

        // Clean up socket file.
        let _ = tokio::fs::remove_file(&self.socket_path).await;
        Ok(())
    }
}

/// Wait until the shutdown signal is `true`.
async fn shutdown_signal(rx: &tokio::sync::watch::Receiver<bool>) {
    let mut rx = rx.clone();
    // Wait for the value to become true.
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            // Sender dropped — treat as shutdown.
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a single line, enforcing a maximum length to prevent memory
/// exhaustion from malicious input.
async fn read_limited_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut String,
    max_len: usize,
) -> std::io::Result<usize> {
    let n = reader.read_line(buf).await?;
    if buf.len() > max_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "line exceeds maximum length",
        ));
    }
    Ok(n)
}

/// Attempt a TCP connection to an upstream host with a timeout.
async fn connect_upstream(host: &str, port: u16) -> Result<TcpStream, RuntimeError> {
    match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(RuntimeError::Proxy {
            message: format!("upstream connect to {host}:{port} failed: {e}"),
        }),
        Err(_) => Err(RuntimeError::Proxy {
            message: format!("upstream connect to {host}:{port} timed out"),
        }),
    }
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

/// Response bytes for common HTTP status codes.
const RESPONSE_200: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const RESPONSE_400: &[u8] = b"HTTP/1.1 400 Bad Request\r\n\r\n";
const RESPONSE_403: &[u8] = b"HTTP/1.1 403 Forbidden\r\n\r\n";
const RESPONSE_502: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\n\r\n";

/// Shared context for handling a single proxy connection.
struct ConnContext<'a> {
    allowlist: &'a DomainAllowlist,
    audit: Option<&'a AuditLogWriter>,
    session_id: Option<SessionId>,
}

/// Handle a single proxy connection.
async fn handle_connection(
    stream: UnixStream,
    allowlist: &DomainAllowlist,
    audit: Option<&AuditLogWriter>,
    session_id: Option<SessionId>,
) -> Result<(), RuntimeError> {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);

    // Read the first line (request line) with a timeout to prevent
    // slowloris-style attacks.
    let mut request_line = String::new();
    let read_result = tokio::time::timeout(
        REQUEST_LINE_TIMEOUT,
        read_limited_line(&mut buf_reader, &mut request_line, MAX_LINE_LENGTH),
    )
    .await;

    let bytes_read = match read_result {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            return Err(RuntimeError::Proxy {
                message: format!("failed to read request line: {e}"),
            });
        }
        Err(_) => {
            let _ = writer.write_all(RESPONSE_400).await;
            return Ok(());
        }
    };

    if bytes_read == 0 {
        return Ok(()); // Client disconnected immediately.
    }

    let request_line = request_line.trim_end();

    let Some(request) = parse_request_line(request_line) else {
        let _ = writer.write_all(RESPONSE_400).await;
        return Ok(());
    };

    let ctx = ConnContext {
        allowlist,
        audit,
        session_id,
    };

    match request {
        ProxyRequest::Connect { host, port } => {
            handle_connect(&host, port, buf_reader, writer, &ctx).await
        }
        ProxyRequest::Http {
            method,
            host,
            port,
            path,
        } => handle_http(&method, &host, port, &path, buf_reader, writer, &ctx).await,
    }
}

/// Handle an HTTP CONNECT tunnel request.
async fn handle_connect(
    host: &str,
    port: u16,
    mut buf_reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    mut writer: tokio::net::unix::OwnedWriteHalf,
    ctx: &ConnContext<'_>,
) -> Result<(), RuntimeError> {
    // Consume remaining headers until the blank line.
    let mut header_line = String::new();
    loop {
        header_line.clear();
        let n = read_limited_line(&mut buf_reader, &mut header_line, MAX_LINE_LENGTH)
            .await
            .map_err(|e| RuntimeError::Proxy {
                message: format!("failed to read header: {e}"),
            })?;
        if n == 0 || header_line.trim().is_empty() {
            break;
        }
    }

    let allowed = ctx.allowlist.is_allowed(host);

    // Audit the connection attempt.
    emit_audit(
        ctx.audit,
        ctx.session_id,
        &format!("CONNECT {host}:{port}"),
        allowed,
    )
    .await;

    if !allowed {
        debug!(host, port, "CONNECT denied");
        let _ = writer.write_all(RESPONSE_403).await;
        return Ok(());
    }

    // Establish upstream TCP connection with timeout.
    let upstream = match connect_upstream(host, port).await {
        Ok(s) => s,
        Err(e) => {
            debug!(host, port, error = %e, "upstream connect failed");
            let _ = writer.write_all(RESPONSE_502).await;
            return Ok(());
        }
    };

    // Tell the client the tunnel is established.
    writer
        .write_all(RESPONSE_200)
        .await
        .map_err(|e| RuntimeError::Proxy {
            message: format!("failed to send 200: {e}"),
        })?;

    debug!(host, port, "CONNECT tunnel established");

    // Relay bytes bidirectionally.
    let client_reader = buf_reader.into_inner();
    let mut client = client_reader
        .reunite(writer)
        .map_err(|e| RuntimeError::Proxy {
            message: format!("failed to reunite stream halves: {e}"),
        })?;
    let (mut upstream_read, mut upstream_write) = upstream.into_split();
    let (mut client_read, mut client_write) = client.split();

    let client_to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
    let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut client_write);

    // When either direction finishes, both are done.
    let _ = tokio::try_join!(client_to_upstream, upstream_to_client);

    debug!(host, port, "CONNECT tunnel closed");
    Ok(())
}

/// Handle a plain HTTP proxy request.
#[allow(clippy::too_many_arguments)]
async fn handle_http(
    method: &str,
    host: &str,
    port: u16,
    path: &str,
    mut buf_reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    mut writer: tokio::net::unix::OwnedWriteHalf,
    ctx: &ConnContext<'_>,
) -> Result<(), RuntimeError> {
    let allowed = ctx.allowlist.is_allowed(host);

    emit_audit(
        ctx.audit,
        ctx.session_id,
        &format!("{method} http://{host}:{port}{path}"),
        allowed,
    )
    .await;

    if !allowed {
        debug!(host, port, method, "HTTP request denied");
        let _ = writer.write_all(RESPONSE_403).await;
        return Ok(());
    }

    // Connect to the upstream server with timeout.
    let mut upstream = match connect_upstream(host, port).await {
        Ok(s) => s,
        Err(e) => {
            debug!(host, port, error = %e, "upstream connect failed");
            let _ = writer.write_all(RESPONSE_502).await;
            return Ok(());
        }
    };

    // Rewrite the request line to origin-form and forward.
    let origin_request = format!("{method} {path} HTTP/1.1\r\n");
    upstream
        .write_all(origin_request.as_bytes())
        .await
        .map_err(|e| RuntimeError::Proxy {
            message: format!("failed to forward request line: {e}"),
        })?;

    // Forward remaining headers and body from client to upstream.
    // Read headers, forward them, and track Content-Length for body.
    // Strip Proxy-* hop-by-hop headers to prevent information leakage.
    let mut content_length: u64 = 0;
    let mut header_line = String::new();
    loop {
        header_line.clear();
        let n = read_limited_line(&mut buf_reader, &mut header_line, MAX_LINE_LENGTH)
            .await
            .map_err(|e| RuntimeError::Proxy {
                message: format!("failed to read header: {e}"),
            })?;
        if n == 0 || header_line.trim().is_empty() {
            upstream
                .write_all(b"\r\n")
                .await
                .map_err(|e| RuntimeError::Proxy {
                    message: format!("failed to forward end-of-headers: {e}"),
                })?;
            break;
        }
        // Parse header name for filtering and content-length tracking.
        if let Some(colon_pos) = header_line.find(':') {
            let name = &header_line[..colon_pos];

            // Strip Proxy-* hop-by-hop headers.
            if name.len() >= 6 && name[..6].eq_ignore_ascii_case("proxy-") {
                continue;
            }

            if name.eq_ignore_ascii_case("content-length") {
                let val = &header_line[colon_pos + 1..];
                if let Ok(len) = val.trim().parse::<u64>() {
                    content_length = len;
                }
            }
        }
        upstream
            .write_all(header_line.as_bytes())
            .await
            .map_err(|e| RuntimeError::Proxy {
                message: format!("failed to forward header: {e}"),
            })?;
    }

    // Forward request body if present.
    if content_length > 0 {
        let mut body_reader = buf_reader.take(content_length);
        tokio::io::copy(&mut body_reader, &mut upstream)
            .await
            .map_err(|e| RuntimeError::Proxy {
                message: format!("failed to forward request body: {e}"),
            })?;
    }

    // Relay the entire upstream response back to the client.
    let (mut upstream_read, _upstream_write) = upstream.into_split();
    tokio::io::copy(&mut upstream_read, &mut writer)
        .await
        .map_err(|e| RuntimeError::Proxy {
            message: format!("failed to relay response: {e}"),
        })?;

    debug!(host, port, method, path, "HTTP request completed");
    Ok(())
}

// ---------------------------------------------------------------------------
// Audit helpers
// ---------------------------------------------------------------------------

/// Emit an audit event for a proxy connection attempt.
async fn emit_audit(
    audit: Option<&AuditLogWriter>,
    session_id: Option<SessionId>,
    action_summary: &str,
    allowed: bool,
) {
    let Some(writer) = audit else { return };

    let decision = if allowed {
        PolicyDecision::Allow
    } else {
        PolicyDecision::Deny {
            reason: "domain not in proxy allowlist".to_owned(),
        }
    };

    let event = AuditEvent {
        request_id: RequestId::new(),
        timestamp: time::OffsetDateTime::now_utc(),
        action_summary: action_summary.to_owned(),
        origin_summary: "network-proxy".to_owned(),
        decision,
        session_id,
        sanitize_report: None,
    };

    if let Err(e) = sigil_core::traits::AuditWriter::append(writer, &event).await {
        warn!(error = %e, "failed to write proxy audit event");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::print_stderr,
        clippy::unwrap_used
    )]

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    // -- DomainAllowlist tests ------------------------------------------------

    #[test]
    fn exact_match_allows_domain() {
        let al = DomainAllowlist::new(vec!["example.com".to_owned()]);
        assert!(al.is_allowed("example.com"));
    }

    #[test]
    fn exact_match_rejects_different_domain() {
        let al = DomainAllowlist::new(vec!["example.com".to_owned()]);
        assert!(!al.is_allowed("other.com"));
    }

    #[test]
    fn exact_match_rejects_subdomain() {
        let al = DomainAllowlist::new(vec!["example.com".to_owned()]);
        assert!(!al.is_allowed("sub.example.com"));
    }

    #[test]
    fn suffix_match_allows_exact_domain() {
        let al = DomainAllowlist::new(vec![".github.com".to_owned()]);
        assert!(al.is_allowed("github.com"));
    }

    #[test]
    fn suffix_match_allows_subdomain() {
        let al = DomainAllowlist::new(vec![".github.com".to_owned()]);
        assert!(al.is_allowed("api.github.com"));
    }

    #[test]
    fn suffix_match_allows_deep_subdomain() {
        let al = DomainAllowlist::new(vec![".github.com".to_owned()]);
        assert!(al.is_allowed("a.b.c.github.com"));
    }

    #[test]
    fn suffix_match_rejects_non_boundary() {
        let al = DomainAllowlist::new(vec![".github.com".to_owned()]);
        assert!(!al.is_allowed("notgithub.com"));
    }

    #[test]
    fn suffix_match_rejects_partial_overlap() {
        let al = DomainAllowlist::new(vec![".github.com".to_owned()]);
        assert!(!al.is_allowed("evilgithub.com"));
    }

    #[test]
    fn case_insensitive_matching() {
        let al = DomainAllowlist::new(vec![".GitHub.COM".to_owned()]);
        assert!(al.is_allowed("API.GITHUB.COM"));
        assert!(al.is_allowed("github.com"));
    }

    #[test]
    fn empty_allowlist_blocks_everything() {
        let al = DomainAllowlist::new(vec![]);
        assert!(!al.is_allowed("anything.com"));
        assert!(al.is_empty());
    }

    #[test]
    fn rejects_ipv4_address() {
        let al = DomainAllowlist::new(vec![".example.com".to_owned()]);
        assert!(!al.is_allowed("1.2.3.4"));
        assert!(!al.is_allowed("127.0.0.1"));
    }

    #[test]
    fn rejects_ipv6_address() {
        let al = DomainAllowlist::new(vec![".example.com".to_owned()]);
        assert!(!al.is_allowed("::1"));
        assert!(!al.is_allowed("[::1]"));
        assert!(!al.is_allowed("2001:db8::1"));
    }

    #[test]
    fn multiple_entries_checked() {
        let al = DomainAllowlist::new(vec![
            ".anthropic.com".to_owned(),
            ".github.com".to_owned(),
            "registry.npmjs.org".to_owned(),
        ]);
        assert!(al.is_allowed("api.anthropic.com"));
        assert!(al.is_allowed("github.com"));
        assert!(al.is_allowed("registry.npmjs.org"));
        assert!(!al.is_allowed("evil.com"));
        assert!(!al.is_allowed("npmjs.org")); // exact match only
    }

    // -- Request parsing tests ------------------------------------------------

    #[test]
    fn parse_connect_request() {
        let req = parse_request_line("CONNECT api.github.com:443 HTTP/1.1");
        assert_eq!(
            req,
            Some(ProxyRequest::Connect {
                host: "api.github.com".to_owned(),
                port: 443,
            })
        );
    }

    #[test]
    fn parse_connect_lowercase() {
        let req = parse_request_line("connect host.example.com:8443 HTTP/1.1");
        assert_eq!(
            req,
            Some(ProxyRequest::Connect {
                host: "host.example.com".to_owned(),
                port: 8443,
            })
        );
    }

    #[test]
    fn parse_connect_missing_port() {
        let req = parse_request_line("CONNECT api.github.com HTTP/1.1");
        assert_eq!(req, None);
    }

    #[test]
    fn parse_http_get() {
        let req = parse_request_line("GET http://example.com/path HTTP/1.1");
        assert_eq!(
            req,
            Some(ProxyRequest::Http {
                method: "GET".to_owned(),
                host: "example.com".to_owned(),
                port: 80,
                path: "/path".to_owned(),
            })
        );
    }

    #[test]
    fn parse_http_get_with_port() {
        let req = parse_request_line("GET http://example.com:8080/api/v1 HTTP/1.1");
        assert_eq!(
            req,
            Some(ProxyRequest::Http {
                method: "GET".to_owned(),
                host: "example.com".to_owned(),
                port: 8080,
                path: "/api/v1".to_owned(),
            })
        );
    }

    #[test]
    fn parse_http_no_path() {
        let req = parse_request_line("GET http://example.com HTTP/1.1");
        assert_eq!(
            req,
            Some(ProxyRequest::Http {
                method: "GET".to_owned(),
                host: "example.com".to_owned(),
                port: 80,
                path: "/".to_owned(),
            })
        );
    }

    #[test]
    fn parse_http_post() {
        let req = parse_request_line("POST http://api.example.com/data HTTP/1.1");
        assert_eq!(
            req,
            Some(ProxyRequest::Http {
                method: "POST".to_owned(),
                host: "api.example.com".to_owned(),
                port: 80,
                path: "/data".to_owned(),
            })
        );
    }

    #[test]
    fn parse_relative_path_rejected() {
        // Non-proxy request (relative path) should be rejected.
        let req = parse_request_line("GET /index.html HTTP/1.1");
        assert_eq!(req, None);
    }

    #[test]
    fn parse_empty_line() {
        assert_eq!(parse_request_line(""), None);
    }

    #[test]
    fn parse_garbage() {
        assert_eq!(parse_request_line("not a valid request"), None);
    }

    // -- Integration tests (Unix socket) --------------------------------------

    #[tokio::test]
    async fn proxy_denies_connect_to_unlisted_domain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("proxy.sock");

        let proxy = DomainProxy::new(
            vec![".allowed.com".to_owned()],
            sock_path.clone(),
            None,
            None,
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let proxy_task = tokio::spawn(async move {
            let _ = proxy.run(shutdown_rx).await;
        });

        // Wait for socket to appear.
        wait_for_socket(&sock_path).await;

        // Connect and send a CONNECT to a denied domain.
        let mut client = UnixStream::connect(&sock_path).await.expect("connect");
        client
            .write_all(b"CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com\r\n\r\n")
            .await
            .expect("write");

        let mut response = vec![0u8; 512];
        let n = client.read(&mut response).await.expect("read");
        let response_str = std::str::from_utf8(&response[..n]).expect("utf8");

        assert!(
            response_str.contains("403"),
            "expected 403, got: {response_str}"
        );

        let _ = shutdown_tx.send(true);
        let _ = proxy_task.await;
    }

    #[tokio::test]
    async fn proxy_allows_connect_to_listed_domain() {
        // We can't fully test a CONNECT tunnel without a real upstream
        // server, but we can verify the proxy attempts the connection
        // (and returns 502 since the domain won't resolve in tests).
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("proxy.sock");

        let proxy = DomainProxy::new(
            vec![".allowed-test-domain.invalid".to_owned()],
            sock_path.clone(),
            None,
            None,
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let proxy_task = tokio::spawn(async move {
            let _ = proxy.run(shutdown_rx).await;
        });

        wait_for_socket(&sock_path).await;

        let mut client = UnixStream::connect(&sock_path).await.expect("connect");
        client
            .write_all(
                b"CONNECT allowed-test-domain.invalid:443 HTTP/1.1\r\nHost: allowed-test-domain.invalid\r\n\r\n",
            )
            .await
            .expect("write");

        let mut response = vec![0u8; 512];
        let n = client.read(&mut response).await.expect("read");
        let response_str = std::str::from_utf8(&response[..n]).expect("utf8");

        // The domain is allowed but won't resolve → 502 Bad Gateway.
        assert!(
            response_str.contains("502"),
            "expected 502 (unresolvable but allowed), got: {response_str}"
        );

        let _ = shutdown_tx.send(true);
        let _ = proxy_task.await;
    }

    #[tokio::test]
    async fn proxy_returns_400_on_malformed_request() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("proxy.sock");

        let proxy = DomainProxy::new(
            vec![".allowed.com".to_owned()],
            sock_path.clone(),
            None,
            None,
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let proxy_task = tokio::spawn(async move {
            let _ = proxy.run(shutdown_rx).await;
        });

        wait_for_socket(&sock_path).await;

        let mut client = UnixStream::connect(&sock_path).await.expect("connect");
        client
            .write_all(b"GARBAGE INPUT\r\n\r\n")
            .await
            .expect("write");

        let mut response = vec![0u8; 512];
        let n = client.read(&mut response).await.expect("read");
        let response_str = std::str::from_utf8(&response[..n]).expect("utf8");

        assert!(
            response_str.contains("400"),
            "expected 400, got: {response_str}"
        );

        let _ = shutdown_tx.send(true);
        let _ = proxy_task.await;
    }

    #[tokio::test]
    async fn proxy_denies_http_get_to_unlisted_domain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("proxy.sock");

        let proxy = DomainProxy::new(
            vec![".allowed.com".to_owned()],
            sock_path.clone(),
            None,
            None,
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let proxy_task = tokio::spawn(async move {
            let _ = proxy.run(shutdown_rx).await;
        });

        wait_for_socket(&sock_path).await;

        let mut client = UnixStream::connect(&sock_path).await.expect("connect");
        client
            .write_all(b"GET http://evil.com/secrets HTTP/1.1\r\nHost: evil.com\r\n\r\n")
            .await
            .expect("write");

        let mut response = vec![0u8; 512];
        let n = client.read(&mut response).await.expect("read");
        let response_str = std::str::from_utf8(&response[..n]).expect("utf8");

        assert!(
            response_str.contains("403"),
            "expected 403, got: {response_str}"
        );

        let _ = shutdown_tx.send(true);
        let _ = proxy_task.await;
    }

    #[tokio::test]
    async fn proxy_shutdown_cleans_up_socket() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("proxy.sock");

        let proxy = DomainProxy::new(vec![], sock_path.clone(), None, None);

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let proxy_task = tokio::spawn(async move {
            let _ = proxy.run(shutdown_rx).await;
        });

        wait_for_socket(&sock_path).await;
        assert!(sock_path.exists(), "socket should exist while running");

        let _ = shutdown_tx.send(true);
        let _ = proxy_task.await;

        assert!(
            !sock_path.exists(),
            "socket should be cleaned up after shutdown"
        );
    }

    /// Poll until the socket file appears (max 2 seconds).
    async fn wait_for_socket(path: &std::path::Path) {
        for _ in 0..200 {
            if path.exists() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("socket did not appear at {}", path.display());
    }
}
