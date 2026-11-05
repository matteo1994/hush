use std::collections::HashMap;
use std::io::{self, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ServerConnection, StreamOwned};

use crate::tls::Mitm;

mod http;
mod relay;
mod scrub;

#[cfg(fuzzing)]
pub mod fuzzing;

use http::{
    Head, connection_has, copy_body, header_value, parse_head, read_head, request_framing,
    resolve_target, split_host_port,
};
use relay::{Scrubbed, relay_response};
use scrub::Scrubber;

/// No `Debug`: this holds real values, which must never be printed.
#[derive(Clone)]
pub struct PlaceholderEntry {
    pub real_value: String,
    pub host: String,
    /// Required on a loopback upstream, where the child can listen on any
    /// port; compared wherever it is set.
    pub port: Option<u16>,
    pub header: String,
    pub format: String,
    pub allow_http: bool,
    /// Previous values to redact from responses. Substitution never sends
    /// these; only `real_value` is swapped in.
    pub retired: Vec<String>,
}

/// Placeholder → what to swap it for, and where. Fixed before the proxy starts.
pub type PlaceholderTable = HashMap<String, PlaceholderEntry>;

/// Read timeout on forwarded (non-tunnel) upstream connections, so a server
/// that goes silent mid-response can't pin a thread forever. Waiting between
/// requests on a kept-alive connection isn't a read and isn't limited by it.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(300);

/// Wait before accepting again after `accept` failed.
const ACCEPT_RETRY: Duration = Duration::from_millis(50);

type ClientTls = StreamOwned<ServerConnection, TcpStream>;
type UpstreamTls = StreamOwned<ClientConnection, TcpStream>;

/// Most distinct messages an `ErrorLog` keeps; later new ones are only counted.
const MAX_DISTINCT_ERRORS: usize = 8;

/// Connection errors, collected instead of printed: the proxy shares the
/// child's terminal, and a line written under a full-screen agent corrupts its
/// display. The run reports them once the child has exited.
#[derive(Default)]
pub struct ErrorLog {
    inner: Mutex<ErrorCounts>,
}

#[derive(Default)]
struct ErrorCounts {
    /// Distinct messages in first-seen order, with how often each occurred.
    seen: Vec<(String, usize)>,
    /// Errors dropped because `seen` was full.
    other: usize,
}

impl ErrorLog {
    fn record(&self, message: String) {
        let mut counts = self.inner.lock().unwrap();
        if let Some((_, n)) = counts.seen.iter_mut().find(|(m, _)| *m == message) {
            *n += 1;
        } else if counts.seen.len() < MAX_DISTINCT_ERRORS {
            counts.seen.push((message, 1));
        } else {
            counts.other += 1;
        }
    }

    /// One line per distinct error, or `None` if there were none.
    pub fn summary(&self) -> Option<String> {
        use std::fmt::Write as _;
        let counts = self.inner.lock().unwrap();
        let total = counts.seen.iter().map(|(_, n)| n).sum::<usize>() + counts.other;
        if total == 0 {
            return None;
        }
        let mut out = format!("{total} proxy connection error(s) during the run:");
        for (message, n) in &counts.seen {
            let _ = write!(out, "\n  {n}× {message}");
        }
        if counts.other > 0 {
            let _ = write!(out, "\n  {}× other errors", counts.other);
        }
        Some(out)
    }
}

pub fn start_proxy(table: PlaceholderTable, mitm: Arc<Mitm>, errors: Arc<ErrorLog>) -> Result<u16> {
    let table = Arc::new(table);
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    thread::spawn(move || {
        for stream in listener.incoming() {
            let client = match stream {
                Ok(client) => client,
                Err(e) => {
                    errors.record(format!("accepting a connection: {e}"));
                    // Out of file descriptors, say: this would fail again at once.
                    thread::sleep(ACCEPT_RETRY);
                    continue;
                }
            };
            let table = table.clone();
            let mitm = mitm.clone();
            let thread_errors = errors.clone();
            let handler = thread::Builder::new().spawn(move || {
                if let Err(e) = handle_connection(client, &table, &mitm) {
                    thread_errors.record(format!("{e:#}"));
                }
            });
            // `thread::spawn` would panic here, ending the proxy for the rest
            // of the run and printing over the child's screen.
            if let Err(e) = handler {
                errors.record(format!("starting a connection thread: {e}"));
            }
        }
    });

    Ok(port)
}

fn handle_connection(client: TcpStream, table: &PlaceholderTable, mitm: &Mitm) -> Result<()> {
    let mut client = BufReader::new(client);
    let Some(head) = read_head(&mut client)? else {
        return Ok(());
    };
    let mut req = parse_head(&head)?;

    if req.method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(&req.path, 443);
        let leftover = client.buffer().to_vec();
        return handle_connect(client.into_inner(), leftover, &host, port, table, mitm);
    }

    let (host, port, path) = resolve_target(&req.path, header_value(&req.headers, "host"))?;
    req.path = path;
    let upstream = TcpStream::connect((host.as_str(), port))?;
    upstream.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    let target = Target {
        host: &host,
        port,
        tls: false,
        peer: upstream.peer_addr()?,
        local: upstream.local_addr()?,
    };
    // One request per connection here: the next could name a different host.
    forward(
        &mut client,
        req,
        &target,
        table,
        &mut BufReader::new(upstream),
        Reuse::Close,
    )?;
    Ok(())
}

/// HTTPS via `CONNECT`. Hosts that some minted placeholder is bound to get
/// intercepted: TLS is terminated with a session-CA leaf for that host, the
/// requests are forwarded with placeholders swapped, over a verified TLS
/// connection to the real host. That upstream connection belongs to this
/// client connection alone and carries its requests one after another for as
/// long as both ends keep theirs open; it is never shared, so nothing a client
/// does to the framing can reach another client's responses. Every other host
/// gets a blind byte tunnel — hush never decrypts traffic it has no secret
/// for, and any placeholder in it goes out verbatim.
fn handle_connect(
    mut client: TcpStream,
    leftover: Vec<u8>,
    host: &str,
    port: u16,
    table: &PlaceholderTable,
    mitm: &Mitm,
) -> Result<()> {
    let upstream = match TcpStream::connect((host, port)) {
        Ok(s) => s,
        Err(e) => {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
            return Err(e).with_context(|| format!("connecting to {host}:{port}"));
        }
    };
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;

    let target = Target {
        host,
        port,
        tls: true,
        peer: upstream.peer_addr()?,
        local: upstream.local_addr()?,
    };
    if !is_bound(table, &target) {
        return tunnel(client, &leftover, upstream);
    }
    if !leftover.is_empty() {
        bail!("client sent data before CONNECT to {host} was established");
    }

    upstream.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    let server_name =
        ServerName::try_from(host.to_string()).with_context(|| format!("invalid host {host}"))?;
    let mut upstream = BufReader::new(StreamOwned::new(
        ClientConnection::new(mitm.upstream_config(), server_name)?,
        upstream,
    ));
    let mut client = BufReader::new(StreamOwned::new(
        ServerConnection::new(mitm.server_config(host)?)?,
        client,
    ));

    while let Some(head) = read_head(&mut client)? {
        let req = parse_head(&head)?;
        let reusable = forward(
            &mut client,
            req,
            &target,
            table,
            &mut upstream,
            Reuse::KeepAlive,
        )?;
        if !reusable || !wait_for_request(&mut client, &mut upstream) {
            break;
        }
    }

    client.get_mut().conn.send_close_notify();
    let _ = client.get_mut().flush();
    upstream.get_mut().conn.send_close_notify();
    let _ = upstream.get_mut().flush();
    Ok(())
}

/// Between requests on a kept-alive pair: blocks until the client has sent
/// something (`true`), or the upstream connection is no longer usable for
/// another request (`false`). Closing the client side as soon as the server
/// drops its idle connection is what the client would see without a proxy, and
/// what lets it retry on a fresh connection instead of sending into a dead one.
fn wait_for_request(
    client: &mut BufReader<ClientTls>,
    upstream: &mut BufReader<UpstreamTls>,
) -> bool {
    loop {
        // Already read off the socket, so no poll would ever report it.
        let decrypted = |tls: &mut ClientTls| {
            tls.conn
                .process_new_packets()
                .is_ok_and(|state| state.plaintext_bytes_to_read() > 0)
        };
        if !client.buffer().is_empty() || decrypted(client.get_mut()) {
            return true;
        }

        let pollfd = |fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let mut fds = [
            pollfd(upstream.get_ref().sock.as_raw_fd()),
            pollfd(client.get_ref().sock.as_raw_fd()),
        ];
        // SAFETY: `fds` is live for the call and its length is what's passed.
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) } < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
        if fds[0].revents != 0 {
            // Either the server is done with this connection, or it is TLS
            // housekeeping (a new session ticket, a key update), which leaves
            // the connection as usable as before.
            let tls = upstream.get_mut();
            let alive = matches!(tls.conn.read_tls(&mut tls.sock), Ok(n) if n > 0)
                && tls.conn.process_new_packets().is_ok_and(|state| {
                    !state.peer_has_closed() && state.plaintext_bytes_to_read() == 0
                });
            if !alive {
                return false;
            }
        } else if fds[1].revents != 0 {
            return true;
        }
    }
}

fn tunnel(mut client: TcpStream, leftover: &[u8], mut upstream: TcpStream) -> Result<()> {
    upstream.write_all(leftover)?;
    let mut client_read = client.try_clone()?;
    let mut upstream_write = upstream.try_clone()?;
    let up = thread::spawn(move || {
        let _ = io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut upstream, &mut client);
    let _ = client.shutdown(Shutdown::Write);
    let _ = up.join();
    Ok(())
}

/// Whether a connection pair may carry more than this one request.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reuse {
    KeepAlive,
    /// The request goes out with `Connection: close`.
    Close,
}

/// Forwards one request and relays its response. Returns whether both
/// connections are left at a message boundary and willing to carry another
/// request, which is only ever the case with `Reuse::KeepAlive`. Each request
/// gets its own substitution.
fn forward<C: Read + Write, U: Read + Write>(
    client: &mut BufReader<C>,
    req: Head,
    target: &Target,
    table: &PlaceholderTable,
    upstream: &mut BufReader<U>,
    reuse: Reuse,
) -> Result<bool> {
    let body = match request_framing(&req.headers) {
        Ok(body) => body,
        Err(e) => {
            // Nothing has gone upstream yet, and the client's next bytes can't
            // be trusted to start a request, so both connections end here.
            let _ = client.get_mut().write_all(
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            );
            let _ = client.get_mut().flush();
            return Err(e);
        }
    };
    let expects_continue = req.headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("expect") && v.trim().eq_ignore_ascii_case("100-continue")
    });
    let keep_alive =
        reuse == Reuse::KeepAlive && req.version == 1 && !connection_has(&req.headers, "close");

    let mut headers = req.headers;
    if names_only(&headers, &req.path, target.host) {
        substitute_placeholders(&mut headers, target, table);
    }
    headers.retain(|(k, _)| !HOP_BY_HOP.iter().any(|h| k.eq_ignore_ascii_case(h)));
    if !keep_alive {
        headers.push(("Connection".to_string(), "close".to_string()));
    }
    let scrubber = if is_bound(table, target) {
        // A missing Accept-Encoding means any coding is acceptable, so ask for
        // `identity` explicitly: a compressed response can't be scanned.
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("accept-encoding"));
        headers.push(("Accept-Encoding".to_string(), "identity".to_string()));
        Scrubber::new(real_values(table))
    } else {
        Scrubber::new(Vec::new())
    };

    let mut out = Vec::new();
    write!(out, "{} {} HTTP/1.1\r\n", req.method, req.path)?;
    for (k, v) in &headers {
        write!(out, "{k}: {v}\r\n")?;
    }
    out.extend_from_slice(b"\r\n");
    upstream.get_mut().write_all(&out)?;

    // `Expect` was stripped upstream, so answer it here or the client stalls
    // waiting before it sends the body.
    if expects_continue {
        client
            .get_mut()
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
        client.get_mut().flush()?;
    }
    copy_body(client, upstream.get_mut(), body)?;
    upstream.get_mut().flush()?;

    let mut out = Scrubbed {
        scrubber,
        out: client.get_mut(),
    };
    let open = relay_response(upstream, &mut out, &req.method)?;
    // Bytes past the response's end mean the two sides disagree on framing.
    Ok(keep_alive && open && upstream.buffer().is_empty())
}

/// Headers that only make sense for the client↔proxy hop.
const HOP_BY_HOP: &[&str] = &[
    "proxy-connection",
    "proxy-authorization",
    "connection",
    "keep-alive",
    "expect",
];

/// Whether everything in the request that names a host names `target_host`:
/// every `Host` header (at least one) and the authority of an absolute-form
/// request target. The connection goes to `target_host` either way, but a
/// server shared between sites, such as a CDN, routes on these, so a request
/// that names another site would carry the real value to that site's origin.
/// Such a request is forwarded as it came, placeholder included. Ports are
/// not compared, as for bindings.
fn names_only(headers: &[(String, String)], path: &str, target_host: &str) -> bool {
    let is_target = |authority: &str| {
        split_host_port(authority.trim(), 0)
            .0
            .eq_ignore_ascii_case(target_host)
    };
    let mut hosts = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.as_str())
        .peekable();
    if hosts.peek().is_none() || !hosts.all(is_target) {
        return false;
    }
    if path.starts_with('/') || path == "*" {
        return true;
    }
    path.split_once("://").is_some_and(|(_, rest)| {
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..end];
        // A URI's authority may carry userinfo; a `Host` header may not.
        is_target(authority.rsplit_once('@').map_or(authority, |(_, a)| a))
    })
}

/// Live values plus any still inside their grace period. The scrubber
/// redacts both, in every encoding it knows; substitution reads `real_value`
/// on its own, so this list is the only place a retired value meets the
/// response path.
fn real_values(table: &PlaceholderTable) -> Vec<String> {
    let mut values = Vec::new();
    for entry in table.values() {
        values.push(entry.real_value.clone());
        values.extend(entry.retired.iter().cloned());
    }
    values
}

/// Whether some placeholder may be swapped on the way to `target`. Only
/// such connections are intercepted, and only their responses scrubbed.
fn is_bound(table: &PlaceholderTable, target: &Target) -> bool {
    table.values().any(|e| target.matches(e))
}

/// Where a request is going, as the proxy connected to it.
struct Target<'a> {
    /// The name the request used.
    host: &'a str,
    port: u16,
    tls: bool,
    /// The address actually connected to.
    peer: SocketAddr,
    /// This end of that connection.
    local: SocketAddr,
}

impl Target<'_> {
    /// Whether the server is on this machine, where the child can listen
    /// too. Judged by the connection, not the name, so a bound name that
    /// resolves off-machine doesn't count. That covers loopback and every
    /// other address of this machine, such as its LAN address, which a
    /// connection to reaches through loopback with that same address on
    /// both ends.
    fn this_machine(&self) -> bool {
        let peer = self.peer.ip().to_canonical();
        peer.is_loopback() || peer == self.local.ip().to_canonical()
    }

    /// Plain HTTP off this machine: the request crosses the network unencrypted.
    fn cleartext(&self) -> bool {
        !self.tls && !self.this_machine()
    }

    fn matches(&self, entry: &PlaceholderEntry) -> bool {
        if self.this_machine() {
            // On this machine the child can listen on any port, and on the
            // other address family of a port, so only the exact socket the
            // binding names will do, whatever name the request used.
            return entry.port == Some(self.peer.port())
                && entry
                    .host
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| ip.to_canonical() == self.peer.ip().to_canonical());
        }
        self.host.eq_ignore_ascii_case(&entry.host)
            && entry.port.is_none_or(|port| port == self.port)
            && (!self.cleartext() || entry.allow_http)
    }
}

/// A `cleartext` request (plain HTTP off this machine) only gets the real
/// value for bindings that opted in with `allow_http`, and a loopback one only
/// for bindings that name the address and port connected to; otherwise the
/// placeholder goes out verbatim, as for any other non-matching request.
fn substitute_placeholders(
    headers: &mut [(String, String)],
    target: &Target,
    table: &PlaceholderTable,
) {
    for (name, value) in headers.iter_mut() {
        let mut replacement: Option<String> = None;
        for (placeholder, entry) in table.iter() {
            if !name.eq_ignore_ascii_case(&entry.header) || !target.matches(entry) {
                continue;
            }
            let expected = entry.format.replace("{value}", placeholder);
            if *value == expected {
                replacement = Some(entry.format.replace("{value}", &entry.real_value));
                break;
            }
        }
        if let Some(new_value) = replacement {
            *value = new_value;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};

    use super::http::{body_framing, copy_until_close, parse_response_head, response_framing};
    use super::scrub::tests::scrub_in_pieces;
    use super::*;

    const PLACEHOLDER: &str = "hush_ph_test";

    fn table_bound_to(host: &str) -> PlaceholderTable {
        table_with(host, false)
    }

    fn table_with(host: &str, allow_http: bool) -> PlaceholderTable {
        let (host, port) = crate::vault::split_host(host);
        let entry = PlaceholderEntry {
            real_value: "REAL".to_string(),
            host,
            port,
            header: "Authorization".to_string(),
            format: "Bearer {value}".to_string(),
            allow_http,
            retired: Vec::new(),
        };
        HashMap::from([(PLACEHOLDER.to_string(), entry)])
    }

    fn auth_headers() -> Vec<(String, String)> {
        vec![("authorization".to_string(), format!("Bearer {PLACEHOLDER}"))]
    }

    /// A target over TLS on another machine, as most are.
    fn remote(host: &str) -> Target<'_> {
        Target {
            host,
            port: 443,
            tls: true,
            peer: "203.0.113.7:443".parse().unwrap(),
            local: "198.51.100.2:50000".parse().unwrap(),
        }
    }

    fn swapped(table: &PlaceholderTable, target: &Target, headers: &[(String, String)]) -> String {
        let mut h = headers.to_vec();
        substitute_placeholders(&mut h, target, table);
        h[0].1.clone()
    }

    #[test]
    fn substitutes_only_for_bound_host() {
        let table = table_bound_to("api.example.com");
        assert_eq!(
            swapped(&table, &remote("API.example.com"), &auth_headers()),
            "Bearer REAL"
        );
        assert_eq!(
            swapped(&table, &remote("evil.example.com"), &auth_headers()),
            format!("Bearer {PLACEHOLDER}")
        );
    }

    #[test]
    fn substitutes_only_matching_header_and_format() {
        let table = table_bound_to("api.example.com");
        let target = remote("api.example.com");

        let h = vec![("X-Api-Key".to_string(), format!("Bearer {PLACEHOLDER}"))];
        assert_eq!(
            swapped(&table, &target, &h),
            format!("Bearer {PLACEHOLDER}")
        );

        let h = vec![("Authorization".to_string(), format!("Token {PLACEHOLDER}"))];
        assert_eq!(swapped(&table, &target, &h), format!("Token {PLACEHOLDER}"));
    }

    #[test]
    fn cleartext_swaps_only_with_allow_http() {
        let target = Target {
            tls: false,
            port: 80,
            ..remote("api.example.com")
        };
        for (allow_http, expected) in [
            (false, format!("Bearer {PLACEHOLDER}")),
            (true, "Bearer REAL".to_string()),
        ] {
            let table = table_with("api.example.com", allow_http);
            assert_eq!(
                swapped(&table, &target, &auth_headers()),
                expected,
                "allow_http={allow_http}"
            );
        }
    }

    #[test]
    fn a_port_in_the_binding_must_match() {
        let ph = format!("Bearer {PLACEHOLDER}");
        for (bound, expected) in [
            ("api.example.com", "Bearer REAL"),
            ("api.example.com:443", "Bearer REAL"),
            ("api.example.com:8443", ph.as_str()),
        ] {
            let got = swapped(
                &table_bound_to(bound),
                &remote("api.example.com"),
                &auth_headers(),
            );
            assert_eq!(got, expected, "bound={bound}");
        }
    }

    /// On this machine only the exact socket a binding names will do,
    /// whatever name the request used.
    #[test]
    fn loopback_binding_matches_only_the_socket_connected_to() {
        let ph = format!("Bearer {PLACEHOLDER}");
        let local = |host, peer: &str| Target {
            host,
            port: 3000,
            tls: false,
            peer: peer.parse().unwrap(),
            local: "127.0.0.1:50000".parse().unwrap(),
        };
        for (bound, target, expected) in [
            (
                "127.0.0.1:3000",
                local("localhost", "127.0.0.1:3000"),
                "Bearer REAL",
            ),
            (
                "127.0.0.1:3000",
                local("127.0.0.1", "127.0.0.1:3000"),
                "Bearer REAL",
            ),
            (
                "127.0.0.1:3000",
                local("localhost", "[::ffff:127.0.0.1]:3000"),
                "Bearer REAL",
            ),
            (
                "[::1]:3000",
                local("localhost", "[::1]:3000"),
                "Bearer REAL",
            ),
            (
                "127.0.0.1:3000",
                local("localhost", "[::1]:3000"),
                ph.as_str(),
            ),
            (
                "127.0.0.1:3000",
                local("localhost", "127.0.0.2:3000"),
                ph.as_str(),
            ),
            (
                "127.0.0.1:3000",
                local("localhost", "127.0.0.1:3001"),
                ph.as_str(),
            ),
            (
                "localhost:3000",
                local("localhost", "127.0.0.1:3000"),
                ph.as_str(),
            ),
            (
                "localhost",
                local("localhost", "127.0.0.1:3000"),
                ph.as_str(),
            ),
            // A name that resolves to this machine, bound with or without a port.
            (
                "api.example.com",
                local("api.example.com", "127.0.0.1:3000"),
                ph.as_str(),
            ),
            (
                "api.example.com:3000",
                local("api.example.com", "127.0.0.1:3000"),
                ph.as_str(),
            ),
        ] {
            let got = swapped(&table_bound_to(bound), &target, &auth_headers());
            assert_eq!(got, expected, "bound={bound} peer={}", target.peer);
        }
    }

    /// Another address of this machine, such as its LAN address, is as open
    /// to the child as loopback: a key bound to it without a port, or by a
    /// name, would go to whatever the child listens on there.
    #[test]
    fn another_address_of_this_machine_counts_as_loopback() {
        let ph = format!("Bearer {PLACEHOLDER}");
        let lan = |host| Target {
            host,
            port: 3000,
            tls: false,
            peer: "192.0.2.5:3000".parse().unwrap(),
            local: "192.0.2.5:50000".parse().unwrap(),
        };
        for (bound, target, expected) in [
            ("192.0.2.5:3000", lan("192.0.2.5"), "Bearer REAL"),
            ("192.0.2.5:3000", lan("mymac.local"), "Bearer REAL"),
            ("192.0.2.5", lan("192.0.2.5"), ph.as_str()),
            ("192.0.2.5:3001", lan("192.0.2.5"), ph.as_str()),
            ("mymac.local", lan("mymac.local"), ph.as_str()),
            ("mymac.local:3000", lan("mymac.local"), ph.as_str()),
        ] {
            let got = swapped(&table_with(bound, true), &target, &auth_headers());
            assert_eq!(got, expected, "bound={bound} host={}", target.host);
        }
    }

    /// Off this machine the binding is matched against the name the request
    /// used, and that same string is what gets resolved and, over TLS,
    /// verified. So the only spelling that may match is the bound name in
    /// another ASCII case; anything else fails closed.
    #[test]
    fn odd_spellings_of_a_bound_host_fail_closed() {
        let ph = format!("Bearer {PLACEHOLDER}");
        for (bound, authority, expected) in [
            ("api.example.com", "API.Example.COM:443", "Bearer REAL"),
            ("api.example.com", "api.example.com.:443", ph.as_str()),
            (
                "api.example.com",
                "api.example.com@evil.com:443",
                ph.as_str(),
            ),
            (
                "api.example.com",
                "evil.com@api.example.com:443",
                ph.as_str(),
            ),
            ("api.example.com", "api.example.com:443:443", ph.as_str()),
            ("api.example.com", "api.example.com:70000", ph.as_str()),
            ("api.example.com", "api.example.com%2e:443", ph.as_str()),
            ("api.example.com", " api.example.com:443", ph.as_str()),
            ("xn--bcher-kva.example", "bücher.example:443", ph.as_str()),
            ("bücher.example", "xn--bcher-kva.example:443", ph.as_str()),
            ("2001:db8::1", "[2001:db8::1]:443", "Bearer REAL"),
            ("[2001:db8::1]", "[2001:DB8::1]:443", "Bearer REAL"),
            ("2001:db8::1", "[2001:0db8::1]:443", ph.as_str()),
            // Unbracketed, the last group reads as a port: `2001:db8::`
            // port 1, which is also where the proxy would connect.
            ("2001:db8::1", "2001:db8::1", ph.as_str()),
            ("203.0.113.7", "203.0.113.7:443", "Bearer REAL"),
            ("203.0.113.7", "0xcb.0.113.7:443", ph.as_str()),
            ("203.0.113.7", "3405803783:443", ph.as_str()),
            ("203.0.113.7", "[::ffff:203.0.113.7]:443", ph.as_str()),
        ] {
            let (host, port) = split_host_port(authority, 443);
            let target = Target {
                port,
                ..remote(&host)
            };
            let got = swapped(&table_bound_to(bound), &target, &auth_headers());
            assert_eq!(got, expected, "bound={bound} authority={authority}");
        }
    }

    /// Plain HTTP takes the host from an absolute-form target or the `Host`
    /// header (`resolve_target`), and the request must name no other
    /// (`names_only`); odd spellings there fail closed too.
    #[test]
    fn odd_spellings_in_a_plain_http_request_fail_closed() {
        let ph = format!("Bearer {PLACEHOLDER}");
        let table = table_with("api.example.com", true);
        for (request_target, host_header, expected) in [
            (
                "http://API.example.com/v1",
                "api.example.com",
                "Bearer REAL",
            ),
            ("http://api.example.com", "api.example.com", "Bearer REAL"),
            // Not stripped as absolute-form, so the Host header picks the
            // host, and `names_only` checks the target names the same one.
            (
                "HTTP://api.example.com/v1",
                "api.example.com",
                "Bearer REAL",
            ),
            ("HTTP://evil.com/v1", "api.example.com", ph.as_str()),
            (
                "http://api.example.com./v1",
                "api.example.com.",
                ph.as_str(),
            ),
            (
                "http://api.example.com@evil.com/v1",
                "evil.com",
                ph.as_str(),
            ),
            (
                "http://evil.com@api.example.com/v1",
                "api.example.com",
                ph.as_str(),
            ),
            (
                "http://api.example.com:80:80/v1",
                "api.example.com",
                ph.as_str(),
            ),
            (
                "http://api.example.com?@evil.com/",
                "api.example.com",
                ph.as_str(),
            ),
            (
                "http://api.example.com#@evil.com/",
                "api.example.com",
                ph.as_str(),
            ),
            ("http://api.example.com/v1", "evil.com", ph.as_str()),
            ("/v1", "api.example.com.", ph.as_str()),
            ("/v1", "api.example.com:80:80", ph.as_str()),
            ("/v1", "api.example.com@evil.com", ph.as_str()),
        ] {
            let mut headers = vec![("Host".to_string(), host_header.to_string())];
            headers.extend(auth_headers());
            // As `handle_connection` and `forward` do.
            let (host, port, path) = resolve_target(request_target, Some(host_header)).unwrap();
            let target = Target {
                port,
                tls: false,
                ..remote(&host)
            };
            if names_only(&headers, &path, target.host) {
                substitute_placeholders(&mut headers, &target, &table);
            }
            assert_eq!(
                headers[1].1, expected,
                "target={request_target} host={host_header}"
            );
        }
    }

    #[test]
    fn a_retired_value_is_scrubbed_and_never_substituted() {
        let mut table = table_bound_to("api.example.com");
        table.get_mut(PLACEHOLDER).unwrap().retired = vec!["OLD-SECRET".into()];
        let sent = swapped(&table, &remote("api.example.com"), &auth_headers());
        assert_eq!(sent, "Bearer REAL");

        // The child sending the old bytes itself is not hush injecting them.
        let mut headers = vec![("authorization".into(), "Bearer OLD-SECRET".into())];
        substitute_placeholders(&mut headers, &remote("api.example.com"), &table);
        assert_eq!(headers[0].1, "Bearer OLD-SECRET");

        // Redacted like a live value, encoded forms included.
        let values = real_values(&table);
        let refs: Vec<&str> = values.iter().map(String::as_str).collect();
        let echo = "echo OLD-SECRET, REAL and T0xELVNFQ1JFVA==";
        let redacted = scrub_in_pieces(&refs, &[echo]);
        assert!(!redacted.contains("OLD-SECRET"), "{redacted}");
        assert!(!redacted.contains("REAL"), "{redacted}");
        assert!(!redacted.contains("T0xELVNFQ1JFVA=="), "{redacted}");
        assert!(redacted.contains("HUSH"), "{redacted}");
    }

    #[test]
    fn error_log_counts_repeats_and_caps_distinct_messages() {
        let log = ErrorLog::default();
        assert_eq!(log.summary(), None);

        for _ in 0..3 {
            log.record("connecting to a:443: no route".to_string());
        }
        for i in 0..MAX_DISTINCT_ERRORS + 1 {
            log.record(format!("error {i}"));
        }
        let summary = log.summary().unwrap();
        assert!(summary.starts_with(&format!("{} proxy", MAX_DISTINCT_ERRORS + 4)));
        assert!(summary.contains("\n  3× connecting to a:443: no route"));
        assert!(summary.contains("\n  1× error 0"));
        assert!(summary.ends_with("\n  2× other errors"), "{summary}");
    }

    #[test]
    fn ambiguous_request_gets_400_and_never_reaches_the_upstream() {
        let up = spawn_upstream(true);
        let (proxy, mitm) = start(
            table_bound_to(&format!("127.0.0.1:{}", up.port)),
            &[&up.cert],
        );

        let (tcp, _) = connect(proxy, &format!("localhost:{}", up.port));
        let request = chunked_post().replacen(
            "Transfer-Encoding",
            "Content-Length: 5\r\nTransfer-Encoding",
            1,
        );
        let resp = roundtrip(&mut tls_client(tcp, mitm.ca_der()), &request);

        assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
        assert_eq!(received(&up), None, "upstream must not get a request");
    }

    #[test]
    fn names_only_checks_every_host_header_and_an_absolute_target() {
        let h = |values: &[&str]| -> Vec<(String, String)> {
            values
                .iter()
                .map(|v| ("Host".to_string(), v.to_string()))
                .collect()
        };
        let api = "api.example.com";

        assert!(names_only(&h(&[api]), "/v1", api));
        assert!(names_only(&h(&["API.example.com:8443"]), "*", api));
        assert!(names_only(&h(&["[::1]:8443"]), "/", "::1"));
        assert!(names_only(&h(&[api]), "https://api.example.com/v1", api));
        assert!(names_only(
            &h(&[api]),
            "http://u:p@api.example.com:80?x",
            api
        ));

        assert!(!names_only(&[], "/v1", api));
        assert!(!names_only(&h(&["evil.example.com"]), "/v1", api));
        assert!(!names_only(&h(&[api, "evil.example.com"]), "/v1", api));
        assert!(!names_only(&h(&["api.example.com.evil.com"]), "/v1", api));
        assert!(!names_only(&h(&["api.example.com@evil.com"]), "/v1", api));
        assert!(!names_only(&h(&[api]), "https://evil.example.com/v1", api));
        assert!(!names_only(&h(&["evil.com@api.example.com"]), "/v1", api));
        assert!(!names_only(
            &h(&[api]),
            "https://api.example.com@evil.com/",
            api
        ));
        assert!(!names_only(&h(&[api]), "evil.example.com/v1", api));
    }

    /// A one-shot upstream for `localhost`, plain or TLS. It answers a single
    /// request by echoing back the raw head and body it received, and reports
    /// the same through `received` — or `None` if no request ever arrived.
    struct Upstream {
        port: u16,
        cert: CertificateDer<'static>,
        received: std::sync::mpsc::Receiver<Option<String>>,
    }

    /// A self-signed TLS identity for `localhost`.
    fn localhost_tls() -> (Arc<ServerConfig>, CertificateDer<'static>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cert_der = cert.der().clone();
        let cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert_der.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        (Arc::new(cfg), cert_der)
    }

    fn spawn_upstream(tls: bool) -> Upstream {
        let (cfg, cert_der) = localhost_tls();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, received) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let result = if tls {
                let mut s = StreamOwned::new(ServerConnection::new(cfg).unwrap(), tcp);
                let r = echo_one(&mut s);
                s.conn.send_close_notify();
                let _ = s.flush();
                r
            } else {
                let mut s = tcp;
                echo_one(&mut s)
            };
            let _ = tx.send(result.ok());
        });
        Upstream {
            port,
            cert: cert_der,
            received,
        }
    }

    fn echo_one<S: Read + Write>(s: &mut S) -> Result<String> {
        let mut src = BufReader::new(&mut *s);
        let head = read_head(&mut src)?.context("no request")?;
        let req = parse_head(&head)?;
        let mut body = Vec::new();
        copy_body(&mut src, &mut body, body_framing(&req.headers)?)?;
        let seen = format!(
            "{}{}",
            String::from_utf8_lossy(&head),
            String::from_utf8_lossy(&body)
        );
        write!(
            s,
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{seen}",
            seen.len()
        )?;
        s.flush()?;
        Ok(seen)
    }

    fn received(up: &Upstream) -> Option<String> {
        up.received.recv_timeout(Duration::from_secs(5)).unwrap()
    }

    /// A TLS upstream for `localhost` that leaves its connections open. Every
    /// request is echoed back and reported through `seen`, with the index of
    /// the connection it arrived on. A path containing `chunked` gets a
    /// chunked response; one containing `then-close` is the last on its
    /// connection, without the response saying so.
    struct KeepAliveUpstream {
        port: u16,
        cert: CertificateDer<'static>,
        seen: std::sync::mpsc::Receiver<(usize, String)>,
    }

    fn spawn_keep_alive_upstream() -> KeepAliveUpstream {
        let (cfg, cert) = localhost_tls();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, seen) = std::sync::mpsc::channel();
        thread::spawn(move || {
            for (index, tcp) in listener.incoming().enumerate() {
                let (cfg, tx) = (cfg.clone(), tx.clone());
                thread::spawn(move || {
                    let tls = StreamOwned::new(ServerConnection::new(cfg).unwrap(), tcp.unwrap());
                    let mut s = BufReader::new(tls);
                    while let Ok(Some(seen)) = echo_and_stay_open(&mut s) {
                        let last = seen.contains("then-close");
                        let _ = tx.send((index, seen));
                        if last {
                            break;
                        }
                    }
                    s.get_mut().conn.send_close_notify();
                    let _ = s.get_mut().flush();
                });
            }
        });
        KeepAliveUpstream { port, cert, seen }
    }

    fn echo_and_stay_open<S: Read + Write>(s: &mut BufReader<S>) -> Result<Option<String>> {
        let Some(head) = read_head(s)? else {
            return Ok(None);
        };
        let req = parse_head(&head)?;
        let mut body = Vec::new();
        copy_body(s, &mut body, body_framing(&req.headers)?)?;
        let seen = format!(
            "{}{}",
            String::from_utf8_lossy(&head),
            String::from_utf8_lossy(&body)
        );
        let out = s.get_mut();
        if req.method == "HEAD" {
            write!(
                out,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                seen.len()
            )?;
        } else if req.path.contains("chunked") {
            let (a, b) = seen.split_at(seen.len() / 2);
            write!(
                out,
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                 {:x}\r\n{a}\r\n{:x}\r\n{b}\r\n0\r\n\r\n",
                a.len(),
                b.len()
            )?;
        } else {
            write!(
                out,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{seen}",
                seen.len()
            )?;
        }
        out.flush()?;
        Ok(Some(seen))
    }

    fn seen(up: &KeepAliveUpstream) -> (usize, String) {
        up.seen.recv_timeout(Duration::from_secs(5)).unwrap()
    }

    /// Starts a proxy whose upstream TLS trusts only `upstream_roots`.
    fn start(
        table: PlaceholderTable,
        upstream_roots: &[&CertificateDer<'static>],
    ) -> (u16, Arc<Mitm>) {
        let mut roots = RootCertStore::empty();
        for cert in upstream_roots {
            roots.add((*cert).clone()).unwrap();
        }
        let mitm = Arc::new(Mitm::new(roots).unwrap());
        let port = start_proxy(table, mitm.clone(), Arc::default()).unwrap();
        (port, mitm)
    }

    /// Sends `CONNECT authority` and returns the tunnel plus the proxy's status line.
    fn connect(proxy_port: u16, authority: &str) -> (TcpStream, String) {
        let mut tcp = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        write!(
            tcp,
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
        )
        .unwrap();
        // So that a response that never comes fails a test instead of hanging it.
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let head = read_head(&mut BufReader::new(&tcp)).unwrap().unwrap();
        let status = String::from_utf8_lossy(&head)
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        (tcp, status)
    }

    /// TLS client over `tcp`, verifying the server as `localhost` against `trust` only.
    fn tls_client(
        tcp: TcpStream,
        trust: &CertificateDer<'static>,
    ) -> StreamOwned<ClientConnection, TcpStream> {
        let mut roots = RootCertStore::empty();
        roots.add(trust.clone()).unwrap();
        let cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let conn = ClientConnection::new(Arc::new(cfg), ServerName::try_from("localhost").unwrap())
            .unwrap();
        StreamOwned::new(conn, tcp)
    }

    fn roundtrip<S: Read + Write>(s: &mut S, request: &str) -> String {
        s.write_all(request.as_bytes()).unwrap();
        let mut resp = Vec::new();
        let _ = copy_until_close(s, &mut resp);
        String::from_utf8_lossy(&resp).into_owned()
    }

    /// Sends `request` and reads exactly one response, leaving the connection open.
    fn exchange<S: Read + Write>(s: &mut BufReader<S>, method: &str, request: &str) -> String {
        s.get_mut().write_all(request.as_bytes()).unwrap();
        let head = read_head(s).unwrap().expect("no response");
        let resp = parse_response_head(&head).unwrap();
        let mut body = Vec::new();
        copy_body(s, &mut body, response_framing(method, &resp)).unwrap();
        format!(
            "{}{}",
            String::from_utf8_lossy(&head),
            String::from_utf8_lossy(&body)
        )
    }

    fn get(path: &str) -> String {
        format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n"
        )
    }

    fn chunked_post() -> String {
        format!(
            "POST /v1 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\
             Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        )
    }

    #[test]
    fn https_to_bound_host_is_intercepted_and_swapped() {
        let up = spawn_upstream(true);
        let (proxy, mitm) = start(
            table_bound_to(&format!("127.0.0.1:{}", up.port)),
            &[&up.cert],
        );

        let (tcp, status) = connect(proxy, &format!("localhost:{}", up.port));
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        let resp = roundtrip(&mut tls_client(tcp, mitm.ca_der()), &chunked_post());

        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        let seen = received(&up).unwrap();
        assert!(seen.contains("Authorization: Bearer REAL\r\n"), "{seen}");
        assert!(seen.ends_with("5\r\nhello\r\n0\r\n\r\n"), "{seen}");
        // The upstream echoes the swapped header back; the child must not see it.
        assert!(resp.contains("Authorization: Bearer HUSH\r\n"), "{resp}");
        assert!(!resp.contains("REAL"), "{resp}");
    }

    #[test]
    fn bound_host_is_asked_for_an_uncompressed_response() {
        let up = spawn_upstream(true);
        let (proxy, mitm) = start(
            table_bound_to(&format!("127.0.0.1:{}", up.port)),
            &[&up.cert],
        );

        let (tcp, _) = connect(proxy, &format!("localhost:{}", up.port));
        let request = chunked_post().replacen(
            "Transfer-Encoding",
            "Accept-Encoding: gzip, br\r\nTransfer-Encoding",
            1,
        );
        roundtrip(&mut tls_client(tcp, mitm.ca_der()), &request);

        let seen = received(&up).unwrap().to_ascii_lowercase();
        assert!(seen.contains("accept-encoding: identity\r\n"), "{seen}");
        assert!(!seen.contains("gzip"), "{seen}");
    }

    #[test]
    fn https_to_unbound_host_is_tunneled_untouched() {
        let up = spawn_upstream(true);
        let (proxy, _mitm) = start(table_bound_to("api.example.com"), &[&up.cert]);

        // Not intercepted: the client completes TLS with the real upstream itself.
        let (tcp, _) = connect(proxy, &format!("localhost:{}", up.port));
        roundtrip(&mut tls_client(tcp, &up.cert), &chunked_post());

        let seen = received(&up).unwrap();
        assert!(
            seen.contains(&format!("Authorization: Bearer {PLACEHOLDER}\r\n")),
            "{seen}"
        );
    }

    #[test]
    fn connect_to_another_loopback_socket_is_tunneled_untouched() {
        let up = spawn_upstream(true);
        // Bound to the same port on the other address family: the server the
        // proxy reaches isn't the bound one, whatever the request calls it.
        let (proxy, _mitm) = start(table_bound_to(&format!("[::1]:{}", up.port)), &[&up.cert]);

        let (tcp, _) = connect(proxy, &format!("127.0.0.1:{}", up.port));
        roundtrip(&mut tls_client(tcp, &up.cert), &chunked_post());

        let seen = received(&up).unwrap();
        assert!(
            seen.contains(&format!("Authorization: Bearer {PLACEHOLDER}\r\n")),
            "{seen}"
        );
        assert!(!seen.contains("REAL"), "{seen}");
    }

    /// The upstream stands in for a CDN that routes on what the request
    /// itself names: the key must not go out under another site's name.
    #[test]
    fn request_naming_another_host_is_not_swapped() {
        let post = chunked_post();
        for (case, request) in [
            (
                "other Host",
                post.replacen("Host: localhost", "Host: attacker.example", 1),
            ),
            (
                "second Host",
                post.replacen(
                    "Host: localhost",
                    "Host: localhost\r\nHost: attacker.example",
                    1,
                ),
            ),
            ("no Host", post.replacen("Host: localhost\r\n", "", 1)),
            (
                "absolute-form target",
                post.replacen("/v1", "https://attacker.example/v1", 1),
            ),
        ] {
            let up = spawn_upstream(true);
            let (proxy, mitm) = start(
                table_bound_to(&format!("127.0.0.1:{}", up.port)),
                &[&up.cert],
            );

            let (tcp, _) = connect(proxy, &format!("localhost:{}", up.port));
            roundtrip(&mut tls_client(tcp, mitm.ca_der()), &request);

            let seen = received(&up).unwrap();
            assert!(
                seen.contains(&format!("Authorization: Bearer {PLACEHOLDER}\r\n")),
                "{case}: {seen}"
            );
            assert!(!seen.contains("REAL"), "{case}: {seen}");
        }
    }

    #[test]
    fn request_naming_the_bound_host_in_any_form_is_swapped() {
        let post = chunked_post();
        for (case, request) in [
            (
                "Host with port and other case",
                post.replacen("Host: localhost", "Host: LOCALHOST:8443", 1),
            ),
            (
                "absolute-form target",
                post.replacen("/v1", "https://user@localhost:8443/v1", 1),
            ),
        ] {
            let up = spawn_upstream(true);
            let (proxy, mitm) = start(
                table_bound_to(&format!("127.0.0.1:{}", up.port)),
                &[&up.cert],
            );

            let (tcp, _) = connect(proxy, &format!("localhost:{}", up.port));
            roundtrip(&mut tls_client(tcp, mitm.ca_der()), &request);

            let seen = received(&up).unwrap();
            assert!(
                seen.contains("Authorization: Bearer REAL\r\n"),
                "{case}: {seen}"
            );
        }
    }

    #[test]
    fn plain_http_with_a_host_header_naming_another_host_is_not_swapped() {
        let up = spawn_upstream(false);
        let (proxy, _mitm) = start(table_bound_to(&format!("127.0.0.1:{}", up.port)), &[]);

        let mut tcp = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
        let request = chunked_post()
            .replacen("/v1", &format!("http://localhost:{}/v1", up.port), 1)
            .replacen("Host: localhost", "Host: attacker.example", 1);
        roundtrip(&mut tcp, &request);

        let seen = received(&up).unwrap();
        assert!(
            seen.contains(&format!("Authorization: Bearer {PLACEHOLDER}\r\n")),
            "{seen}"
        );
        assert!(!seen.contains("REAL"), "{seen}");
    }

    #[test]
    fn untrusted_upstream_never_receives_the_secret() {
        let up = spawn_upstream(true);
        let unrelated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        // The proxy trusts some other cert, so the upstream fails verification.
        let (proxy, mitm) = start(
            table_bound_to(&format!("127.0.0.1:{}", up.port)),
            &[unrelated.cert.der()],
        );

        let (tcp, _) = connect(proxy, &format!("localhost:{}", up.port));
        let resp = roundtrip(&mut tls_client(tcp, mitm.ca_der()), &chunked_post());

        assert_eq!(resp, "");
        assert_eq!(received(&up), None, "upstream must not get a request");
    }

    #[test]
    fn https_content_length_body_with_expect_continue_and_hop_by_hop_stripped() {
        let up = spawn_upstream(true);
        let (proxy, mitm) = start(
            table_bound_to(&format!("127.0.0.1:{}", up.port)),
            &[&up.cert],
        );
        let (tcp, _) = connect(proxy, &format!("localhost:{}", up.port));
        let mut tls = tls_client(tcp, mitm.ca_der());

        write!(
            tls,
            "PUT /v1 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\
             Proxy-Authorization: Basic cHJveHk=\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\n\
             Expect: 100-continue\r\nContent-Length: 5\r\n\r\n"
        )
        .unwrap();
        let mut tls = BufReader::new(tls);
        let interim = read_head(&mut tls).unwrap().unwrap();
        assert!(interim.starts_with(b"HTTP/1.1 100 Continue"));
        let resp = roundtrip(tls.get_mut(), "hello");
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");

        let seen = received(&up).unwrap().to_ascii_lowercase();
        assert!(seen.contains("authorization: bearer real\r\n"), "{seen}");
        assert!(seen.ends_with("\r\n\r\nhello"), "{seen}");
        for stripped in ["proxy-authorization", "keep-alive", "expect", "connection"] {
            assert!(
                !seen.contains(stripped),
                "{stripped} leaked upstream: {seen}"
            );
        }
    }

    #[test]
    fn intercepted_connection_carries_several_requests_over_one_upstream_connection() {
        let up = spawn_keep_alive_upstream();
        let (proxy, mitm) = start(
            table_bound_to(&format!("127.0.0.1:{}", up.port)),
            &[&up.cert],
        );
        let (tcp, _) = connect(proxy, &format!("localhost:{}", up.port));
        let mut tls = BufReader::new(tls_client(tcp, mitm.ca_der()));

        let requests = [
            ("GET", get("/length")),
            ("HEAD", get("/head").replacen("GET", "HEAD", 1)),
            ("POST", chunked_post().replacen("/v1", "/chunked", 1)),
            ("GET", get("/last")),
        ];
        for (method, request) in &requests {
            let resp = exchange(&mut tls, method, request);
            assert!(resp.starts_with("HTTP/1.1 200"), "{method}: {resp}");

            let (connection, seen) = seen(&up);
            assert_eq!(connection, 0, "{method} went out on a new connection");
            // Swapped on every request, not only the first.
            assert!(seen.contains("Authorization: Bearer REAL\r\n"), "{seen}");
            assert!(!seen.to_ascii_lowercase().contains("connection:"), "{seen}");
            match *method {
                "HEAD" => assert!(resp.ends_with("\r\n\r\n"), "{resp}"),
                // The echo quotes the real value; the scrubber still applies.
                "GET" => assert!(resp.contains("Bearer HUSH") && !resp.contains("REAL")),
                _ => assert!(resp.ends_with("0\r\n\r\n"), "{resp}"),
            }
        }
    }

    #[test]
    fn client_asking_to_close_ends_both_connections() {
        let up = spawn_keep_alive_upstream();
        let (proxy, mitm) = start(
            table_bound_to(&format!("127.0.0.1:{}", up.port)),
            &[&up.cert],
        );
        let (tcp, _) = connect(proxy, &format!("localhost:{}", up.port));

        // The upstream would keep going, so reading to the end only returns
        // because the proxy closes.
        let request = get("/once").replacen("\r\n\r\n", "\r\nConnection: close\r\n\r\n", 1);
        let resp = roundtrip(&mut tls_client(tcp, mitm.ca_der()), &request);
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(seen(&up).1.contains("Connection: close\r\n"));
    }

    #[test]
    fn upstream_dropping_an_idle_connection_closes_the_client_side() {
        let up = spawn_keep_alive_upstream();
        let (proxy, mitm) = start(
            table_bound_to(&format!("127.0.0.1:{}", up.port)),
            &[&up.cert],
        );
        let (tcp, _) = connect(proxy, &format!("localhost:{}", up.port));
        let mut tls = BufReader::new(tls_client(tcp, mitm.ca_der()));

        let resp = exchange(&mut tls, "GET", &get("/then-close"));
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        // Nothing in the response announced it; the client learns from the
        // connection itself, as it would without a proxy.
        let mut rest = Vec::new();
        copy_until_close(&mut tls, &mut rest).unwrap();
        assert!(rest.is_empty());
    }

    #[test]
    fn plain_http_swaps_only_for_bound_host() {
        for (bound, expected) in [
            ("localhost", "Bearer REAL"),
            ("api.example.com", "Bearer hush_ph_test"),
        ] {
            let up = spawn_upstream(false);
            let bound = if bound == "localhost" {
                format!("127.0.0.1:{}", up.port)
            } else {
                bound.to_string()
            };
            let (proxy, _mitm) = start(table_bound_to(&bound), &[]);

            let mut tcp = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
            let request =
                chunked_post().replacen("/v1", &format!("http://localhost:{}/v1", up.port), 1);
            let resp = roundtrip(&mut tcp, &request);
            assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");

            assert!(!resp.contains("REAL"), "{resp}");

            let seen = received(&up).unwrap();
            assert!(seen.starts_with("POST /v1 HTTP/1.1\r\n"), "{seen}");
            assert!(
                seen.contains(&format!("Authorization: {expected}\r\n")),
                "bound={bound}: {seen}"
            );
            assert!(seen.ends_with("5\r\nhello\r\n0\r\n\r\n"), "{seen}");
        }
    }

    /// The child can't listen on the bound host's other ports anywhere but
    /// on this machine, where every port is open to it.
    #[test]
    fn loopback_key_goes_only_to_the_bound_port() {
        let dev_server = TcpListener::bind("127.0.0.1:0").unwrap();
        let dev_port = dev_server.local_addr().unwrap().port();
        for (bound, expected) in [
            ("localhost".to_string(), format!("Bearer {PLACEHOLDER}")),
            (
                format!("127.0.0.1:{dev_port}"),
                format!("Bearer {PLACEHOLDER}"),
            ),
        ] {
            let childs_listener = spawn_upstream(false);
            let (proxy, _mitm) = start(table_bound_to(&bound), &[]);

            let mut tcp = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
            let request = chunked_post().replacen(
                "/v1",
                &format!("http://localhost:{}/v1", childs_listener.port),
                1,
            );
            roundtrip(&mut tcp, &request);

            let seen = received(&childs_listener).unwrap();
            assert!(
                seen.contains(&format!("Authorization: {expected}\r\n")),
                "bound={bound}: {seen}"
            );
        }
    }

    /// `localhost` names two sockets per port, `127.0.0.1` and `::1`. With
    /// the dev server on one, the child can listen on the other.
    #[test]
    fn loopback_key_goes_only_to_the_address_its_binding_names() {
        let dev_server = spawn_upstream(false);
        let Ok(childs_listener) = TcpListener::bind(("::1", dev_server.port)) else {
            eprintln!("no IPv6 loopback here; skipping");
            return;
        };
        let (tx, childs) = std::sync::mpsc::channel();
        thread::spawn(move || {
            if let Ok((mut s, _)) = childs_listener.accept() {
                let _ = tx.send(echo_one(&mut s).ok());
            }
        });
        let (proxy, _mitm) = start(
            table_bound_to(&format!("127.0.0.1:{}", dev_server.port)),
            &[],
        );

        let mut tcp = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
        let request = chunked_post().replacen(
            "/v1",
            &format!("http://localhost:{}/v1", dev_server.port),
            1,
        );
        roundtrip(&mut tcp, &request);

        let child_saw = childs.recv_timeout(Duration::from_secs(1)).ok().flatten();
        assert!(
            !child_saw.as_deref().unwrap_or("").contains("REAL"),
            "the child's [::1] listener got the key: {child_saw:?}"
        );
    }

    /// This machine's LAN address, where the child can listen on any port
    /// too: the key goes only to the address and port a binding names, and
    /// there without `allow_http`, as the request never leaves the machine.
    #[test]
    fn key_bound_to_this_machines_lan_address_needs_its_port() {
        // The address a packet off this machine would leave from; nothing
        // is sent.
        let lan = std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|s| s.connect("192.0.2.1:9").map(|_| s))
            .and_then(|s| s.local_addr())
            .map(|a| a.ip());
        let Ok(lan) = lan.map(|ip| ip.to_string()) else {
            eprintln!("no LAN address here; skipping");
            return;
        };
        for with_port in [false, true] {
            let listener = TcpListener::bind((lan.as_str(), 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let (tx, seen) = std::sync::mpsc::channel();
            thread::spawn(move || {
                if let Ok((mut s, _)) = listener.accept() {
                    let _ = tx.send(echo_one(&mut s).ok());
                }
            });
            let (table, expected) = if with_port {
                (table_with(&format!("{lan}:{port}"), false), "REAL")
            } else {
                (table_with(&lan, true), PLACEHOLDER)
            };
            let (proxy, _mitm) = start(table, &[]);

            let mut tcp = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
            let request = chunked_post()
                .replacen("/v1", &format!("http://{lan}:{port}/v1"), 1)
                .replacen("Host: localhost", &format!("Host: {lan}:{port}"), 1);
            roundtrip(&mut tcp, &request);

            let seen = seen.recv_timeout(Duration::from_secs(1)).ok().flatten();
            let seen = seen.expect("the request reached the listener");
            assert!(
                seen.contains(&format!("Authorization: Bearer {expected}\r\n")),
                "with_port={with_port}, listener on {lan}: {seen}"
            );
        }
    }

    /// A server that answers one request with `response`, every `{auth}`
    /// in it replaced by the `Authorization` value it received, sent a few
    /// bytes at a time, then closes.
    fn spawn_echoing(response: String) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let Ok((mut s, _)) = listener.accept() else {
                return;
            };
            let mut src = BufReader::new(s.try_clone().unwrap());
            let Ok(Some(head)) = read_head(&mut src) else {
                return;
            };
            let req = parse_head(&head).unwrap();
            let auth = header_value(&req.headers, "authorization").unwrap_or("");
            for piece in response.replace("{auth}", auth).as_bytes().chunks(7) {
                if s.write_all(piece).is_err() {
                    return;
                }
                let _ = s.flush();
            }
        });
        port
    }

    /// Every way a response can reach the client goes through the Scrubber:
    /// a server that echoes the swapped-in key back, in any part of any
    /// response, only ever shows the client the marker.
    #[test]
    fn every_response_path_is_scrubbed() {
        let big = "x".repeat(16 * 1024 - 5);
        let big_body = format!("{big}{{auth}}");
        let cases = [
            ("headers", "GET", "HTTP/1.1 200 OK\r\nX-Echo: {auth}\r\nContent-Length: 0\r\n\r\n".to_string()),
            (
                "content-length body across the copy buffer",
                "GET",
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{big_body}", big.len() + 11),
            ),
            (
                "chunked body and trailer",
                "GET",
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nb\r\n{auth}\r\n0\r\nX-Echo: {auth}\r\n\r\n".to_string(),
            ),
            (
                "interim response",
                "GET",
                "HTTP/1.1 103 Early Hints\r\nX-Echo: {auth}\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{auth}".to_string(),
            ),
            (
                "101 and what follows",
                "GET",
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\nConnection: upgrade\r\nX-Echo: {auth}\r\n\r\n{auth}".to_string(),
            ),
            ("close-delimited body", "GET", "HTTP/1.1 200 OK\r\n\r\n{auth}".to_string()),
            ("HTTP/1.0 body", "GET", "HTTP/1.0 200 OK\r\nX-Echo: {auth}\r\n\r\n{auth}".to_string()),
            (
                "unparsable head",
                "GET",
                "HTTP/1.1 2x0 Odd\r\nX-Echo: {auth}\r\n\r\n{auth}".to_string(),
            ),
            (
                "invalid content-length",
                "GET",
                "HTTP/1.1 200 OK\r\nContent-Length: eleven\r\n\r\n{auth}".to_string(),
            ),
            (
                "HEAD answered with a body",
                "HEAD",
                "HTTP/1.1 200 OK\r\nX-Echo: {auth}\r\nContent-Length: 11\r\n\r\n{auth}".to_string(),
            ),
            (
                "304 with a body",
                "GET",
                "HTTP/1.1 304 Not Modified\r\nX-Echo: {auth}\r\n\r\n{auth}".to_string(),
            ),
        ];
        for (name, method, response) in cases {
            let port = spawn_echoing(response);
            let (proxy, _mitm) = start(table_bound_to(&format!("127.0.0.1:{port}")), &[]);

            let mut tcp = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
            let request = format!(
                "{method} http://127.0.0.1:{port}/v1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
                 Authorization: Bearer {PLACEHOLDER}\r\n\r\n"
            );
            let resp = roundtrip(&mut tcp, &request);

            assert!(!resp.contains("REAL"), "{name}: {resp}");
            if name == "unparsable head" {
                assert!(resp.starts_with("HTTP/1.1 502"), "{name}: {resp}");
                assert!(!resp.contains("2x0"), "{name}: {resp}");
                continue;
            }
            assert!(resp.contains("Bearer HUSH"), "{name}: no echo seen: {resp}");
        }
    }

    #[test]
    fn loopback_key_goes_to_the_port_its_binding_names() {
        let dev_server = spawn_upstream(false);
        let (proxy, _mitm) = start(
            table_bound_to(&format!("127.0.0.1:{}", dev_server.port)),
            &[],
        );

        let mut tcp = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
        let request = chunked_post().replacen(
            "/v1",
            &format!("http://localhost:{}/v1", dev_server.port),
            1,
        );
        roundtrip(&mut tcp, &request);

        let seen = received(&dev_server).unwrap();
        assert!(seen.contains("Authorization: Bearer REAL\r\n"), "{seen}");
    }

    #[test]
    fn connect_to_unreachable_host_returns_502() {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let (proxy, _mitm) = start(table_bound_to("localhost"), &[]);
        let (_, status) = connect(proxy, &format!("127.0.0.1:{port}"));
        assert!(status.starts_with("HTTP/1.1 502"), "{status}");
    }
}
