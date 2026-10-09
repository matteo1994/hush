use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ServerConnection, StreamOwned};

use crate::tls::Mitm;

#[derive(Debug, Clone)]
pub struct PlaceholderEntry {
    pub real_value: String,
    pub host: String,
    pub header: String,
    pub format: String,
    pub allow_http: bool,
}

pub type PlaceholderTable = Arc<Mutex<HashMap<String, PlaceholderEntry>>>;

/// Upper bound on a request head, so a client can't make the agent buffer forever.
const MAX_HEAD: usize = 64 * 1024;

/// Read timeout on forwarded (non-tunnel) upstream connections, so a server that
/// ignores `Connection: close` can't pin a thread forever.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(300);

pub fn start_proxy(table: PlaceholderTable, mitm: Arc<Mitm>) -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(client) = stream else { continue };
            let table = table.clone();
            let mitm = mitm.clone();
            thread::spawn(move || {
                if let Err(e) = handle_connection(client, &table, &mitm) {
                    eprintln!("hush-agent: proxy connection error: {e:#}");
                }
            });
        }
    });

    Ok(port)
}

struct Head {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

fn handle_connection(mut client: TcpStream, table: &PlaceholderTable, mitm: &Mitm) -> Result<()> {
    let (head, leftover) = read_head(&mut client)?;
    let req = parse_head(&head)?;

    if req.method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(&req.path, 443);
        return handle_connect(client, leftover, &host, port, table, mitm);
    }

    let (host, port, path) = resolve_target(&req.path, header_value(&req.headers, "host"))?;
    let mut upstream = TcpStream::connect((host.as_str(), port))?;
    upstream.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    // Judged by the address actually connected to, not the name, so a bound
    // name that resolves off-machine doesn't count as local.
    let leaves_machine = !upstream.peer_addr()?.ip().to_canonical().is_loopback();
    forward(
        &mut client,
        &leftover,
        req,
        &path,
        &host,
        leaves_machine,
        table,
        &mut upstream,
    )
}

/// HTTPS via `CONNECT`. Hosts that some minted placeholder is bound to get
/// intercepted: TLS is terminated with a session-CA leaf for that host, the
/// request is forwarded with placeholders swapped, over a fresh, verified TLS
/// connection to the real host. Every other host gets a blind byte tunnel —
/// hush never decrypts traffic it has no secret for, and any placeholder in it
/// goes out verbatim.
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

    if !is_bound_host(table, host) {
        return tunnel(client, &leftover, upstream);
    }
    if !leftover.is_empty() {
        bail!("client sent data before CONNECT to {host} was established");
    }

    upstream.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    let server_name =
        ServerName::try_from(host.to_string()).with_context(|| format!("invalid host {host}"))?;
    let mut upstream = StreamOwned::new(
        ClientConnection::new(mitm.upstream_config(), server_name)?,
        upstream,
    );
    let mut client = StreamOwned::new(ServerConnection::new(mitm.server_config(host)?)?, client);

    let (head, leftover) = read_head(&mut client)?;
    let req = parse_head(&head)?;
    let path = req.path.clone();
    forward(
        &mut client,
        &leftover,
        req,
        &path,
        host,
        false,
        table,
        &mut upstream,
    )?;

    client.conn.send_close_notify();
    let _ = client.flush();
    Ok(())
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

/// Forwards one request and relays its response. The request is sent with
/// `Connection: close`, so the response ends at upstream EOF and the client
/// opens a fresh connection (and fresh substitution) for its next request.
/// `cleartext` means the request crosses the network unencrypted.
#[allow(clippy::too_many_arguments)]
fn forward<C: Read + Write, U: Read + Write>(
    client: &mut C,
    leftover: &[u8],
    req: Head,
    path: &str,
    target_host: &str,
    cleartext: bool,
    table: &PlaceholderTable,
    upstream: &mut U,
) -> Result<()> {
    let body = body_framing(&req.headers)?;
    let expects_continue = req.headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("expect") && v.trim().eq_ignore_ascii_case("100-continue")
    });

    let mut headers = req.headers;
    substitute_placeholders(&mut headers, target_host, cleartext, table);
    headers.retain(|(k, _)| !HOP_BY_HOP.iter().any(|h| k.eq_ignore_ascii_case(h)));
    headers.push(("Connection".to_string(), "close".to_string()));

    let mut out = format!("{} {path} HTTP/1.1\r\n", req.method);
    for (k, v) in &headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    upstream.write_all(out.as_bytes())?;

    // `Expect` was stripped upstream, so answer it here or the client stalls
    // waiting before it sends the body.
    if expects_continue {
        client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
        client.flush()?;
    }
    {
        let mut src = BufReader::new(leftover.chain(&mut *client));
        copy_body(&mut src, upstream, body)?;
    }
    upstream.flush()?;

    relay_until_eof(upstream, client)
}

/// Headers that only make sense for the client↔proxy hop.
const HOP_BY_HOP: &[&str] = &[
    "proxy-connection",
    "proxy-authorization",
    "connection",
    "keep-alive",
    "expect",
];

#[derive(Debug, PartialEq)]
enum Body {
    None,
    Length(u64),
    Chunked,
}

fn body_framing(headers: &[(String, String)]) -> Result<Body> {
    if let Some(te) = header_value(headers, "transfer-encoding")
        && te.to_ascii_lowercase().contains("chunked")
    {
        return Ok(Body::Chunked);
    }
    match header_value(headers, "content-length") {
        Some(v) => Ok(Body::Length(
            v.trim().parse().context("invalid Content-Length")?,
        )),
        None => Ok(Body::None),
    }
}

/// Copies exactly one request body, re-emitting chunked framing verbatim.
fn copy_body<R: BufRead, W: Write>(src: &mut R, dst: &mut W, body: Body) -> Result<()> {
    match body {
        Body::None => Ok(()),
        Body::Length(n) => copy_exact(src, dst, n),
        Body::Chunked => loop {
            let line = read_line(src)?;
            dst.write_all(line.as_bytes())?;
            let size = line.trim_end().split(';').next().unwrap_or("").trim();
            let size = u64::from_str_radix(size, 16)
                .with_context(|| format!("invalid chunk size {size:?}"))?;
            if size == 0 {
                // Trailer section, terminated by an empty line.
                loop {
                    let line = read_line(src)?;
                    dst.write_all(line.as_bytes())?;
                    if line.trim_end_matches(['\r', '\n']).is_empty() {
                        return Ok(());
                    }
                }
            }
            copy_exact(src, dst, size + 2)?; // chunk data + CRLF
        },
    }
}

fn copy_exact<R: Read, W: Write>(src: &mut R, dst: &mut W, n: u64) -> Result<()> {
    if io::copy(&mut src.take(n), dst)? < n {
        bail!("client closed the connection mid-body");
    }
    Ok(())
}

fn read_line<R: BufRead>(src: &mut R) -> Result<String> {
    let mut line = String::new();
    if src.read_line(&mut line)? == 0 {
        bail!("client closed the connection mid-body");
    }
    Ok(line)
}

fn relay_until_eof<U: Read, C: Write>(upstream: &mut U, client: &mut C) -> Result<()> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = match upstream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            // Plenty of servers close without a TLS close_notify; the response
            // is still complete from HTTP's point of view.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        client.write_all(&buf[..n])?;
    }
    client.flush()?;
    Ok(())
}

/// Reads bytes until the header terminator is found, returning
/// (`head_bytes`, `leftover_body_bytes_already_read`).
fn read_head<R: Read>(client: &mut R) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(pos) = find_double_crlf(&buf) {
            let leftover = buf.split_off(pos + 4);
            return Ok((buf, leftover));
        }
        if buf.len() > MAX_HEAD {
            bail!("request head larger than {MAX_HEAD} bytes");
        }
        let n = client.read(&mut chunk)?;
        if n == 0 {
            bail!("connection closed before headers were complete");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn parse_head(head: &[u8]) -> Result<Head> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut headers);
    if parsed.parse(head)?.is_partial() {
        bail!("incomplete request head");
    }
    Ok(Head {
        method: parsed.method.unwrap_or("GET").to_string(),
        path: parsed.path.unwrap_or("/").to_string(),
        headers: parsed
            .headers
            .iter()
            .map(|h| {
                (
                    h.name.to_string(),
                    String::from_utf8_lossy(h.value).to_string(),
                )
            })
            .collect(),
    })
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn resolve_target(raw_path: &str, host_header: Option<&str>) -> Result<(String, u16, String)> {
    if let Some(rest) = raw_path.strip_prefix("http://") {
        let (authority, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };
        let (host, port) = split_host_port(authority, 80);
        return Ok((host, port, path.to_string()));
    }

    let authority =
        host_header.ok_or_else(|| anyhow::anyhow!("no Host header and no absolute-form URI"))?;
    let (host, port) = split_host_port(authority, 80);
    Ok((host, port, raw_path.to_string()))
}

fn split_host_port(authority: &str, default_port: u16) -> (String, u16) {
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.contains(']') => match p.parse::<u16>() {
            Ok(port) => (h, port),
            Err(_) => (authority, default_port),
        },
        _ => (authority, default_port),
    };
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    (host.to_string(), port)
}

fn is_bound_host(table: &PlaceholderTable, host: &str) -> bool {
    table
        .lock()
        .unwrap()
        .values()
        .any(|e| e.host.eq_ignore_ascii_case(host))
}

/// A `cleartext` request (plain HTTP off this machine) only gets the real
/// value for bindings that opted in with `allow_http`; otherwise the
/// placeholder goes out verbatim, as for any other non-matching request.
fn substitute_placeholders(
    headers: &mut [(String, String)],
    target_host: &str,
    cleartext: bool,
    table: &PlaceholderTable,
) {
    let table = table.lock().unwrap();
    for (name, value) in headers.iter_mut() {
        let mut replacement: Option<String> = None;
        for (placeholder, entry) in table.iter() {
            if !name.eq_ignore_ascii_case(&entry.header) || (cleartext && !entry.allow_http) {
                continue;
            }
            let expected = entry.format.replace("{value}", placeholder);
            if *value == expected && target_host.eq_ignore_ascii_case(&entry.host) {
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

    use super::*;

    const PLACEHOLDER: &str = "hush_ph_test";

    fn table_bound_to(host: &str) -> PlaceholderTable {
        table_with(host, false)
    }

    fn table_with(host: &str, allow_http: bool) -> PlaceholderTable {
        let entry = PlaceholderEntry {
            real_value: "REAL".to_string(),
            host: host.to_string(),
            header: "Authorization".to_string(),
            format: "Bearer {value}".to_string(),
            allow_http,
        };
        Arc::new(Mutex::new(HashMap::from([(
            PLACEHOLDER.to_string(),
            entry,
        )])))
    }

    fn auth_headers() -> Vec<(String, String)> {
        vec![("authorization".to_string(), format!("Bearer {PLACEHOLDER}"))]
    }

    #[test]
    fn substitutes_only_for_bound_host() {
        let table = table_bound_to("api.example.com");

        let mut h = auth_headers();
        substitute_placeholders(&mut h, "API.example.com", false, &table);
        assert_eq!(h[0].1, "Bearer REAL");

        let mut h = auth_headers();
        substitute_placeholders(&mut h, "evil.example.com", false, &table);
        assert_eq!(h[0].1, format!("Bearer {PLACEHOLDER}"));
    }

    #[test]
    fn substitutes_only_matching_header_and_format() {
        let table = table_bound_to("api.example.com");

        let mut h = vec![("X-Api-Key".to_string(), format!("Bearer {PLACEHOLDER}"))];
        substitute_placeholders(&mut h, "api.example.com", false, &table);
        assert_eq!(h[0].1, format!("Bearer {PLACEHOLDER}"));

        let mut h = vec![("Authorization".to_string(), format!("Token {PLACEHOLDER}"))];
        substitute_placeholders(&mut h, "api.example.com", false, &table);
        assert_eq!(h[0].1, format!("Token {PLACEHOLDER}"));
    }

    #[test]
    fn cleartext_swaps_only_with_allow_http() {
        for (allow_http, expected) in [
            (false, format!("Bearer {PLACEHOLDER}")),
            (true, "Bearer REAL".to_string()),
        ] {
            let mut h = auth_headers();
            substitute_placeholders(
                &mut h,
                "api.example.com",
                true,
                &table_with("api.example.com", allow_http),
            );
            assert_eq!(h[0].1, expected, "allow_http={allow_http}");
        }
    }

    #[test]
    fn copies_chunked_body_and_stops_at_end() {
        let wire = b"5;ext=1\r\nhello\r\n0\r\nX-Trailer: t\r\n\r\nNEXT REQUEST";
        let mut src = BufReader::new(&wire[..]);
        let mut dst = Vec::new();
        copy_body(&mut src, &mut dst, Body::Chunked).unwrap();
        assert_eq!(dst, b"5;ext=1\r\nhello\r\n0\r\nX-Trailer: t\r\n\r\n");
    }

    #[test]
    fn copies_content_length_body_exactly() {
        let mut src = BufReader::new(&b"abcdefXYZ"[..]);
        let mut dst = Vec::new();
        copy_body(&mut src, &mut dst, Body::Length(6)).unwrap();
        assert_eq!(dst, b"abcdef");

        let mut short = BufReader::new(&b"abc"[..]);
        assert!(copy_body(&mut short, &mut Vec::new(), Body::Length(6)).is_err());
    }

    #[test]
    fn body_framing_prefers_chunked() {
        let h = vec![
            ("Content-Length".to_string(), "10".to_string()),
            ("Transfer-Encoding".to_string(), "gzip, Chunked".to_string()),
        ];
        assert_eq!(body_framing(&h).unwrap(), Body::Chunked);
        assert_eq!(body_framing(&[]).unwrap(), Body::None);
    }

    #[test]
    fn splits_host_and_port() {
        assert_eq!(
            split_host_port("api.example.com:8443", 443),
            ("api.example.com".into(), 8443)
        );
        assert_eq!(
            split_host_port("api.example.com", 443),
            ("api.example.com".into(), 443)
        );
        assert_eq!(split_host_port("[::1]:8080", 443), ("::1".into(), 8080));
        assert_eq!(split_host_port("[::1]", 443), ("::1".into(), 443));
    }

    /// A one-shot upstream for `localhost`, plain or TLS. It answers a single
    /// request by echoing back the raw head and body it received, and reports
    /// the same through `received` — or `None` if no request ever arrived.
    struct Upstream {
        port: u16,
        cert: CertificateDer<'static>,
        received: std::sync::mpsc::Receiver<Option<String>>,
    }

    fn spawn_upstream(tls: bool) -> Upstream {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cert_der = cert.der().clone();
        let cfg = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert_der.clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                )
                .unwrap(),
        );

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
        let (head, leftover) = read_head(s)?;
        let req = parse_head(&head)?;
        let mut body = Vec::new();
        {
            let mut src = BufReader::new(leftover.as_slice().chain(&mut *s));
            copy_body(&mut src, &mut body, body_framing(&req.headers)?)?;
        }
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
        (start_proxy(table, mitm.clone()).unwrap(), mitm)
    }

    /// Sends `CONNECT authority` and returns the tunnel plus the proxy's status line.
    fn connect(proxy_port: u16, authority: &str) -> (TcpStream, String) {
        let mut tcp = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        write!(
            tcp,
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
        )
        .unwrap();
        let (head, _) = read_head(&mut tcp).unwrap();
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
        let _ = relay_until_eof(s, &mut resp);
        String::from_utf8_lossy(&resp).into_owned()
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
        let (proxy, mitm) = start(table_bound_to("localhost"), &[&up.cert]);

        let (tcp, status) = connect(proxy, &format!("localhost:{}", up.port));
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        let resp = roundtrip(&mut tls_client(tcp, mitm.ca_der()), &chunked_post());

        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        let seen = received(&up).unwrap();
        assert!(seen.contains("Authorization: Bearer REAL\r\n"), "{seen}");
        assert!(seen.ends_with("5\r\nhello\r\n0\r\n\r\n"), "{seen}");
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
    fn swap_follows_connect_target_not_inner_host_header() {
        let up = spawn_upstream(true);
        let (proxy, _mitm) = start(table_bound_to("localhost"), &[&up.cert]);

        // Same server, reached under a name that isn't bound; the inner Host
        // header claims the bound name. Must be tunneled, never swapped.
        let (tcp, _) = connect(proxy, &format!("127.0.0.1:{}", up.port));
        roundtrip(&mut tls_client(tcp, &up.cert), &chunked_post());

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
        let (proxy, mitm) = start(table_bound_to("localhost"), &[unrelated.cert.der()]);

        let (tcp, _) = connect(proxy, &format!("localhost:{}", up.port));
        let resp = roundtrip(&mut tls_client(tcp, mitm.ca_der()), &chunked_post());

        assert_eq!(resp, "");
        assert_eq!(received(&up), None, "upstream must not get a request");
    }

    #[test]
    fn https_content_length_body_with_expect_continue_and_hop_by_hop_stripped() {
        let up = spawn_upstream(true);
        let (proxy, mitm) = start(table_bound_to("localhost"), &[&up.cert]);
        let (tcp, _) = connect(proxy, &format!("localhost:{}", up.port));
        let mut tls = tls_client(tcp, mitm.ca_der());

        write!(
            tls,
            "PUT /v1 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\
             Proxy-Authorization: Basic cHJveHk=\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\n\
             Expect: 100-continue\r\nContent-Length: 5\r\n\r\n"
        )
        .unwrap();
        let (interim, _) = read_head(&mut tls).unwrap();
        assert!(interim.starts_with(b"HTTP/1.1 100 Continue"));
        let resp = roundtrip(&mut tls, "hello");
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");

        let seen = received(&up).unwrap().to_ascii_lowercase();
        assert!(seen.contains("authorization: bearer real\r\n"), "{seen}");
        assert!(seen.contains("connection: close\r\n"), "{seen}");
        assert!(seen.ends_with("\r\n\r\nhello"), "{seen}");
        for stripped in [
            "proxy-authorization",
            "keep-alive",
            "expect",
            "connection: keep-alive",
        ] {
            assert!(
                !seen.contains(stripped),
                "{stripped} leaked upstream: {seen}"
            );
        }
    }

    #[test]
    fn plain_http_swaps_only_for_bound_host() {
        for (bound, expected) in [
            ("localhost", "Bearer REAL"),
            ("api.example.com", "Bearer hush_ph_test"),
        ] {
            let up = spawn_upstream(false);
            let (proxy, _mitm) = start(table_bound_to(bound), &[]);

            let mut tcp = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
            let request =
                chunked_post().replacen("/v1", &format!("http://localhost:{}/v1", up.port), 1);
            let resp = roundtrip(&mut tcp, &request);
            assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");

            let seen = received(&up).unwrap();
            assert!(seen.starts_with("POST /v1 HTTP/1.1\r\n"), "{seen}");
            assert!(
                seen.contains(&format!("Authorization: {expected}\r\n")),
                "bound={bound}: {seen}"
            );
            assert!(seen.ends_with("5\r\nhello\r\n0\r\n\r\n"), "{seen}");
        }
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
