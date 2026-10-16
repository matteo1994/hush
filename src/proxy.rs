use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
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
    /// Required on a loopback upstream, where the child can listen on any
    /// port; compared wherever it is set.
    pub port: Option<u16>,
    pub header: String,
    pub format: String,
    pub allow_http: bool,
}

pub type PlaceholderTable = Arc<Mutex<HashMap<String, PlaceholderEntry>>>;

/// Upper bound on a message head, so neither side can make the proxy buffer forever.
const MAX_HEAD: usize = 64 * 1024;

/// Read timeout on forwarded (non-tunnel) upstream connections, so a server
/// that goes silent mid-response can't pin a thread forever. Waiting between
/// requests on a kept-alive connection isn't a read and isn't limited by it.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(300);

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
        let counts = self.inner.lock().unwrap();
        let total = counts.seen.iter().map(|(_, n)| n).sum::<usize>() + counts.other;
        if total == 0 {
            return None;
        }
        let mut out = format!("{total} proxy connection error(s) during the run:");
        for (message, n) in &counts.seen {
            out.push_str(&format!("\n  {n}× {message}"));
        }
        if counts.other > 0 {
            out.push_str(&format!("\n  {}× other errors", counts.other));
        }
        Some(out)
    }
}

pub fn start_proxy(table: PlaceholderTable, mitm: Arc<Mitm>, errors: Arc<ErrorLog>) -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(client) = stream else { continue };
            let table = table.clone();
            let mitm = mitm.clone();
            let errors = errors.clone();
            thread::spawn(move || {
                if let Err(e) = handle_connection(client, &table, &mitm) {
                    errors.record(format!("{e:#}"));
                }
            });
        }
    });

    Ok(port)
}

struct Head {
    method: String,
    path: String,
    /// The minor version: 1 for HTTP/1.1.
    version: u8,
    headers: Vec<(String, String)>,
}

struct ResponseHead {
    version: u8,
    status: u16,
    headers: Vec<(String, String)>,
}

fn handle_connection(client: TcpStream, table: &PlaceholderTable, mitm: &Mitm) -> Result<()> {
    let mut client = BufReader::new(client);
    let Some(head) = read_head(&mut client)? else {
        return Ok(());
    };
    let req = parse_head(&head)?;

    if req.method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(&req.path, 443);
        let leftover = client.buffer().to_vec();
        return handle_connect(client.into_inner(), leftover, &host, port, table, mitm);
    }

    let (host, port, path) = resolve_target(&req.path, header_value(&req.headers, "host"))?;
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
        &path,
        &target,
        table,
        &mut BufReader::new(upstream),
        false,
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
        let path = req.path.clone();
        let reusable = forward(&mut client, req, &path, &target, table, &mut upstream, true)?;
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
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
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

/// Forwards one request and relays its response. Returns whether both
/// connections are left at a message boundary and willing to carry another
/// request, which is only ever the case when the caller asked with `reuse`;
/// without it the request goes out with `Connection: close`. Each request gets
/// its own substitution.
fn forward<C: Read + Write, U: Read + Write>(
    client: &mut BufReader<C>,
    req: Head,
    path: &str,
    target: &Target,
    table: &PlaceholderTable,
    upstream: &mut BufReader<U>,
    reuse: bool,
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
    let keep_alive = reuse && req.version == 1 && !connection_has(&req.headers, "close");

    let mut headers = req.headers;
    if names_only(&headers, path, target.host) {
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

    let mut out = format!("{} {path} HTTP/1.1\r\n", req.method);
    for (k, v) in &headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    upstream.get_mut().write_all(out.as_bytes())?;

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
    let reusable = relay_response(upstream, &mut out, &req.method)?;
    // Bytes past the response's end mean the two sides disagree on framing.
    Ok(keep_alive && reusable && upstream.buffer().is_empty())
}

/// Relays one response, with any interim (1xx) ones before it, and reports
/// whether the upstream connection can carry another request afterwards.
fn relay_response<U: BufRead, W: Write>(
    upstream: &mut U,
    out: &mut Scrubbed<'_, W>,
    method: &str,
) -> Result<bool> {
    loop {
        let head = read_head(upstream)?.context("upstream closed before responding")?;
        out.write_all(&head)?;
        let Some(resp) = parse_response_head(&head) else {
            // Nothing to frame it by: pass it on as it comes, to the end.
            copy_body(upstream, out, Body::UntilClose)?;
            out.finish()?;
            return Ok(false);
        };
        if (100..200).contains(&resp.status) && resp.status != 101 {
            out.finish()?;
            continue;
        }
        let body = response_framing(method, &resp);
        copy_body(upstream, out, body)?;
        out.finish()?;
        return Ok(body != Body::UntilClose
            && resp.version == 1
            && !connection_has(&resp.headers, "close"));
    }
}

/// Headers that only make sense for the client↔proxy hop.
const HOP_BY_HOP: &[&str] = &[
    "proxy-connection",
    "proxy-authorization",
    "connection",
    "keep-alive",
    "expect",
];

#[derive(Debug, Clone, Copy, PartialEq)]
enum Body {
    None,
    Length(u64),
    Chunked,
    /// Ends when the sender closes the connection. Responses only.
    UntilClose,
}

/// How a request's body ends. Stricter than `body_framing`: anything a server
/// could read differently is refused, since the proxy and the server must
/// agree on where each request on a kept-alive connection ends. That means
/// both `Transfer-Encoding` and `Content-Length`, `chunked` that isn't the
/// final coding or appears twice, and lengths that disagree or aren't plain
/// digits.
fn request_framing(headers: &[(String, String)]) -> Result<Body> {
    let values = |name: &str| -> Vec<String> {
        headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .flat_map(|(_, v)| v.split(','))
            .map(|v| v.trim().to_ascii_lowercase())
            .collect()
    };
    let codings = values("transfer-encoding");
    let lengths = values("content-length");

    if !codings.is_empty() {
        if !lengths.is_empty() {
            bail!("request has both Transfer-Encoding and Content-Length");
        }
        let chunked = codings.iter().filter(|c| *c == "chunked").count();
        if chunked != 1 || codings.last().map(String::as_str) != Some("chunked") {
            bail!("request Transfer-Encoding must end in a single chunked");
        }
        return Ok(Body::Chunked);
    }
    let Some(first) = lengths.first() else {
        return Ok(Body::None);
    };
    if lengths.iter().any(|l| l != first) {
        bail!("request has conflicting Content-Length values");
    }
    if first.is_empty() || !first.bytes().all(|b| b.is_ascii_digit()) {
        bail!("invalid Content-Length {first:?}");
    }
    Ok(Body::Length(
        first.parse().context("invalid Content-Length")?,
    ))
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

/// How a response's body ends, given the method of the request it answers.
fn response_framing(method: &str, resp: &ResponseHead) -> Body {
    if method.eq_ignore_ascii_case("HEAD") || matches!(resp.status, 100 | 102..=199 | 204 | 304) {
        return Body::None;
    }
    // A 101 hands the connection to another protocol, which isn't relayed in
    // both directions here; what the server sends is passed on until it closes.
    if resp.status == 101 {
        return Body::UntilClose;
    }
    match body_framing(&resp.headers) {
        Ok(Body::None) | Err(_) => Body::UntilClose,
        Ok(body) => body,
    }
}

/// Whether a `Connection` header lists `token`.
fn connection_has(headers: &[(String, String)], token: &str) -> bool {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case(token))
}

/// Copies exactly one message body, re-emitting chunked framing verbatim.
fn copy_body<R: BufRead, W: Write>(src: &mut R, dst: &mut W, body: Body) -> Result<()> {
    match body {
        Body::None => Ok(()),
        Body::Length(n) => copy_exact(src, dst, n),
        Body::UntilClose => copy_until_close(src, dst),
        Body::Chunked => loop {
            let line = read_line(src)?;
            dst.write_all(line.as_bytes())?;
            let size = chunk_size(&line)?;
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
            copy_exact(src, dst, size)?;
            let mut crlf = [0; 2];
            src.read_exact(&mut crlf)
                .context("connection closed mid-body")?;
            if &crlf != b"\r\n" {
                bail!("chunk data longer than its size");
            }
            dst.write_all(&crlf)?;
        },
    }
}

/// The size from a chunk-size line: hex digits only, then optional
/// extensions, ended by CRLF.
fn chunk_size(line: &str) -> Result<u64> {
    let Some(line) = line.strip_suffix("\r\n") else {
        bail!("chunk-size line not ended by CRLF");
    };
    let size = line
        .split(';')
        .next()
        .unwrap_or("")
        .trim_end_matches([' ', '\t']);
    if size.is_empty() || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid chunk size {size:?}");
    }
    u64::from_str_radix(size, 16).with_context(|| format!("chunk size {size:?} too large"))
}

fn copy_exact<R: Read, W: Write>(src: &mut R, dst: &mut W, n: u64) -> Result<()> {
    if io::copy(&mut src.take(n), dst)? < n {
        bail!("connection closed mid-body");
    }
    Ok(())
}

fn read_line<R: BufRead>(src: &mut R) -> Result<String> {
    let mut line = String::new();
    if src.read_line(&mut line)? == 0 {
        bail!("connection closed mid-body");
    }
    Ok(line)
}

fn copy_until_close<R: Read, W: Write>(src: &mut R, dst: &mut W) -> Result<()> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            // Plenty of servers close without a TLS close_notify; the response
            // is still complete from HTTP's point of view.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        dst.write_all(&buf[..n])?;
    }
}

/// Replaces every real value in a byte stream with a marker of the same
/// length, so a bound host that echoes the key back (an error message quoting
/// it, a request-inspection endpoint) can't hand it to the child. Same length
/// keeps `Content-Length` and chunk sizes valid. The stream is scanned raw, so
/// this covers the response head as well as the body; a value split by chunk
/// framing or escaped by the server isn't caught.
struct Scrubber {
    secrets: Vec<Vec<u8>>,
    /// Bytes not yet released, so a value split across reads is still caught.
    pending: Vec<u8>,
    /// How many trailing bytes could be the start of a value: longest − 1.
    hold: usize,
}

const REDACTED: &[u8] = b"HUSH_REDACTED";

impl Scrubber {
    fn new(secrets: Vec<String>) -> Self {
        let secrets: Vec<Vec<u8>> = secrets
            .into_iter()
            .filter(|s| !s.is_empty())
            .map(String::into_bytes)
            .collect();
        let hold = secrets.iter().map(Vec::len).max().unwrap_or(1) - 1;
        Scrubber {
            secrets,
            pending: Vec::new(),
            hold,
        }
    }

    /// Returns the bytes that are safe to release now.
    fn feed(&mut self, data: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(data);
        self.redact();
        let keep = self.hold.min(self.pending.len());
        let rest = self.pending.split_off(self.pending.len() - keep);
        std::mem::replace(&mut self.pending, rest)
    }

    /// Releases whatever is still held back, at end of stream.
    fn finish(&mut self) -> Vec<u8> {
        self.redact();
        std::mem::take(&mut self.pending)
    }

    fn redact(&mut self) {
        for secret in &self.secrets {
            let mut from = 0;
            while let Some(pos) = self.pending[from..]
                .windows(secret.len())
                .position(|w| w == secret.as_slice())
            {
                let start = from + pos;
                let marker = REDACTED.iter().chain(std::iter::repeat(&b'*'));
                for (b, m) in self.pending[start..start + secret.len()]
                    .iter_mut()
                    .zip(marker)
                {
                    *b = *m;
                }
                from = start + secret.len();
            }
        }
    }
}

/// A response on its way to the client, through a `Scrubber`.
struct Scrubbed<'a, W: Write> {
    scrubber: Scrubber,
    out: &'a mut W,
}

impl<W: Write> Scrubbed<'_, W> {
    /// Releases what the scrubber held back, at the end of a message.
    fn finish(&mut self) -> io::Result<()> {
        self.out.write_all(&self.scrubber.finish())?;
        self.out.flush()
    }
}

impl<W: Write> Write for Scrubbed<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.out.write_all(&self.scrubber.feed(buf))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// Reads one message head, through its blank line, and leaves whatever
/// follows in `src`. `None` if the connection ended before the first byte.
fn read_head<R: BufRead>(src: &mut R) -> Result<Option<Vec<u8>>> {
    let mut head = Vec::new();
    loop {
        let buf = match src.fill_buf() {
            Ok(buf) => buf,
            // A TLS peer that closed without a close_notify.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => &[],
            Err(e) => return Err(e.into()),
        };
        if buf.is_empty() {
            if head.is_empty() {
                return Ok(None);
            }
            bail!("connection closed before headers were complete");
        }
        let taken = buf.len();
        // The terminator may straddle what was read before.
        let from = head.len().saturating_sub(3);
        head.extend_from_slice(buf);
        if let Some(pos) = find_double_crlf(&head[from..]) {
            let end = from + pos + 4;
            src.consume(taken - (head.len() - end));
            head.truncate(end);
            return Ok(Some(head));
        }
        src.consume(taken);
        if head.len() > MAX_HEAD {
            bail!("message head larger than {MAX_HEAD} bytes");
        }
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
        version: parsed.version.unwrap_or(1),
        headers: owned_headers(parsed.headers),
    })
}

/// `None` for anything that isn't a complete, well-formed response head.
fn parse_response_head(head: &[u8]) -> Option<ResponseHead> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut parsed = httparse::Response::new(&mut headers);
    if !parsed.parse(head).ok()?.is_complete() {
        return None;
    }
    Some(ResponseHead {
        version: parsed.version?,
        status: parsed.code?,
        headers: owned_headers(parsed.headers),
    })
}

fn owned_headers(headers: &[httparse::Header]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|h| {
            (
                h.name.to_string(),
                String::from_utf8_lossy(h.value).to_string(),
            )
        })
        .collect()
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

fn real_values(table: &PlaceholderTable) -> Vec<String> {
    table
        .lock()
        .unwrap()
        .values()
        .map(|e| e.real_value.clone())
        .collect()
}

/// Whether some placeholder may be swapped on the way to `target`. Only
/// such connections are intercepted, and only their responses scrubbed.
fn is_bound(table: &PlaceholderTable, target: &Target) -> bool {
    table.lock().unwrap().values().any(|e| target.matches(e))
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
    let table = table.lock().unwrap();
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
        };
        Arc::new(Mutex::new(HashMap::from([(
            PLACEHOLDER.to_string(),
            entry,
        )])))
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

    fn scrub_in_pieces(secrets: &[&str], pieces: &[&str]) -> String {
        let mut scrubber = Scrubber::new(secrets.iter().map(|s| s.to_string()).collect());
        let mut out = Vec::new();
        for piece in pieces {
            out.extend(scrubber.feed(piece.as_bytes()));
        }
        out.extend(scrubber.finish());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn scrubber_redacts_with_same_length_marker() {
        assert_eq!(
            scrub_in_pieces(&["sk-0123456789abcdef"], &["key=sk-0123456789abcdef;"]),
            "key=HUSH_REDACTED******;"
        );
        assert_eq!(
            scrub_in_pieces(&["REAL"], &["a REAL b REAL"]),
            "a HUSH b HUSH"
        );
        assert_eq!(scrub_in_pieces(&[], &["a REAL b"]), "a REAL b");
    }

    #[test]
    fn scrubber_catches_a_value_split_across_reads() {
        let secret = "sk-0123456789abcdef";
        let text = format!("xx{secret}yy{secret}");
        let expected = text.replace(secret, "HUSH_REDACTED******");
        for split in 0..=text.len() {
            let (a, b) = text.split_at(split);
            assert_eq!(
                scrub_in_pieces(&[secret], &[a, b]),
                expected,
                "split={split}"
            );
        }
        let bytes: Vec<String> = text.chars().map(String::from).collect();
        let pieces: Vec<&str> = bytes.iter().map(String::as_str).collect();
        assert_eq!(scrub_in_pieces(&[secret], &pieces), expected);
    }

    #[test]
    fn scrubber_handles_several_values_of_different_lengths() {
        assert_eq!(
            scrub_in_pieces(&["ab", "longer-secret"], &["ab longer-", "secret ab"]),
            "HU HUSH_REDACTED HU"
        );
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

    fn framing_of(pairs: &[(&str, &str)]) -> Result<Body> {
        let h: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        request_framing(&h)
    }

    /// A request whose length could be read two ways is refused: the proxy
    /// and the server must never disagree on where it ends.
    #[test]
    fn request_framing_refuses_anything_ambiguous() {
        let te = "Transfer-Encoding";
        let cl = "Content-Length";
        assert_eq!(framing_of(&[]).unwrap(), Body::None);
        assert_eq!(framing_of(&[(cl, "5")]).unwrap(), Body::Length(5));
        assert_eq!(
            framing_of(&[(cl, "5"), (cl, "5")]).unwrap(),
            Body::Length(5)
        );
        assert_eq!(framing_of(&[(te, "Chunked")]).unwrap(), Body::Chunked);
        assert_eq!(framing_of(&[(te, "gzip, chunked")]).unwrap(), Body::Chunked);

        for (case, pairs) in [
            ("both", vec![(te, "chunked"), (cl, "5")]),
            ("conflicting lengths", vec![(cl, "5"), (cl, "6")]),
            ("length list", vec![(cl, "5, 6")]),
            ("signed length", vec![(cl, "+5")]),
            ("empty length", vec![(cl, "")]),
            ("chunked not last", vec![(te, "chunked, gzip")]),
            ("not chunked", vec![(te, "gzip")]),
            ("chunked lookalike", vec![(te, "xchunked")]),
            ("chunked twice", vec![(te, "chunked"), (te, "chunked")]),
        ] {
            assert!(framing_of(&pairs).is_err(), "{case}");
        }
    }

    #[test]
    fn chunked_body_must_be_well_formed() {
        let copy = |body: &str| {
            let mut out = Vec::new();
            copy_body(&mut body.as_bytes(), &mut out, Body::Chunked).map(|_| out)
        };
        assert!(copy("5\r\nhello\r\n0\r\n\r\n").is_ok());
        assert!(copy("5;ext=1\r\nhello\r\n0\r\n\r\n").is_ok());
        for (case, body) in [
            ("signed size", "+5\r\nhello\r\n0\r\n\r\n"),
            ("empty size", "\r\nhello\r\n0\r\n\r\n"),
            ("bare LF", "5\nhello\r\n0\r\n\r\n"),
            ("data longer than size", "3\r\nhello\r\n0\r\n\r\n"),
            ("space inside size", "0 5\r\nhello\r\n0\r\n\r\n"),
        ] {
            assert!(copy(body).is_err(), "{case}");
        }
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
    fn read_head_leaves_what_follows_in_the_reader() {
        let mut src = BufReader::with_capacity(5, &b"GET / HTTP/1.1\r\nHost: a\r\n\r\nbody"[..]);
        let head = read_head(&mut src).unwrap().unwrap();
        assert!(head.ends_with(b"Host: a\r\n\r\n"));
        let mut rest = String::new();
        src.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "body");

        assert!(read_head(&mut &b""[..]).unwrap().is_none());
        assert!(read_head(&mut &b"GET / HTTP/1.1\r\n"[..]).is_err());
    }

    #[test]
    fn response_framing_follows_status_method_and_headers() {
        let framing = |method, head: &str| {
            let head = format!("HTTP/1.1 {head}\r\n\r\n");
            response_framing(method, &parse_response_head(head.as_bytes()).unwrap())
        };
        assert_eq!(
            framing("GET", "200 OK\r\nContent-Length: 7"),
            Body::Length(7)
        );
        assert_eq!(framing("HEAD", "200 OK\r\nContent-Length: 7"), Body::None);
        assert_eq!(
            framing("GET", "304 Not Modified\r\nContent-Length: 7"),
            Body::None
        );
        assert_eq!(framing("GET", "204 No Content"), Body::None);
        assert_eq!(
            framing(
                "GET",
                "200 OK\r\nContent-Length: 7\r\nTransfer-Encoding: chunked"
            ),
            Body::Chunked
        );
        assert_eq!(framing("GET", "200 OK"), Body::UntilClose);
        assert_eq!(
            framing("GET", "200 OK\r\nContent-Length: x"),
            Body::UntilClose
        );
        assert_eq!(framing("GET", "101 Switching Protocols"), Body::UntilClose);
        assert!(parse_response_head(b"not http\r\n\r\n").is_none());
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
