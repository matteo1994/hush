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
        let Some(resp) = parse_response_head(&head) else {
            // Nothing to frame it by: pass it on as it comes, to the end.
            // Still scrubbed, so a plaintext echo in the bytes doesn't pass.
            out.write_all(&head)?;
            copy_body(upstream, out, Body::UntilClose)?;
            out.finish()?;
            return Ok(false);
        };
        if (100..200).contains(&resp.status) && resp.status != 101 {
            out.write_all(&head)?;
            out.finish()?;
            continue;
        }
        let body = response_framing(method, &resp);
        // A body we can't decode is a body we can't scan. Delivering it
        // would hand the child whatever the bound host put in it.
        if out.scrubber.active() && unscannable_body(body, &resp.headers) {
            refuse_unscanned(out)?;
            // An error, so it's in the summary `hush run` prints: the 502
            // only reaches the child, and you'd never learn why it failed.
            // The reason names a known coding or "unrecognized", never the
            // raw header: a bound host can put the secret in that field.
            bail!(
                "refused a bound host's response with {}, which hush can't scan for secrets",
                refusal_reason(body, &resp.headers)
            );
        }
        if out.scrubber.active() && body == Body::Chunked {
            // Finish the head on its own so chunk-size lines never sit in
            // the scanned stream between the two halves of a value.
            out.write_all(&head)?;
            out.finish()?;
            copy_chunked_scrubbed(upstream, &mut out.scrubber, out.out)?;
            return Ok(resp.version == 1 && !connection_has(&resp.headers, "close"));
        }
        out.write_all(&head)?;
        copy_body(upstream, out, body)?;
        out.finish()?;
        return Ok(body != Body::UntilClose
            && resp.version == 1
            && !connection_has(&resp.headers, "close"));
    }
}

/// Codings listed in `name`, lowercased, in header order.
fn header_codings(headers: &[(String, String)], name: &str) -> Vec<String> {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .flat_map(|(_, v)| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Whether the bytes of a body can be read off the wire. `identity` (and a
/// missing `Content-Encoding`) can. A single `chunked` transfer coding can,
/// once the framing is stripped. Anything else — gzip, brotli, a transfer
/// coding in front of `chunked` — would hide an echoed value. A `chunked`
/// coding that also carries `Content-Length` is refused separately: the two
/// headers name different ends of the body.
fn encodings_scannable(headers: &[(String, String)]) -> bool {
    let content = header_codings(headers, "content-encoding");
    if content.iter().any(|t| t != "identity") {
        return false;
    }
    let transfer = header_codings(headers, "transfer-encoding");
    transfer.is_empty() || (transfer.len() == 1 && transfer[0] == "chunked")
}

fn has_content_length(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-length"))
}

/// A body that isn't there (`HEAD`, `204`, an empty `Content-Length`) has
/// nothing unscanned in it. Every other body must be plaintext or chunked.
/// Chunked framing together with `Content-Length` is refused: re-chunking
/// would forward a head whose length no longer matches the body, and a client
/// can honor either header.
fn unscannable_body(body: Body, headers: &[(String, String)]) -> bool {
    if body == Body::Chunked && has_content_length(headers) {
        return true;
    }
    match body {
        Body::None | Body::Length(0) => false,
        Body::Length(_) | Body::Chunked | Body::UntilClose => !encodings_scannable(headers),
    }
}

/// Why a body was refused, using only words hush chose. A coding token is
/// repeated only when it is one of `KNOWN_CODINGS`; every other token,
/// including a secret written into the header, is `unrecognized`.
fn refusal_reason(body: Body, headers: &[(String, String)]) -> String {
    if body == Body::Chunked && has_content_length(headers) {
        return "both Content-Length and Transfer-Encoding".to_string();
    }
    let content = header_codings(headers, "content-encoding");
    if content.iter().any(|t| t != "identity") {
        return format!("Content-Encoding: {}", describe_codings(&content));
    }
    format!(
        "Transfer-Encoding: {}",
        describe_codings(&header_codings(headers, "transfer-encoding"))
    )
}

/// Coding names safe to print. Matched after the header token is trimmed and
/// lowercased, and the string that is printed is this one, not the header's.
const KNOWN_CODINGS: &[&str] = &[
    "br",
    "chunked",
    "compress",
    "deflate",
    "gzip",
    "identity",
    "x-compress",
    "x-gzip",
    "zstd",
];

fn coding_name(token: &str) -> &'static str {
    KNOWN_CODINGS
        .iter()
        .copied()
        .find(|known| *known == token)
        .unwrap_or("unrecognized")
}

fn describe_codings(tokens: &[String]) -> String {
    tokens
        .iter()
        .map(|t| coding_name(t))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Replaces a bound host's response with a fixed 502. The status line and
/// body are constants: echoing the upstream headers here would publish the
/// value we're refusing to forward.
fn refuse_unscanned<W: Write>(out: &mut Scrubbed<'_, W>) -> Result<()> {
    out.finish()?;
    const BODY: &[u8] = b"hush: refusing a response whose encoding can't be scanned for secrets\n";
    write!(
        out.out,
        "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
        BODY.len()
    )?;
    out.out.write_all(BODY)?;
    out.out.flush()?;
    Ok(())
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
        bail!("invalid Content-Length");
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
/// extensions, ended by CRLF. Errors don't quote the line: a bound server
/// can echo the real value into it, and errors end up on the terminal.
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
        bail!("invalid chunk size");
    }
    u64::from_str_radix(size, 16).context("chunk size too large")
}

fn copy_exact<R: Read, W: Write>(src: &mut R, dst: &mut W, n: u64) -> Result<()> {
    if io::copy(&mut src.take(n), dst)? < n {
        bail!("connection closed mid-body");
    }
    Ok(())
}

/// One line of chunked framing, through its LF. Bounded like a message
/// head, so a peer can't make hush buffer a line that never ends.
fn read_line<R: BufRead>(src: &mut R) -> Result<String> {
    let mut line = Vec::new();
    src.take(MAX_HEAD as u64).read_until(b'\n', &mut line)?;
    if !line.ends_with(b"\n") {
        if line.len() == MAX_HEAD {
            bail!("chunk line longer than {MAX_HEAD} bytes");
        }
        bail!("connection closed mid-body");
    }
    String::from_utf8(line).context("chunk line isn't UTF-8")
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
/// keeps `Content-Length` valid. Chunk framing is stripped before a body is
/// scanned and put back afterwards, so a value split across chunks is one
/// span here. JSON string escapes, including a `\u` surrogate pair, a single
/// layer of percent-encoding, and base64 (standard or url-safe, alone or
/// inside a longer blob) are scanned too. A value split across two responses,
/// between chunk data and a trailer, or across the header/body boundary isn't,
/// and neither is a second layer of encoding, base64 of a secret shorter than
/// 4 bytes, or base64 shifted by a preceding base64-alphabet character.
struct Scrubber {
    secrets: Vec<Vec<u8>>,
    /// Bytes not yet released, so a value split across reads is still caught.
    pending: Vec<u8>,
    /// Trailing bytes that could still be the start of a value or of one of
    /// its encoded forms. One less than the longest form.
    hold: usize,
}

/// Base64 windows shorter than this match inside ordinary text by chance.
const MIN_BASE64_SECRET: usize = 4;

const REDACTED: &[u8] = b"HUSH_REDACTED";

impl Scrubber {
    fn new(secrets: Vec<String>) -> Self {
        let secrets: Vec<Vec<u8>> = secrets
            .into_iter()
            .filter(|s| !s.is_empty())
            .map(String::into_bytes)
            .collect();
        let hold = secrets
            .iter()
            .map(|s| covered_len(s.len()))
            .max()
            .unwrap_or(1)
            - 1;
        Scrubber {
            secrets,
            pending: Vec::new(),
            hold,
        }
    }

    fn active(&self) -> bool {
        !self.secrets.is_empty()
    }

    /// Returns the bytes that are safe to release now.
    fn feed(&mut self, data: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(data);
        self.release(false)
    }

    /// Releases whatever is still held back, at end of stream.
    fn finish(&mut self) -> Vec<u8> {
        self.release(true)
    }

    fn release(&mut self, end_of_stream: bool) -> Vec<u8> {
        self.redact(end_of_stream);
        if end_of_stream {
            return std::mem::take(&mut self.pending);
        }
        let keep = self.aligned_keep(self.needed_keep());
        let rest = self.pending.split_off(self.pending.len() - keep);
        std::mem::replace(&mut self.pending, rest)
    }

    /// How many trailing bytes must wait for the next read: those from the
    /// earliest one where a value, or an encoded form of one, could start
    /// and still be unfinished. Usually far fewer than `hold`, which covers
    /// a value with every byte escaped: holding all of that would leave a
    /// streamed response several events behind.
    fn needed_keep(&self) -> usize {
        let data = &self.pending;
        let len = data.len();
        let window = len - self.hold.min(len);
        let mut start = len;
        // Raw, JSON-escaped and percent-encoded forms: a match that begins
        // before `window` is complete in `data`, so it was already painted.
        for j in window..len {
            if self
                .secrets
                .iter()
                .any(|secret| could_still_match(&data[j..], secret))
            {
                start = j;
                break;
            }
        }
        // Base64: a run that reaches the end may still grow into an encoded
        // value, so keep its last stretch, cut on a quantum boundary.
        let b64_hold = self
            .secrets
            .iter()
            .filter(|s| s.len() >= MIN_BASE64_SECRET)
            .map(|s| 4 * (s.len() + 2).div_ceil(3) - 1)
            .max();
        if let Some(b64_hold) = b64_hold
            && data.last().is_some_and(|&b| is_b64_byte(b) || b == b'=')
        {
            let mut alphabet_end = len;
            while alphabet_end > 0 && data[alphabet_end - 1] == b'=' {
                alphabet_end -= 1;
            }
            let mut run = alphabet_end;
            while run > 0 && is_b64_byte(data[run - 1]) {
                run -= 1;
            }
            let from = run.max(len - b64_hold.min(len));
            start = start.min(from - (from - run) % 4);
        }
        len - start
    }

    /// A base64 run has to be cut on a quantum boundary. Otherwise the next
    /// feed would decode the tail at the wrong alignment and miss a value
    /// that started in the bytes about to be released.
    fn aligned_keep(&self, keep: usize) -> usize {
        let len = self.pending.len();
        if keep >= len || keep == 0 {
            return keep;
        }
        let mut release = len - keep;
        if !is_b64_byte(self.pending[release - 1]) || !is_b64_byte(self.pending[release]) {
            return keep;
        }
        let mut start = release;
        while start > 0 && is_b64_byte(self.pending[start - 1]) {
            start -= 1;
        }
        let phase = (release - start) % 4;
        if phase == 0 {
            return keep;
        }
        release -= phase;
        len - release
    }

    fn redact(&mut self, end_of_stream: bool) {
        if self.secrets.is_empty() || self.pending.is_empty() {
            return;
        }
        let spans = secret_spans(&self.pending, &self.secrets, end_of_stream);
        for (start, end) in merge_spans(spans) {
            paint(&mut self.pending[start..end]);
        }
    }
}

/// Whether `tail`, which runs to the end of what has been read, could be the
/// unfinished start of `secret`: raw, with JSON string escapes or with
/// percent-encoding, mixed freely (more than the scans match, which only
/// holds back more). An escape the next read may complete counts as a start.
fn could_still_match(tail: &[u8], secret: &[u8]) -> bool {
    let Some(&want) = secret.first() else {
        // All of it matched within the data: painted already.
        return false;
    };
    let Some(&b) = tail.first() else {
        return true;
    };
    if b == b'\\' {
        match json_escape(tail) {
            Some(esc) => {
                if secret.starts_with(&esc.bytes[..esc.len])
                    && could_still_match(&tail[esc.consumed..], &secret[esc.len..])
                {
                    return true;
                }
            }
            // `\`, `\u00`, a high surrogate waiting for its pair.
            None if tail.len() < 12 => return true,
            None => {}
        }
    }
    if b == b'%' {
        match percent_byte(tail) {
            Some(byte) => {
                if byte == want && could_still_match(&tail[3..], &secret[1..]) {
                    return true;
                }
            }
            None if tail.len() < 3 => return true,
            None => {}
        }
    }
    b == want && could_still_match(&tail[1..], &secret[1..])
}

/// Longest byte string that can still be one encoding of a value this long:
/// the value itself, JSON `\uXXXX` for every byte, `%XX` for every byte, or
/// the base64 of the value plus two bytes of alignment.
fn covered_len(secret_len: usize) -> usize {
    let json = secret_len.saturating_mul(6);
    let percent = secret_len.saturating_mul(3);
    let b64 = if secret_len >= MIN_BASE64_SECRET {
        4 * (secret_len + 2).div_ceil(3)
    } else {
        0
    };
    secret_len.max(json).max(percent).max(b64)
}

fn paint(span: &mut [u8]) {
    for (b, m) in span
        .iter_mut()
        .zip(REDACTED.iter().copied().chain(std::iter::repeat(b'*')))
    {
        *b = m;
    }
}

fn merge_spans(mut spans: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    spans.sort_by_key(|(start, _)| *start);
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in spans {
        if start >= end {
            continue;
        }
        if let Some(last) = merged.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
            continue;
        }
        merged.push((start, end));
    }
    merged
}

/// Every span of `data` that is a secret or an encoded form of one.
fn secret_spans(data: &[u8], secrets: &[Vec<u8>], end_of_stream: bool) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    for secret in secrets {
        push_raw_spans(data, secret, &mut spans);
        push_json_spans(data, secret, &mut spans);
        push_percent_spans(data, secret, &mut spans);
    }
    push_b64_spans(data, secrets, end_of_stream, &mut spans);
    spans
}

fn push_raw_spans(data: &[u8], secret: &[u8], spans: &mut Vec<(usize, usize)>) {
    if secret.is_empty() {
        return;
    }
    let mut from = 0;
    while from + secret.len() <= data.len() {
        let Some(rel) = data[from..].windows(secret.len()).position(|w| w == secret) else {
            break;
        };
        let start = from + rel;
        spans.push((start, start + secret.len()));
        from = start + secret.len();
    }
}

fn push_json_spans(data: &[u8], secret: &[u8], spans: &mut Vec<(usize, usize)>) {
    let Some(&first) = secret.first() else {
        return;
    };
    let mut i = 0;
    while i < data.len() {
        if data[i] != b'\\' && data[i] != first {
            i += 1;
            continue;
        }
        match json_encoded_len(&data[i..], secret) {
            Some(n) if n > 0 => {
                spans.push((i, i + n));
                i += n;
            }
            _ => i += 1,
        }
    }
}

fn push_percent_spans(data: &[u8], secret: &[u8], spans: &mut Vec<(usize, usize)>) {
    let Some(&first) = secret.first() else {
        return;
    };
    let mut i = 0;
    while i < data.len() {
        if data[i] != b'%' && data[i] != first {
            i += 1;
            continue;
        }
        match percent_encoded_len(&data[i..], secret) {
            Some(n) if n > 0 => {
                spans.push((i, i + n));
                i += n;
            }
            _ => i += 1,
        }
    }
}

struct Escaped {
    bytes: [u8; 4],
    len: usize,
    consumed: usize,
}

/// One JSON string escape, if `data` begins with a complete one.
fn json_escape(data: &[u8]) -> Option<Escaped> {
    if data.first() != Some(&b'\\') {
        return None;
    }
    let byte = *data.get(1)?;
    let simple = |decoded: u8| Escaped {
        bytes: [decoded, 0, 0, 0],
        len: 1,
        consumed: 2,
    };
    match byte {
        b'"' | b'\\' | b'/' => Some(simple(byte)),
        b'b' => Some(simple(0x08)),
        b'f' => Some(simple(0x0c)),
        b'n' => Some(simple(b'\n')),
        b'r' => Some(simple(b'\r')),
        b't' => Some(simple(b'\t')),
        b'u' => decode_json_u(data),
        _ => None,
    }
}

/// `\uXXXX` at the start of `data`, as a code unit.
fn json_u_unit(data: &[u8]) -> Option<u32> {
    if data.first() != Some(&b'\\') || data.get(1) != Some(&b'u') {
        return None;
    }
    let hex = std::str::from_utf8(data.get(2..6)?).ok()?;
    u32::from_str_radix(hex, 16).ok()
}

/// One `\uXXXX`, or a surrogate pair (`\uD83D\uDE00`) decoded to the UTF-8 of
/// the non-BMP character. A lone surrogate is not an escape.
fn decode_json_u(data: &[u8]) -> Option<Escaped> {
    let unit = json_u_unit(data)?;
    if let Some(ch) = char::from_u32(unit) {
        let mut bytes = [0u8; 4];
        let len = ch.encode_utf8(&mut bytes).len();
        return Some(Escaped {
            bytes,
            len,
            consumed: 6,
        });
    }
    let low = json_u_unit(data.get(6..)?)?;
    if !(0xD800..0xDC00).contains(&unit) || !(0xDC00..0xE000).contains(&low) {
        return None;
    }
    let cp = 0x10000 + (((unit - 0xD800) << 10) | (low - 0xDC00));
    let ch = char::from_u32(cp)?;
    let mut bytes = [0u8; 4];
    let len = ch.encode_utf8(&mut bytes).len();
    Some(Escaped {
        bytes,
        len,
        consumed: 12,
    })
}

/// Length of a JSON-string encoding of `secret` at the start of `data`.
/// Plain text (no escape used) is left to the raw scan.
fn json_encoded_len(data: &[u8], secret: &[u8]) -> Option<usize> {
    let mut di = 0;
    let mut si = 0;
    let mut escaped = false;
    while si < secret.len() {
        if di >= data.len() {
            return None;
        }
        if data[di] == b'\\'
            && let Some(esc) = json_escape(&data[di..])
            && secret[si..].starts_with(&esc.bytes[..esc.len])
        {
            di += esc.consumed;
            si += esc.len;
            escaped = true;
            continue;
        }
        if data[di] == secret[si] {
            di += 1;
            si += 1;
            continue;
        }
        return None;
    }
    escaped.then_some(di)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn percent_byte(data: &[u8]) -> Option<u8> {
    if data.len() < 3 || data[0] != b'%' {
        return None;
    }
    Some((hex_val(data[1])? << 4) | hex_val(data[2])?)
}

/// Length of a percent-encoding of `secret` at the start of `data`. Any byte
/// may be raw or `%XX`. Plain text is left to the raw scan.
fn percent_encoded_len(data: &[u8], secret: &[u8]) -> Option<usize> {
    let mut di = 0;
    let mut si = 0;
    let mut encoded = false;
    while si < secret.len() {
        if di >= data.len() {
            return None;
        }
        if data[di] == b'%'
            && let Some(byte) = percent_byte(&data[di..])
            && byte == secret[si]
        {
            di += 3;
            si += 1;
            encoded = true;
            continue;
        }
        if data[di] == secret[si] {
            di += 1;
            si += 1;
            continue;
        }
        return None;
    }
    encoded.then_some(di)
}

fn b64_digit(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

fn is_b64_byte(b: u8) -> bool {
    b64_digit(b).is_some()
}

fn push_b64_spans(
    data: &[u8],
    secrets: &[Vec<u8>],
    end_of_stream: bool,
    spans: &mut Vec<(usize, usize)>,
) {
    if secrets.iter().all(|s| s.len() < MIN_BASE64_SECRET) {
        return;
    }
    let mut i = 0;
    while i < data.len() {
        if !is_b64_byte(data[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < data.len() && is_b64_byte(data[i]) {
            i += 1;
        }
        let mut end = i;
        if end < data.len() && data[end] == b'=' {
            end += 1;
            if end < data.len() && data[end] == b'=' {
                end += 1;
            }
        }
        i = end;
        let terminated = end < data.len() || end_of_stream;
        for (cs, ce) in b64_secret_spans(&data[start..end], secrets, terminated) {
            spans.push((start + cs, start + ce));
        }
    }
}

/// Char spans inside `run` whose decoded bytes contain a secret. A run that
/// reaches the end of the buffer and isn't `terminated` keeps its trailing
/// partial quantum: those bytes may be the start of a value the next read
/// finishes.
fn b64_secret_spans(run: &[u8], secrets: &[Vec<u8>], terminated: bool) -> Vec<(usize, usize)> {
    let alphabet = run.iter().position(|&b| b == b'=').unwrap_or(run.len());
    let usable = if terminated {
        match alphabet % 4 {
            1 => alphabet - 1,
            _ => alphabet,
        }
    } else {
        alphabet - alphabet % 4
    };
    if usable < 2 {
        return Vec::new();
    }
    let decoded = decode_b64(&run[..usable]);
    let mut spans = Vec::new();
    for secret in secrets {
        if secret.len() < MIN_BASE64_SECRET || decoded.len() < secret.len() {
            continue;
        }
        let mut from = 0;
        while from + secret.len() <= decoded.len() {
            let Some(rel) = decoded[from..]
                .windows(secret.len())
                .position(|w| w == secret.as_slice())
            else {
                break;
            };
            let at = from + rel;
            let (cs, ce) = b64_char_span(at, secret.len(), usable);
            if cs < ce {
                spans.push((cs, ce));
            }
            from = at + 1;
        }
    }
    spans
}

/// Alphabet span covering the decoded bytes, widened to whole quanta so the
/// next character stays on a group boundary. A marker that breaks the run
/// (`*`) would otherwise resume decoding mid-group and miss a later value.
fn b64_char_span(decoded_start: usize, decoded_len: usize, usable: usize) -> (usize, usize) {
    if decoded_len == 0 {
        return (0, 0);
    }
    let last = decoded_start + decoded_len - 1;
    let cs = (decoded_start / 3) * 4;
    let ce = (last / 3 + 1) * 4;
    (cs, ce.min(usable))
}

fn decode_b64(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 4 * 3 + 2);
    let mut buf = [0u8; 4];
    let mut n = 0;
    for &b in input {
        let Some(d) = b64_digit(b) else {
            break;
        };
        buf[n] = d;
        n += 1;
        if n == 4 {
            out.push((buf[0] << 2) | (buf[1] >> 4));
            out.push(((buf[1] & 0x0f) << 4) | (buf[2] >> 2));
            out.push(((buf[2] & 0x03) << 6) | buf[3]);
            n = 0;
        }
    }
    if n >= 2 {
        out.push((buf[0] << 2) | (buf[1] >> 4));
    }
    if n == 3 {
        out.push(((buf[1] & 0x0f) << 4) | (buf[2] >> 2));
    }
    out
}

/// Copies one chunked body, scanning only the chunk data and the trailers.
/// Chunk-size lines are parsed and dropped: a value parked in an extension
/// never reaches the client, and the size hush writes back is its own.
/// `scrubber` must be between messages (nothing held from the head).
fn copy_chunked_scrubbed<R: BufRead, W: Write>(
    src: &mut R,
    scrubber: &mut Scrubber,
    dst: &mut W,
) -> Result<()> {
    let mut buf = [0u8; 8 * 1024];
    loop {
        let line = read_line(src)?;
        let size = chunk_size(&line)?;
        if size == 0 {
            let rest = scrubber.finish();
            write_chunk(dst, &rest)?;
            dst.write_all(b"0\r\n")?;
            loop {
                let trailer = read_line(src)?;
                let done = trailer.trim_end_matches(['\r', '\n']).is_empty();
                dst.write_all(&scrubber.feed(trailer.as_bytes()))?;
                if done {
                    dst.write_all(&scrubber.finish())?;
                    dst.flush()?;
                    return Ok(());
                }
            }
        }
        let mut left = size;
        while left > 0 {
            let n = usize::try_from(left).unwrap_or(buf.len()).min(buf.len());
            src.read_exact(&mut buf[..n])
                .context("connection closed mid-body")?;
            write_chunk(dst, &scrubber.feed(&buf[..n]))?;
            left -= n as u64;
        }
        let mut crlf = [0u8; 2];
        src.read_exact(&mut crlf)
            .context("connection closed mid-body")?;
        if &crlf != b"\r\n" {
            bail!("chunk data longer than its size");
        }
    }
}

fn write_chunk(dst: &mut impl Write, data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    write!(dst, "{:x}\r\n", data.len())?;
    dst.write_all(data)?;
    dst.write_all(b"\r\n")
}

/// Head plus chunk data, and the trailer block, of one chunked response.
/// Trailers stay separate: the body scrubber is finished before they are
/// scanned, so a value split across that boundary is not one span. Anything
/// that isn't a complete chunked response comes back as the first buffer,
/// unchanged, with empty trailers.
#[cfg(any(test, fuzzing))]
fn client_visible_parts(resp: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let unchanged = || (resp.to_vec(), Vec::new());
    let Some(rel) = find_double_crlf(resp) else {
        return unchanged();
    };
    let head_end = rel + 4;
    let Some(parsed) = parse_response_head(&resp[..head_end]) else {
        return unchanged();
    };
    let transfer = header_codings(&parsed.headers, "transfer-encoding");
    if !(transfer.len() == 1 && transfer[0] == "chunked") {
        return unchanged();
    }
    let mut body = resp[..head_end].to_vec();
    let mut rest = &resp[head_end..];
    loop {
        let Some(nl) = rest.windows(2).position(|w| w == b"\r\n") else {
            return unchanged();
        };
        let line = &rest[..nl];
        rest = &rest[nl + 2..];
        let token = line.split(|&b| b == b';').next().unwrap_or(line);
        let token = trim_ascii(token);
        let Some(size) = parse_hex_u64(token) else {
            return unchanged();
        };
        if size == 0 {
            return (body, rest.to_vec());
        }
        let Some(size) = usize::try_from(size).ok() else {
            return unchanged();
        };
        let Some(end) = size.checked_add(2) else {
            return unchanged();
        };
        let Some(chunk) = rest.get(..end) else {
            return unchanged();
        };
        if &chunk[size..] != b"\r\n" {
            return unchanged();
        }
        body.extend_from_slice(&chunk[..size]);
        rest = &rest[end..];
    }
}

/// A chunk-size token. Longer than 16 hex digits cannot fit in `u64`, and a
/// size that doesn't fit in `usize` is rejected by the caller; either way the
/// helper returns the response unchanged instead of panicking.
#[cfg(any(test, fuzzing))]
fn parse_hex_u64(token: &[u8]) -> Option<u64> {
    if token.is_empty() || token.len() > 16 {
        return None;
    }
    let mut n = 0u64;
    for &b in token {
        n = n.checked_mul(16)?.checked_add(u64::from(hex_val(b)?))?;
    }
    Some(n)
}

#[cfg(any(test, fuzzing))]
fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(start);
    &bytes[start..end]
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

/// Entry points for the fuzz targets in `fuzz/`, built only under
/// cargo-fuzz. Each takes raw bytes and drives the same code a connection
/// does, asserting what must hold for any input.
#[cfg(fuzzing)]
pub mod fuzzing {
    use std::io::{self, BufReader, Cursor};

    use super::*;

    /// Values the `response` target scrubs. Lowercase, so a redaction
    /// marker can never spell one.
    const SECRETS: &[&str] = &["sk-live-secret", "k3y"];

    /// The first byte sets how much each read returns, so every split of
    /// the input across reads gets tried; the rest is the stream.
    fn reader(data: &[u8]) -> Option<BufReader<Cursor<&[u8]>>> {
        let (&cap, rest) = data.split_first()?;
        Some(BufReader::with_capacity(
            usize::from(cap).max(1),
            Cursor::new(rest),
        ))
    }

    /// A client's requests on a kept-alive connection: heads, framing,
    /// bodies and the host each names.
    pub fn request(data: &[u8]) {
        let Some(mut src) = reader(data) else { return };
        while let Ok(Some(head)) = read_head(&mut src) {
            assert!(head.ends_with(b"\r\n\r\n"));
            let Ok(req) = parse_head(&head) else { return };
            let _ = split_host_port(&req.path, 443);
            if let Ok((host, _, path)) =
                resolve_target(&req.path, header_value(&req.headers, "host"))
            {
                let _ = names_only(&req.headers, &path, &host);
            }
            let Ok(body) = request_framing(&req.headers) else {
                return;
            };
            assert_ne!(body, Body::UntilClose);
            if copy_body(&mut src, &mut io::sink(), body).is_err() {
                return;
            }
        }
    }

    /// A server's responses, relayed to the client through a `Scrubber`.
    /// No real value may reach the client as a contiguous span of the raw
    /// bytes, of the chunk data once framing is removed, or of the trailer
    /// block. Those three are checked separately: the body scrubber is
    /// finished before trailers are scanned, so a value split across that
    /// boundary is delivered, and holding the tail of one response to catch
    /// a split across two responses would stall the client.
    pub fn response(data: &[u8]) {
        let Some((&method, data)) = data.split_first() else {
            return;
        };
        let method = if method & 1 == 0 { "GET" } else { "HEAD" };
        let Some(mut src) = reader(data) else { return };
        let mut client = Vec::new();
        loop {
            let start = client.len();
            let mut out = Scrubbed {
                scrubber: Scrubber::new(SECRETS.iter().map(|s| s.to_string()).collect()),
                out: &mut client,
            };
            let more = relay_response(&mut src, &mut out, method);
            let raw = &client[start..];
            let (body, trailers) = client_visible_parts(raw);
            for secret in SECRETS {
                let bytes = secret.as_bytes();
                assert!(
                    !raw.windows(bytes.len()).any(|w| w == bytes),
                    "{secret} reached the client"
                );
                assert!(
                    !body.windows(bytes.len()).any(|w| w == bytes),
                    "{secret} reached the client after decoding chunks"
                );
                assert!(
                    !trailers.windows(bytes.len()).any(|w| w == bytes),
                    "{secret} reached the client in a trailer"
                );
            }
            if !matches!(more, Ok(true)) {
                return;
            }
        }
    }

    /// A stream through a `Scrubber` with the given values, in pieces.
    /// Input: values separated by 0xFE, 0xFF, then the stream; each byte of
    /// a value is mapped to a lowercase letter, so no marker spells one.
    /// The first byte of the stream sets the piece size.
    pub fn scrub(data: &[u8]) {
        let Some(split) = data.iter().position(|&b| b == 0xFF) else {
            return;
        };
        let secrets: Vec<String> = data[..split]
            .split(|&b| b == 0xFE)
            .map(|s| s.iter().map(|b| char::from(b'a' + b % 26)).collect())
            .collect();
        let Some((&size, stream)) = data[split + 1..].split_first() else {
            return;
        };
        let mut scrubber = Scrubber::new(secrets.clone());
        let mut out = Vec::new();
        for piece in stream.chunks(usize::from(size).max(1)) {
            out.extend(scrubber.feed(piece));
        }
        out.extend(scrubber.finish());
        assert_eq!(out.len(), stream.len());
        for secret in secrets.iter().filter(|s| !s.is_empty()) {
            assert!(
                !out.windows(secret.len()).any(|w| w == secret.as_bytes()),
                "{secret} survived"
            );
        }
        // Nor in an encoded form, wherever the reads were cut: scanning the
        // output again in one piece finds nothing left to paint.
        let secrets: Vec<Vec<u8>> = secrets
            .into_iter()
            .filter(|s| !s.is_empty())
            .map(String::into_bytes)
            .collect();
        let left = secret_spans(&out, &secrets, true);
        assert!(
            left.is_empty(),
            "an encoded value survived at {left:?}: {:?}",
            String::from_utf8_lossy(&out)
        );
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

    /// A streamed response (server-sent events) must reach the client as
    /// each event ends, not held back by the length of the longest encoded
    /// form of a key.
    #[test]
    fn scrubber_releases_a_streamed_event_once_it_ends() {
        let key = format!("sk-ant-api03-{}", "x9Z".repeat(32));
        let mut s = Scrubber::new(vec![key.clone()]);
        let event = "event: content_block_delta\ndata: {\"type\":\"text_delta\",\"text\":\"streamed tokens\"}\n\n";
        for _ in 0..5 {
            assert_eq!(s.feed(event.as_bytes()), event.as_bytes());
        }

        // What could still become the key, or an encoded form of it, waits.
        for tail in ["sk-ant-ap", "\\u0073k-ant", "%73k-", "s\\u00", "\\", "%7"] {
            let mut s = Scrubber::new(vec![key.clone()]);
            let out = s.feed(format!("text: {tail}").as_bytes());
            assert_eq!(out, b"text: ", "{tail}");
            assert_eq!(s.finish(), tail.as_bytes(), "{tail}");
        }
        // Text that can't become the key goes out at once.
        let mut s = Scrubber::new(vec![key.clone()]);
        assert_eq!(s.feed(b"stop, skip it\n"), b"stop, skip it\n");
    }

    #[test]
    fn scrubber_redacts_json_percent_and_base64_forms() {
        let slash = "sk-live/secret";
        let json = r"pre sk-live\/secret post";
        let redacted = scrub_in_pieces(&[slash], &[json]);
        assert_eq!(redacted.len(), json.len(), "{redacted}");
        assert!(!redacted.contains(slash), "{redacted}");
        assert!(!redacted.contains('\\'), "{redacted}");
        assert!(redacted.contains("HUSH_REDACTED"), "{redacted}");

        let unicode = r"\u0073\u006b-live/secret";
        let cafe = "caf\u{00e9}";
        let cafe_json = r"caf\u00e9";
        let redacted = scrub_in_pieces(&[cafe], &[cafe_json]);
        assert!(!redacted.contains(cafe), "{redacted}");
        assert_eq!(redacted.len(), cafe_json.len());
        let redacted = scrub_in_pieces(&[slash], &[unicode]);
        assert!(!redacted.contains("sk-live"), "{redacted}");
        assert!(!redacted.contains("\\u0073"), "{redacted}");
        assert_eq!(redacted.len(), unicode.len());

        // A non-BMP character is a surrogate pair, not one `\uXXXX`.
        let grin = "\u{1F600}";
        for encoded in [r"\uD83D\uDE00", r"\ud83d\ude00"] {
            for split in 0..=encoded.len() {
                let (a, b) = encoded.split_at(split);
                let redacted = scrub_in_pieces(&[grin], &[a, b]);
                assert_eq!(redacted.len(), encoded.len());
                assert!(!redacted.contains(grin), "split={split} {redacted}");
                assert!(
                    !redacted.to_ascii_lowercase().contains("d83d"),
                    "split={split} {redacted}"
                );
            }
        }
        let mixed = format!("sk-{grin}-key");
        let mixed_json = r"sk-\uD83D\uDE00-key";
        let redacted = scrub_in_pieces(&[&mixed], &[mixed_json]);
        assert_eq!(redacted.len(), mixed_json.len());
        assert!(!redacted.contains(grin), "{redacted}");
        assert!(!redacted.contains("sk-"), "{redacted}");

        // `\/` is the escape; the other bytes are raw. Split across reads.
        let mixed = "sk-live\\/secret";
        for split in 0..=mixed.len() {
            let (a, b) = mixed.split_at(split);
            let redacted = scrub_in_pieces(&[slash], &[a, b]);
            assert_eq!(redacted.len(), mixed.len());
            assert!(!redacted.contains("sk-live"), "split={split} {redacted}");
            assert!(!redacted.contains('\\'), "split={split} {redacted}");
        }

        let spaced = "sk live/x";
        let percent = "sk%20live%2Fx";
        let redacted = scrub_in_pieces(&[spaced], &[percent]);
        assert_eq!(redacted.len(), percent.len(), "{redacted}");
        assert!(!redacted.contains("%20"), "{redacted}");
        assert!(!redacted.contains(spaced), "{redacted}");

        let lower = "sk%20live%2fx";
        let redacted = scrub_in_pieces(&[spaced], &[lower]);
        assert!(!redacted.contains("%2f"), "{redacted}");
        assert!(!redacted.contains("%2F"), "{redacted}");

        // A value that base64-encodes with `+` and `/`, and its url-safe form.
        let plus = ">>>>>>";
        for encoded in [
            b64_encode(plus.as_bytes(), false),
            b64_encode(plus.as_bytes(), true),
        ] {
            let text = String::from_utf8(encoded.clone()).unwrap();
            let redacted = scrub_in_pieces(&[plus], &[&text]);
            assert_eq!(redacted.len(), text.len(), "{redacted}");
            assert!(
                !b64_runs_contain(redacted.as_bytes(), plus.as_bytes()),
                "{text} -> {redacted}"
            );
        }

        let under = "????";
        let url = String::from_utf8(b64_encode(under.as_bytes(), true)).unwrap();
        assert!(url.contains('_'), "{url}");
        let redacted = scrub_in_pieces(&[under], &[&url]);
        assert!(
            !b64_runs_contain(redacted.as_bytes(), under.as_bytes()),
            "{redacted}"
        );

        // Inside a larger blob, at every alignment a 3-byte group can have.
        let embedded = "sk-0123456789abcdef";
        for prefix in [b"".as_slice(), b"q", b"qq", b"qqq", b"qqqq!"] {
            let mut raw = prefix.to_vec();
            raw.extend(embedded.as_bytes());
            raw.extend(b"tail");
            let encoded = b64_encode(&raw, false);
            let text = String::from_utf8(encoded).unwrap();
            for split in 0..=text.len() {
                let (a, b) = text.split_at(split);
                let redacted = scrub_in_pieces(&[embedded], &[a, b]);
                assert_eq!(redacted.len(), text.len());
                assert!(
                    !b64_runs_contain(redacted.as_bytes(), embedded.as_bytes()),
                    "prefix={} split={split} {redacted}",
                    prefix.len()
                );
            }
        }

        // Longer than the scrubber's hold, so the run is released in pieces
        // and the tail has to stay aligned. Two copies, so redacting the
        // first must not hide the second.
        let mut raw = vec![b'q'; 80];
        raw.extend(embedded.as_bytes());
        raw.extend(b"mid");
        raw.extend(embedded.as_bytes());
        raw.extend(b"tail");
        let text = String::from_utf8(b64_encode(&raw, false)).unwrap();
        let pieces: Vec<String> = text
            .as_bytes()
            .chunks(17)
            .map(|c| String::from_utf8(c.to_vec()).unwrap())
            .collect();
        let refs: Vec<&str> = pieces.iter().map(String::as_str).collect();
        let redacted = scrub_in_pieces(&[embedded], &refs);
        assert_eq!(redacted.len(), text.len());
        assert!(
            !b64_runs_contain(redacted.as_bytes(), embedded.as_bytes()),
            "{redacted}"
        );
    }

    #[test]
    fn scrubber_leaves_unrelated_encodings_alone() {
        let out = scrub_in_pieces(&["sk-live/secret"], &[r"no secrets here \/ %2F YWI="]);
        assert!(out.contains("no secrets here"), "{out}");
        assert!(out.contains("%2F"), "{out}");
    }

    fn b64_encode(data: &[u8], url_safe: bool) -> Vec<u8> {
        let alphabet = if url_safe {
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        } else {
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        };
        let mut out = Vec::new();
        let mut i = 0;
        while i + 3 <= data.len() {
            let n =
                (u32::from(data[i]) << 16) | (u32::from(data[i + 1]) << 8) | u32::from(data[i + 2]);
            out.push(alphabet[((n >> 18) & 63) as usize]);
            out.push(alphabet[((n >> 12) & 63) as usize]);
            out.push(alphabet[((n >> 6) & 63) as usize]);
            out.push(alphabet[(n & 63) as usize]);
            i += 3;
        }
        if i < data.len() {
            let mut n = u32::from(data[i]) << 16;
            if i + 1 < data.len() {
                n |= u32::from(data[i + 1]) << 8;
            }
            out.push(alphabet[((n >> 18) & 63) as usize]);
            out.push(alphabet[((n >> 12) & 63) as usize]);
            if i + 1 < data.len() {
                out.push(alphabet[((n >> 6) & 63) as usize]);
                out.push(b'=');
            } else {
                out.push(b'=');
                out.push(b'=');
            }
        }
        out
    }

    fn b64_runs_contain(data: &[u8], secret: &[u8]) -> bool {
        let mut i = 0;
        while i < data.len() {
            if b64_digit(data[i]).is_none() {
                i += 1;
                continue;
            }
            let start = i;
            while i < data.len() && b64_digit(data[i]).is_some() {
                i += 1;
            }
            let usable = if (i - start) % 4 == 1 {
                i - start - 1
            } else {
                i - start
            };
            if usable >= secret.len()
                && decode_b64(&data[start..start + usable])
                    .windows(secret.len())
                    .any(|w| w == secret)
            {
                return true;
            }
        }
        false
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

    /// What the client got from a response hush refuses, and the error that
    /// goes in the run's summary.
    fn relay_refused(secrets: &[&str], wire: &[u8]) -> (Vec<u8>, String) {
        let mut client = Vec::new();
        let mut out = Scrubbed {
            scrubber: Scrubber::new(secrets.iter().map(|s| (*s).to_string()).collect()),
            out: &mut client,
        };
        let err = relay_response(&mut BufReader::new(wire), &mut out, "GET").unwrap_err();
        (client, format!("{err:#}"))
    }

    fn relay_with(secrets: &[&str], wire: &[u8], method: &str) -> Result<(Vec<u8>, bool)> {
        let mut client = Vec::new();
        let mut out = Scrubbed {
            scrubber: Scrubber::new(secrets.iter().map(|s| (*s).to_string()).collect()),
            out: &mut client,
        };
        let reusable = relay_response(&mut BufReader::new(wire), &mut out, method)?;
        Ok((client, reusable))
    }

    /// The client reassembles chunk data, so a value split by a chunk-size
    /// line has to be gone from those bytes, not merely absent as a
    /// contiguous span of the wire.
    #[test]
    fn chunked_response_scrubs_a_value_split_across_chunks() {
        let secret = "sk-0123456789abcdef";
        let (left, right) = secret.split_at(7);
        let wire = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
             {ll:x}\r\n{left}\r\n{rl:x}\r\n{right}\r\n0\r\nX-Echo: {secret}\r\n\r\n",
            ll = left.len(),
            rl = right.len(),
        );
        let (resp, reusable) = relay_with(&[secret], wire.as_bytes(), "GET").unwrap();
        assert!(reusable);
        assert!(
            !resp.windows(secret.len()).any(|w| w == secret.as_bytes()),
            "{}",
            String::from_utf8_lossy(&resp)
        );
        let (body, trailers) = client_visible_parts(&resp);
        assert!(
            !body.windows(secret.len()).any(|w| w == secret.as_bytes()),
            "{}",
            String::from_utf8_lossy(&body)
        );
        assert!(
            !trailers
                .windows(secret.len())
                .any(|w| w == secret.as_bytes()),
            "{}",
            String::from_utf8_lossy(&trailers)
        );
        assert!(
            body.windows(b"HUSH_REDACTED".len())
                .any(|w| w == b"HUSH_REDACTED"),
            "{}",
            String::from_utf8_lossy(&body)
        );
        // The trailer echo is scrubbed on its own stream, and the extension
        // form below never arrives: chunk-size lines are not forwarded.
        let text = String::from_utf8_lossy(&trailers);
        assert!(text.contains("X-Echo: HUSH_REDACTED"), "{text}");
    }

    /// The body scrubber is finished before trailers are scanned, so a value
    /// cut between the last chunk and the first trailer is two spans.
    #[test]
    fn chunked_response_leaves_a_value_split_across_body_and_trailer() {
        let secret = "sk-0123456789abcdef";
        let (left, right) = secret.split_at(8);
        let wire = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
             {ll:x}\r\n{left}\r\n0\r\nX-Echo: {right}\r\n\r\n",
            ll = left.len(),
        );
        let (resp, _) = relay_with(&[secret], wire.as_bytes(), "GET").unwrap();
        let (body, trailers) = client_visible_parts(&resp);
        assert!(
            !body.windows(secret.len()).any(|w| w == secret.as_bytes()),
            "{}",
            String::from_utf8_lossy(&body)
        );
        assert!(
            !trailers
                .windows(secret.len())
                .any(|w| w == secret.as_bytes()),
            "{}",
            String::from_utf8_lossy(&trailers)
        );
        let body_text = String::from_utf8_lossy(&body);
        let trailer_text = String::from_utf8_lossy(&trailers);
        assert!(body_text.contains(left), "{body_text}");
        assert!(trailer_text.contains(right), "{trailer_text}");
    }

    #[test]
    fn client_visible_parts_does_not_panic_on_a_huge_chunk_size() {
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\n";
        let (body, trailers) = client_visible_parts(resp);
        assert!(trailers.is_empty());
        assert_eq!(body, resp);
    }

    #[test]
    fn chunked_response_drops_a_value_hidden_in_a_chunk_extension() {
        let secret = "sk-0123456789abcdef";
        let wire = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
             5;note={secret}\r\nhello\r\n0\r\n\r\n"
        );
        let (resp, _) = relay_with(&[secret], wire.as_bytes(), "GET").unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(!text.contains(secret), "{text}");
        let (body, _) = client_visible_parts(&resp);
        assert!(
            body.windows(5).any(|w| w == b"hello"),
            "{}",
            String::from_utf8_lossy(&body)
        );
    }

    #[test]
    fn chunked_response_scrubs_an_encoding_split_across_chunks() {
        let secret = "sk-live/secret";
        let encoded = "sk-live\\/secret";
        let (left, right) = encoded.split_at(8);
        let wire = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
             {ll:x}\r\n{left}\r\n{rl:x}\r\n{right}\r\n0\r\n\r\n",
            ll = left.len(),
            rl = right.len(),
        );
        let (resp, _) = relay_with(&[secret], wire.as_bytes(), "GET").unwrap();
        let (body, _) = client_visible_parts(&resp);
        let text = String::from_utf8_lossy(&body);
        assert!(!text.contains(secret), "{text}");
        assert!(!text.contains('\\'), "{text}");
        assert!(text.contains("HUSH_REDACTED"), "{text}");
    }

    #[test]
    fn compressed_response_from_a_bound_host_is_not_forwarded() {
        let secret = "sk-0123456789abcdef";
        // Declaring a coding is enough: a server can label plaintext as
        // gzip, and a client that ignores the header would read the value.
        for coding in ["gzip", "deflate", "br", "zstd", "gzip, identity"] {
            let wire = format!(
                "HTTP/1.1 200 OK\r\nContent-Encoding: {coding}\r\nContent-Length: {}\r\n\r\n{secret}",
                secret.len()
            );
            let (resp, err) = relay_refused(&[secret], wire.as_bytes());
            let text = String::from_utf8_lossy(&resp);
            assert!(text.starts_with("HTTP/1.1 502"), "{coding}: {text}");
            assert!(!text.contains(secret), "{coding}: {text}");
            assert_eq!(
                err,
                format!(
                    "refused a bound host's response with Content-Encoding: {coding}, which hush can't scan for secrets"
                )
            );
        }
        let wire = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n5\r\n{secret}\r\n0\r\n\r\n"
        );
        let (resp, err) = relay_refused(&[secret], wire.as_bytes());
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 502"), "{text}");
        assert!(!text.contains(secret), "{text}");
        assert!(err.contains("Transfer-Encoding: gzip, chunked"), "{err}");
    }

    /// The run summary is printed on the terminal after the child exits, so
    /// the refusal error may name a known coding and nothing the server wrote.
    #[test]
    fn refusal_errors_never_quote_a_secret_in_an_encoding_header() {
        let secret = "sk-0123456789abcdef";
        let cases = [
            format!(
                "HTTP/1.1 200 OK\r\nContent-Encoding: {secret}\r\nContent-Length: {}\r\n\r\n{secret}",
                secret.len()
            ),
            format!(
                "HTTP/1.1 200 OK\r\nContent-Encoding: gzip, {secret}\r\nContent-Length: {}\r\n\r\n{secret}",
                secret.len()
            ),
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: {secret}\r\nContent-Length: {}\r\n\r\n{secret}",
                secret.len()
            ),
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: {secret}, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
            ),
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {secret}\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
            ),
        ];
        for wire in cases {
            let (resp, err) = relay_refused(&[secret], wire.as_bytes());
            let text = String::from_utf8_lossy(&resp);
            assert!(text.starts_with("HTTP/1.1 502"), "{text}");
            assert!(!text.contains(secret), "{text}");
            assert!(!err.contains(secret), "{err}");
            assert!(
                err.contains("unrecognized")
                    || err.contains("both Content-Length and Transfer-Encoding"),
                "{err}"
            );
        }
    }

    /// Both headers name a different end of the body. Re-chunking would keep
    /// the original `Content-Length`, so the response is refused instead.
    #[test]
    fn chunked_response_with_a_content_length_is_refused() {
        let secret = "sk-0123456789abcdef";
        let wire = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n\
             10\r\n{secret}\r\n0\r\n\r\n"
        );
        let (resp, err) = relay_refused(&[secret], wire.as_bytes());
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 502"), "{text}");
        assert!(!text.contains(secret), "{text}");
        assert!(!text.contains("10\r\n"), "{text}");
        assert_eq!(
            err,
            "refused a bound host's response with both Content-Length and Transfer-Encoding, which hush can't scan for secrets"
        );
    }

    #[test]
    fn head_with_a_content_encoding_is_still_delivered() {
        // `HEAD` has no body. The coding describes the entity GET would
        // return; the headers themselves are still scanned.
        let secret = "sk-0123456789abcdef";
        let wire = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {len}\r\nX-Echo: {secret}\r\n\r\n{secret}",
            len = secret.len()
        );
        let (resp, _) = relay_with(&[secret], wire.as_bytes(), "HEAD").unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(text.contains("X-Echo: HUSH_REDACTED"), "{text}");
        assert!(!text.contains(secret), "{text}");
    }

    #[test]
    fn identity_encoding_is_still_scrubbed() {
        let secret = "sk-0123456789abcdef";
        let wire = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Length: {}\r\n\r\n{secret}",
            secret.len()
        );
        let (resp, reusable) = relay_with(&[secret], wire.as_bytes(), "GET").unwrap();
        assert!(reusable);
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains("HUSH_REDACTED"), "{text}");
        assert!(!text.contains(secret), "{text}");
    }

    #[test]
    fn unbound_response_forwards_compression_and_chunk_extensions() {
        let secret = "sk-0123456789abcdef";
        let wire = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n{secret}",
            secret.len()
        );
        let (resp, _) = relay_with(&[], wire.as_bytes(), "GET").unwrap();
        assert_eq!(resp, wire.as_bytes());

        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n0\r\nX-Trailer: t\r\n\r\n";
        let (resp, reusable) = relay_with(&[], chunked, "GET").unwrap();
        assert!(reusable);
        assert_eq!(resp, chunked);

        // Nothing to scan, so an ambiguous length is still the server's bytes.
        let both = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let (resp, _) = relay_with(&[], both, "GET").unwrap();
        assert_eq!(resp, both);
    }

    #[test]
    fn encoded_forms_in_a_bound_response_are_scrubbed() {
        let secret = "sk-live/secret";
        let body = "echo=sk-live\\/secret&q=sk-live%2Fsecret";
        let wire = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (resp, _) = relay_with(&[secret], wire.as_bytes(), "GET").unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(!text.contains(secret), "{text}");
        assert!(!text.contains("\\/"), "{text}");
        assert!(!text.contains("%2F"), "{text}");
        assert!(text.contains("HUSH_REDACTED"), "{text}");

        let b64 = b64_encode(secret.as_bytes(), false);
        let b64 = String::from_utf8(b64).unwrap();
        let wire = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{b64}",
            b64.len()
        );
        let (resp, _) = relay_with(&[secret], wire.as_bytes(), "GET").unwrap();
        assert!(!b64_runs_contain(&resp, secret.as_bytes()), "{resp:?}");
    }

    #[test]
    fn relay_errors_never_quote_what_the_server_sent() {
        // A server that echoes the key where a chunk size belongs: one that
        // isn't hex, and one that is but overflows.
        for secret in ["sk-live-secret", "0123456789abcdef0123456789abcdef"] {
            let wire = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{secret}\r\n");
            let mut client = Vec::new();
            let mut out = Scrubbed {
                scrubber: Scrubber::new(vec![secret.to_string()]),
                out: &mut client,
            };
            let err =
                relay_response(&mut BufReader::new(wire.as_bytes()), &mut out, "GET").unwrap_err();
            let message = format!("{err:#}");
            assert!(message.contains("chunk size"), "{message}");
            assert!(!message.contains(secret), "{message}");
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
        // Like chunk-size errors, this one doesn't quote what it refused.
        let err = framing_of(&[(cl, "sk-live-secret")]).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("Content-Length"), "{message}");
        assert!(!message.contains("sk-live-secret"), "{message}");
    }

    /// A peer that never ends a chunk line can't make hush buffer it all.
    #[test]
    fn endless_chunk_line_is_refused() {
        for stream in [&b"1"[..], b"5\r\nhello\r\n0\r\nX-Trailer: "] {
            let mut src = BufReader::new(stream.chain(io::repeat(b'1')));
            let err = copy_body(&mut src, &mut io::sink(), Body::Chunked).unwrap_err();
            assert!(err.to_string().contains("longer than"), "{err}");
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
            ("unparsable head", "GET", "HTTP/1.1 2x0 Odd\r\nX-Echo: {auth}\r\n\r\n{auth}".to_string()),
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
