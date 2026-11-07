//! The HTTP/1 the proxy needs: reading heads, finding where a message ends,
//! and copying its body.

use std::borrow::Cow;
use std::io::{self, BufRead, Read, Write};

use anyhow::{Context, Result, bail};

/// Upper bound on a message head, so neither side can make the proxy buffer forever.
const MAX_HEAD: usize = 64 * 1024;

/// Most headers a request may have; more fails its connection.
const MAX_REQUEST_HEADERS: usize = 64;
/// Most headers a response may have; more is an unreadable head.
const MAX_RESPONSE_HEADERS: usize = 128;

/// A header as it came. The name is a token, so ASCII; the value may hold any
/// byte but CR and LF (obs-text, RFC 9110 5.5), so it stays bytes, and text
/// is read from it only to decide something (`header_value`).
pub(super) type Header = (String, Vec<u8>);

pub(super) struct Head {
    pub(super) method: String,
    pub(super) path: String,
    /// The minor version: 1 for HTTP/1.1.
    pub(super) version: u8,
    pub(super) headers: Vec<Header>,
}

pub(super) struct ResponseHead {
    pub(super) version: u8,
    pub(super) status: u16,
    pub(super) headers: Vec<Header>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Body {
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
pub(super) fn request_framing(headers: &[Header]) -> Result<Body> {
    let values = |name: &str| -> Vec<String> {
        headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .flat_map(|(_, v)| {
                String::from_utf8_lossy(v)
                    .split(',')
                    .map(|v| v.trim().to_ascii_lowercase())
                    .collect::<Vec<_>>()
            })
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

pub(super) fn body_framing(headers: &[Header]) -> Result<Body> {
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
pub(super) fn response_framing(method: &str, resp: &ResponseHead) -> Body {
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
pub(super) fn connection_has(headers: &[Header], token: &str) -> bool {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("connection"))
        .any(|(_, v)| {
            String::from_utf8_lossy(v)
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case(token))
        })
}

/// Copies exactly one message body, re-emitting chunked framing verbatim.
pub(super) fn copy_body<R: BufRead, W: Write>(src: &mut R, dst: &mut W, body: Body) -> Result<()> {
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
pub(super) fn chunk_size(line: &str) -> Result<u64> {
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
pub(super) fn read_line<R: BufRead>(src: &mut R) -> Result<String> {
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

pub(super) fn copy_until_close<R: Read, W: Write>(src: &mut R, dst: &mut W) -> Result<()> {
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

/// Reads one message head, through its blank line, and leaves whatever
/// follows in `src`. `None` if the connection ended before the first byte.
pub(super) fn read_head<R: BufRead>(src: &mut R) -> Result<Option<Vec<u8>>> {
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

pub(super) fn parse_head(head: &[u8]) -> Result<Head> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_REQUEST_HEADERS];
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
pub(super) fn parse_response_head(head: &[u8]) -> Option<ResponseHead> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_RESPONSE_HEADERS];
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

fn owned_headers(headers: &[httparse::Header]) -> Vec<Header> {
    headers
        .iter()
        .map(|h| (h.name.to_string(), h.value.to_vec()))
        .collect()
}

/// The first `name` header's value as text, with bytes that aren't UTF-8
/// replaced, which no value hush compares against contains.
pub(super) fn header_value<'a>(headers: &'a [Header], name: &str) -> Option<Cow<'a, str>> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| String::from_utf8_lossy(v))
}

pub(super) fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

pub(super) fn resolve_target(
    raw_path: &str,
    host_header: Option<&str>,
) -> Result<(String, u16, String)> {
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

pub(super) fn split_host_port(authority: &str, default_port: u16) -> (String, u16) {
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

#[cfg(test)]
mod tests {
    use std::io::BufReader;

    use super::*;

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
            ("Content-Length".to_string(), b"10".to_vec()),
            ("Transfer-Encoding".to_string(), b"gzip, Chunked".to_vec()),
        ];
        assert_eq!(body_framing(&h).unwrap(), Body::Chunked);
        assert_eq!(body_framing(&[]).unwrap(), Body::None);
    }

    fn framing_of(pairs: &[(&str, &str)]) -> Result<Body> {
        let h: Vec<Header> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
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
}
