//! Relays a response to the client: through a `Scrubber` when the host is
//! bound, refused when its body can't be scanned.

use std::io::{self, BufRead, Write};

use anyhow::{Context, Result, bail};

#[cfg(any(test, fuzzing))]
use super::http::find_double_crlf;
use super::http::{
    Body, Header, ResponseHead, chunk_size, connection_has, copy_body, parse_response_head,
    read_head, read_line, response_framing,
};
use super::scrub::Scrubber;
#[cfg(any(test, fuzzing))]
use super::scrub::hex_val;

/// Relays one response, with any interim (1xx) ones before it, and reports
/// whether the upstream connection can carry another request afterwards.
pub(super) fn relay_response<U: BufRead, W: Write>(
    upstream: &mut U,
    out: &mut Scrubbed<'_, W>,
    method: &str,
) -> Result<bool> {
    loop {
        let head = read_head(upstream)?.context("upstream closed before responding")?;
        let Some(resp) = parse_response_head(&head) else {
            // No framing, so a compressed or chunked body can't be scanned.
            // A bound host gets the fixed 502; the reason is a constant, so
            // the unreadable head never reaches the run summary. With nothing
            // to scrub, the bytes are passed on as they come.
            if out.scrubber.active() {
                refuse_unscanned(out)?;
                bail!(
                    "refused a bound host's response with an unreadable head, which hush can't scan for secrets"
                );
            }
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
            return Ok(reusable(&resp));
        }
        out.write_all(&head)?;
        copy_body(upstream, out, body)?;
        out.finish()?;
        return Ok(body != Body::UntilClose && reusable(&resp));
    }
}

/// Whether the server left the connection open after this response.
pub(super) fn reusable(resp: &ResponseHead) -> bool {
    resp.version == 1 && !connection_has(&resp.headers, "close")
}

/// Codings listed in `name`, lowercased, in header order.
fn header_codings(headers: &[Header], name: &str) -> Vec<String> {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .flat_map(|(_, v)| {
            String::from_utf8_lossy(v)
                .split(',')
                .map(|t| t.trim().to_ascii_lowercase())
                .filter(|t| !t.is_empty())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Whether the bytes of a body can be read off the wire. `identity` (and a
/// missing `Content-Encoding`) can. A single `chunked` transfer coding can,
/// once the framing is stripped. Anything else — gzip, brotli, a transfer
/// coding in front of `chunked` — would hide an echoed value. A `chunked`
/// coding that also carries `Content-Length` is refused separately: the two
/// headers name different ends of the body.
fn encodings_scannable(headers: &[Header]) -> bool {
    let content = header_codings(headers, "content-encoding");
    if content.iter().any(|t| t != "identity") {
        return false;
    }
    let transfer = header_codings(headers, "transfer-encoding");
    transfer.is_empty() || (transfer.len() == 1 && transfer[0] == "chunked")
}

fn has_content_length(headers: &[Header]) -> bool {
    headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-length"))
}

/// A body that isn't there (`HEAD`, `204`, an empty `Content-Length`) has
/// nothing unscanned in it. Every other body must be plaintext or chunked.
/// Chunked framing together with `Content-Length` is refused: re-chunking
/// would forward a head whose length no longer matches the body, and a client
/// can honor either header.
fn unscannable_body(body: Body, headers: &[Header]) -> bool {
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
fn refusal_reason(body: Body, headers: &[Header]) -> String {
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
    const BODY: &[u8] = b"hush: refusing a response whose encoding can't be scanned for secrets\n";
    out.finish()?;
    write!(
        out.out,
        "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
        BODY.len()
    )?;
    out.out.write_all(BODY)?;
    out.out.flush()?;
    Ok(())
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
pub(super) fn client_visible_parts(resp: &[u8]) -> (Vec<u8>, Vec<u8>) {
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
        let token = token.trim_ascii();
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

/// A response on its way to the client, through a `Scrubber`.
pub(super) struct Scrubbed<'a, W: Write> {
    pub(super) scrubber: Scrubber,
    pub(super) out: &'a mut W,
}

impl<W: Write> Scrubbed<'_, W> {
    /// Releases what the scrubber held back, at the end of a message.
    pub(super) fn finish(&mut self) -> io::Result<()> {
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

#[cfg(test)]
mod tests {
    use std::io::BufReader;

    use super::super::scrub::tests::{b64_encode, b64_runs_contain};
    use super::*;

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

    /// A head httparse rejects has no framing, so the body behind it — gzip
    /// bytes, or a value split across chunk boundaries — is not forwarded.
    #[test]
    fn unparsable_head_from_a_bound_host_is_not_forwarded() {
        let secret = "sk-0123456789abcdef";
        let cases = [
            format!(
                "HTTP/1.1 2x0 Odd\r\nContent-Encoding: gzip\r\nX-Echo: {secret}\r\n\r\n{secret}"
            ),
            format!(
                "HTTP/1.1 2x0 Odd\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n{}\r\n9\r\n{}\r\n0\r\n\r\n",
                &secret[..7],
                &secret[7..]
            ),
        ];
        for wire in cases {
            let (resp, err) = relay_refused(&[secret], wire.as_bytes());
            let text = String::from_utf8_lossy(&resp);
            assert!(text.starts_with("HTTP/1.1 502"), "{text}");
            assert!(!text.contains(secret), "{text}");
            assert!(!text.contains("2x0"), "{text}");
            assert!(!err.contains(secret), "{err}");
            assert!(!err.contains("2x0"), "{err}");
            assert_eq!(
                err,
                "refused a bound host's response with an unreadable head, which hush can't scan for secrets"
            );
        }
    }

    #[test]
    fn unparsable_head_from_an_unbound_host_is_forwarded() {
        let secret = "sk-0123456789abcdef";
        let wire = format!("HTTP/1.1 2x0 Odd\r\nX-Echo: {secret}\r\n\r\n{secret}");
        let (resp, reusable) = relay_with(&[], wire.as_bytes(), "GET").unwrap();
        assert!(!reusable);
        assert_eq!(resp, wire.as_bytes());
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
}
