use std::io::{self, BufReader, Cursor};

use super::http::{
    Body, copy_body, header_value, parse_head, read_head, request_framing, resolve_target,
    split_host_port,
};
use super::names_only;
use super::relay::{Scrubbed, client_visible_parts, relay_response};
use super::scrub::{Scrubber, secret_spans};

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
        if let Ok((host, _, path)) = resolve_target(&req.path, header_value(&req.headers, "host")) {
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
