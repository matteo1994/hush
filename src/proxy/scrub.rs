//! Keeps real values out of what a bound host sends back: `Scrubber` finds a
//! value and its encoded forms in a byte stream and paints them over.

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
pub(super) struct Scrubber {
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
    pub(super) fn new(secrets: Vec<String>) -> Self {
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

    pub(super) fn active(&self) -> bool {
        !self.secrets.is_empty()
    }

    /// Returns the bytes that are safe to release now.
    pub(super) fn feed(&mut self, data: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(data);
        self.release(false)
    }

    /// Releases whatever is still held back, at end of stream.
    pub(super) fn finish(&mut self) -> Vec<u8> {
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
                if secret.starts_with(esc.decoded())
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

pub(super) fn paint(span: &mut [u8]) {
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
pub(super) fn secret_spans(
    data: &[u8],
    secrets: &[Vec<u8>],
    end_of_stream: bool,
) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    for secret in secrets {
        push_raw_spans(data, secret, &mut spans);
        push_encoded_spans(data, secret, b'\\', json_escape, &mut spans);
        push_encoded_spans(data, secret, b'%', percent_escape, &mut spans);
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

/// Every encoded form of `secret` in `data`, for one encoding: `decode` reads
/// one encoded character, `introducer` is the byte each of them starts with.
fn push_encoded_spans(
    data: &[u8],
    secret: &[u8],
    introducer: u8,
    decode: fn(&[u8]) -> Option<Escaped>,
    spans: &mut Vec<(usize, usize)>,
) {
    let Some(&first) = secret.first() else {
        return;
    };
    let mut i = 0;
    while i < data.len() {
        if data[i] != introducer && data[i] != first {
            i += 1;
            continue;
        }
        match encoded_len(&data[i..], secret, decode) {
            Some(n) => {
                spans.push((i, i + n));
                i += n;
            }
            None => i += 1,
        }
    }
}

/// Length of an encoding of `secret` at the start of `data`, in which any
/// character may be raw or encoded. One with nothing encoded is left to the
/// raw scan.
fn encoded_len(data: &[u8], secret: &[u8], decode: fn(&[u8]) -> Option<Escaped>) -> Option<usize> {
    let mut di = 0;
    let mut si = 0;
    let mut encoded = false;
    while si < secret.len() {
        let rest = data.get(di..).filter(|rest| !rest.is_empty())?;
        if let Some(esc) = decode(rest)
            && secret[si..].starts_with(esc.decoded())
        {
            di += esc.consumed;
            si += esc.len;
            encoded = true;
        } else if rest[0] == secret[si] {
            di += 1;
            si += 1;
        } else {
            return None;
        }
    }
    encoded.then_some(di)
}

/// One encoded character: what it decodes to, and how long its encoding is.
struct Escaped {
    bytes: [u8; 4],
    len: usize,
    consumed: usize,
}

impl Escaped {
    fn byte(byte: u8, consumed: usize) -> Self {
        Escaped {
            bytes: [byte, 0, 0, 0],
            len: 1,
            consumed,
        }
    }

    fn char(ch: char, consumed: usize) -> Self {
        let mut bytes = [0u8; 4];
        let len = ch.encode_utf8(&mut bytes).len();
        Escaped {
            bytes,
            len,
            consumed,
        }
    }

    fn decoded(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// One JSON string escape, if `data` begins with a complete one.
fn json_escape(data: &[u8]) -> Option<Escaped> {
    if data.first() != Some(&b'\\') {
        return None;
    }
    let byte = *data.get(1)?;
    let simple = |decoded: u8| Escaped::byte(decoded, 2);
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
        return Some(Escaped::char(ch, 6));
    }
    let low = json_u_unit(data.get(6..)?)?;
    if !(0xD800..0xDC00).contains(&unit) || !(0xDC00..0xE000).contains(&low) {
        return None;
    }
    let cp = 0x10000 + (((unit - 0xD800) << 10) | (low - 0xDC00));
    Some(Escaped::char(char::from_u32(cp)?, 12))
}

pub(super) fn hex_val(b: u8) -> Option<u8> {
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

fn percent_escape(data: &[u8]) -> Option<Escaped> {
    percent_byte(data).map(|byte| Escaped::byte(byte, 3))
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

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(in crate::proxy) fn scrub_in_pieces(secrets: &[&str], pieces: &[&str]) -> String {
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
        // Splits include the inside of an escape (`%|20`, `%2|0`, `%|2F`).
        for percent in ["sk%20live%2Fx", "sk%20live%2fx"] {
            for split in 0..=percent.len() {
                let (a, b) = percent.split_at(split);
                let redacted = scrub_in_pieces(&[spaced], &[a, b]);
                assert_eq!(redacted.len(), percent.len(), "split={split} {redacted}");
                assert!(!redacted.contains(spaced), "split={split} {redacted}");
                assert!(!redacted.contains('%'), "split={split} {redacted}");
            }
        }

        // Longer than the hold, so a prefix is released before the encoding
        // that straddles two reads has all arrived. Two copies, so painting
        // the first must not hide the second.
        let percent = "sk%20live%2Fx";
        let mut long = "q".repeat(80);
        long.push_str(percent);
        long.push_str("mid");
        long.push_str(percent);
        let pieces: Vec<String> = long
            .as_bytes()
            .chunks(17)
            .map(|c| String::from_utf8(c.to_vec()).unwrap())
            .collect();
        let refs: Vec<&str> = pieces.iter().map(String::as_str).collect();
        let redacted = scrub_in_pieces(&[spaced], &refs);
        assert_eq!(redacted.len(), long.len());
        assert!(!redacted.contains(spaced), "{redacted}");
        assert!(!redacted.contains('%'), "{redacted}");

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

    pub(in crate::proxy) fn b64_encode(data: &[u8], url_safe: bool) -> Vec<u8> {
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

    pub(in crate::proxy) fn b64_runs_contain(data: &[u8], secret: &[u8]) -> bool {
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
}
