use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::{bail, Result};

#[derive(Debug, Clone)]
pub struct PlaceholderEntry {
    pub real_value: String,
    pub host: String,
    pub header: String,
    pub format: String,
}

pub type PlaceholderTable = Arc<Mutex<HashMap<String, PlaceholderEntry>>>;

pub fn start_proxy(table: PlaceholderTable) -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(client) => {
                    let table = table.clone();
                    thread::spawn(move || {
                        if let Err(e) = handle_connection(client, table) {
                            eprintln!("hush-agent: proxy connection error: {e:#}");
                        }
                    });
                }
                Err(_) => continue,
            }
        }
    });

    Ok(port)
}

fn handle_connection(mut client: TcpStream, table: PlaceholderTable) -> Result<()> {
    let (head, mut body) = read_head(&mut client)?;

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut headers);
    let status = parsed.parse(&head)?;
    if status.is_partial() {
        bail!("incomplete request head");
    }

    let method = parsed.method.unwrap_or("GET").to_string();
    let raw_path = parsed.path.unwrap_or("/").to_string();

    let mut out_headers: Vec<(String, String)> = parsed
        .headers
        .iter()
        .map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).to_string()))
        .collect();

    let content_length = out_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0);

    while body.len() < content_length {
        let mut buf = [0u8; 8192];
        let n = client.read(&mut buf)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    body.truncate(content_length);

    let host_header = out_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone());

    let (target_host, target_port, upstream_path) = resolve_target(&raw_path, host_header.as_deref())?;

    substitute_placeholders(&mut out_headers, &target_host, &table);

    let mut request_line = format!("{} {} HTTP/1.1\r\n", method, upstream_path);
    for (k, v) in &out_headers {
        if k.eq_ignore_ascii_case("proxy-connection") {
            continue;
        }
        request_line.push_str(&format!("{}: {}\r\n", k, v));
    }
    request_line.push_str("\r\n");

    let mut upstream = TcpStream::connect((target_host.as_str(), target_port))?;
    upstream.write_all(request_line.as_bytes())?;
    upstream.write_all(&body)?;

    std::io::copy(&mut upstream, &mut client)?;
    Ok(())
}

/// Reads bytes from `client` until the header terminator is found, returning
/// (head_bytes_without_terminator, leftover_body_bytes_already_read).
fn read_head(client: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(pos) = find_double_crlf(&buf) {
            let head = buf[..pos + 4].to_vec();
            let leftover = buf[pos + 4..].to_vec();
            return Ok((head, leftover));
        }
        let n = client.read(&mut chunk)?;
        if n == 0 {
            bail!("connection closed before headers were complete");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
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

    let authority = host_header.ok_or_else(|| anyhow::anyhow!("no Host header and no absolute-form URI"))?;
    let (host, port) = split_host_port(authority, 80);
    Ok((host, port, raw_path.to_string()))
}

fn split_host_port(authority: &str, default_port: u16) -> (String, u16) {
    match authority.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h.to_string(), port),
            Err(_) => (authority.to_string(), default_port),
        },
        None => (authority.to_string(), default_port),
    }
}

fn substitute_placeholders(headers: &mut [(String, String)], target_host: &str, table: &PlaceholderTable) {
    let table = table.lock().unwrap();
    for (name, value) in headers.iter_mut() {
        let mut replacement: Option<String> = None;
        for (placeholder, entry) in table.iter() {
            if !name.eq_ignore_ascii_case(&entry.header) {
                continue;
            }
            let expected = entry.format.replace("{value}", placeholder);
            if *value == expected && target_host == entry.host {
                replacement = Some(entry.format.replace("{value}", &entry.real_value));
                break;
            }
        }
        if let Some(new_value) = replacement {
            *value = new_value;
        }
    }
}
