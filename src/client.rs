use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use anyhow::{bail, Context, Result};

use crate::protocol::{Request, Response};
use crate::vault::socket_path;

pub fn send(req: &Request) -> Result<Response> {
    let path = socket_path()?;
    let mut stream = UnixStream::connect(&path).with_context(|| {
        format!(
            "could not connect to hush-agent at {} — is it running? try `hush unlock`",
            path.display()
        )
    })?;

    let line = serde_json::to_string(req)?;
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line)?;
    if response_line.trim().is_empty() {
        bail!("hush-agent closed the connection without responding");
    }

    let resp: Response = serde_json::from_str(response_line.trim())?;
    Ok(resp)
}
