//! A deliberately minimal HTTP/1.1 layer: just enough request parsing and
//! response writing for a handful of JSON REST endpoints, one streamed
//! (chunked) log endpoint, and one raw-upgrade (exec) endpoint.
//!
//! There is no real reason to hand-roll this except that `kilnd` doesn't
//! need anything a general-purpose HTTP crate provides (keep-alive,
//! pipelining, compression, arbitrary content negotiation) and the
//! *client* is always `kiln`/`kiln-compose` or `kiln-dashboard`'s own
//! Electron main process - code this project also controls - so there's
//! no interoperability requirement pulling in a real HTTP stack would
//! satisfy. One request per connection, always `Connection: close`.

use crate::conn::Conn;
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Request {
    /// Reads one request from `reader`. Returns `Ok(None)` on a clean EOF
    /// (the client closed the connection without sending anything).
    pub fn read_from(reader: &mut BufReader<Conn>) -> io::Result<Option<Request>> {
        let mut request_line = String::new();
        if reader.read_line(&mut request_line)? == 0 {
            return Ok(None);
        }
        let mut parts = request_line.trim_end().splitn(3, ' ');
        let method = parts.next().unwrap_or("").to_string();
        let target = parts.next().unwrap_or("").to_string();
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p.to_string(), parse_query(q)),
            None => (target, HashMap::new()),
        };

        let mut headers = HashMap::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }

        let body = match headers.get("content-length").and_then(|v| v.parse::<usize>().ok()) {
            Some(len) if len > 0 => {
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf)?;
                buf
            }
            _ => Vec::new(),
        };

        Ok(Some(Request { method, path, query, headers, body }))
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }

    pub fn is_upgrade_to(&self, protocol: &str) -> bool {
        self.headers.get("upgrade").map(|v| v.eq_ignore_ascii_case(protocol)).unwrap_or(false)
    }
}

fn parse_query(q: &str) -> HashMap<String, String> {
    q.split('&').filter_map(|kv| kv.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json<T: serde::Serialize>(status: u16, value: &T) -> Self {
        let body = serde_json::to_vec(value).expect("serialization cannot fail");
        Response { status, headers: vec![("Content-Type".into(), "application/json".into())], body }
    }

    pub fn text(status: u16, s: impl Into<String>) -> Self {
        Response { status, headers: vec![("Content-Type".into(), "text/plain; charset=utf-8".into())], body: s.into().into_bytes() }
    }

    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        write!(w, "HTTP/1.1 {} {}\r\n", self.status, status_text(self.status))?;
        write!(w, "Content-Length: {}\r\n", self.body.len())?;
        write!(w, "Access-Control-Allow-Origin: *\r\n")?;
        write!(w, "Connection: close\r\n")?;
        for (k, v) in &self.headers {
            write!(w, "{k}: {v}\r\n")?;
        }
        write!(w, "\r\n")?;
        w.write_all(&self.body)?;
        w.flush()
    }
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        101 => "Switching Protocols",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}
