//! A small WebSocket client (RFC 6455) over the Rex server's Unix socket:
//! enough for Rex's control and data connections, which need no
//! compression and no TLS.

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const TEXT: u8 = 0x1;
const BINARY: u8 = 0x2;
const CLOSE: u8 = 0x8;
const PING: u8 = 0x9;
const PONG: u8 = 0xA;
/// The largest message we accept; Rex's control limit is 1 MiB, data messages 64 KiB.
const MAX_MESSAGE: usize = 16 << 20;

pub enum Message {
    Text(String),
    Binary(Vec<u8>),
    /// The server closed the connection: its status code and reason.
    Close(u16, String),
}

/// The writing half; clones share one socket, and each frame is written whole.
#[derive(Clone)]
pub struct Writer(Arc<Mutex<UnixStream>>);

pub struct Reader {
    stream: BufReader<UnixStream>,
    writer: Writer,
}

/// Opens a WebSocket at `path` (`/api/control`) asking for `protocol`.
pub fn connect(socket: &Path, path: &str, protocol: &str) -> Result<(Reader, Writer)> {
    let mut stream = UnixStream::connect(socket).with_context(|| format!("cannot reach the Rex server at {}", socket.display()))?;
    let key = base64::engine::general_purpose::STANDARD.encode(random_bytes::<16>());
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {protocol}\r\n\r\n"
    )?;
    let writer = Writer(Arc::new(Mutex::new(stream.try_clone()?)));
    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    reader.read_line(&mut status)?;
    if !status.starts_with("HTTP/1.1 101") {
        bail!("Rex refused the WebSocket at {path}: {}", status.trim());
    }
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            bail!("Rex closed the connection during the WebSocket handshake");
        }
        if line == "\r\n" {
            break;
        }
    }
    Ok((Reader { stream: reader, writer: writer.clone() }, writer))
}

impl Writer {
    pub fn text(&self, text: &str) -> Result<()> {
        self.frame(TEXT, text.as_bytes())
    }

    pub fn binary(&self, bytes: &[u8]) -> Result<()> {
        self.frame(BINARY, bytes)
    }

    /// Sends a close frame; status 1000 ends a data stream for good.
    pub fn close(&self, code: u16) {
        let _ = self.frame(CLOSE, &code.to_be_bytes());
        if let Ok(s) = self.0.lock() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }

    /// Clients mask every frame (RFC 6455 5.3).
    fn frame(&self, opcode: u8, payload: &[u8]) -> Result<()> {
        let mut out = Vec::with_capacity(payload.len() + 14);
        out.push(0x80 | opcode);
        match payload.len() {
            n if n < 126 => out.push(0x80 | n as u8),
            n if n <= u16::MAX as usize => {
                out.push(0x80 | 126);
                out.extend((n as u16).to_be_bytes());
            }
            n => {
                out.push(0x80 | 127);
                out.extend((n as u64).to_be_bytes());
            }
        }
        let mask = random_bytes::<4>();
        out.extend(mask);
        out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        let mut stream = self.0.lock().unwrap();
        stream.write_all(&out)?;
        Ok(())
    }
}

impl Reader {
    /// The next whole message. Pings are answered here.
    pub fn read(&mut self) -> Result<Message> {
        let mut message: Vec<u8> = Vec::new();
        let mut kind = None;
        loop {
            let (fin, opcode, payload) = self.frame()?;
            match opcode {
                PING => {
                    self.writer.frame(PONG, &payload)?;
                    continue;
                }
                PONG => continue,
                CLOSE => {
                    let code = payload.get(..2).map(|c| u16::from_be_bytes([c[0], c[1]])).unwrap_or(1005);
                    let reason = String::from_utf8_lossy(payload.get(2..).unwrap_or_default()).into_owned();
                    let _ = self.writer.frame(CLOSE, &payload[..payload.len().min(2)]);
                    return Ok(Message::Close(code, reason));
                }
                // Continuation frames carry opcode 0.
                0 if kind.is_none() => bail!("WebSocket continuation without a message"),
                0 => {}
                TEXT | BINARY => kind = Some(opcode),
                other => bail!("unknown WebSocket opcode {other}"),
            }
            message.extend(payload);
            if message.len() > MAX_MESSAGE {
                bail!("WebSocket message larger than {MAX_MESSAGE} bytes");
            }
            if fin {
                return Ok(match kind {
                    Some(TEXT) => Message::Text(String::from_utf8(message).context("WebSocket text that isn't UTF-8")?),
                    _ => Message::Binary(message),
                });
            }
        }
    }

    fn frame(&mut self) -> Result<(bool, u8, Vec<u8>)> {
        let mut head = [0u8; 2];
        self.stream.read_exact(&mut head)?;
        let (fin, opcode, masked) = (head[0] & 0x80 != 0, head[0] & 0x0F, head[1] & 0x80 != 0);
        let len = match head[1] & 0x7F {
            126 => {
                let mut n = [0u8; 2];
                self.stream.read_exact(&mut n)?;
                u16::from_be_bytes(n) as usize
            }
            127 => {
                let mut n = [0u8; 8];
                self.stream.read_exact(&mut n)?;
                u64::from_be_bytes(n) as usize
            }
            n => n as usize,
        };
        if len > MAX_MESSAGE {
            bail!("WebSocket frame larger than {MAX_MESSAGE} bytes");
        }
        let mut mask = [0u8; 4];
        if masked {
            self.stream.read_exact(&mut mask)?;
        }
        let mut payload = vec![0u8; len];
        self.stream.read_exact(&mut payload)?;
        if masked {
            payload.iter_mut().enumerate().for_each(|(i, b)| *b ^= mask[i % 4]);
        }
        Ok((fin, opcode, payload))
    }
}

/// Masks and handshake keys only need to be unpredictable to proxies, not secret.
fn random_bytes<const N: usize>() -> [u8; N] {
    use std::hash::{BuildHasher, Hasher};
    let mut out = [0u8; N];
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or_default();
    for chunk in out.chunks_mut(8) {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u128(nanos);
        chunk.copy_from_slice(&h.finish().to_le_bytes()[..chunk.len()]);
    }
    out
}
