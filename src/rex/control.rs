//! Rex's control connection: JSON requests and responses, and the events
//! the server pushes, on one WebSocket (`/api/control`, `rex.control.v1`).

use super::ws::{self, Message};
use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

/// The control API revision this bridge is written against (the server's llms.txt).
const API_REVISION: u64 = 7;

/// A failed request, as Rex describes it.
#[derive(Debug)]
pub struct RexError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for RexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}
impl std::error::Error for RexError {}

type Reply = mpsc::Sender<Result<Value, RexError>>;

pub struct Control {
    pub socket: PathBuf,
    writer: ws::Writer,
    pending: Arc<Mutex<HashMap<String, Reply>>>,
    next_id: AtomicU64,
    closed: Arc<AtomicBool>,
}

impl Control {
    /// Connects and says hello. Events (`{type, payload}`) arrive on the receiver;
    /// it closes when the connection drops.
    pub fn connect(socket: &Path) -> Result<(Arc<Control>, mpsc::Receiver<Value>)> {
        let (mut reader, writer) = ws::connect(socket, "/api/control", "rex.control.v1")?;
        let hello = json!({
            "type": "hello",
            "api_revision": API_REVISION,
            "client": {"kind": "app", "name": "herdr-app", "version": env!("CARGO_PKG_VERSION")},
        });
        writer.text(&hello.to_string())?;
        match reader.read()? {
            Message::Text(text) => {
                let welcome: Value = serde_json::from_str(&text)?;
                if welcome["type"] != "welcome" || welcome["protocol"] != "rex.control.v1" {
                    bail!("unexpected first message from Rex: {text}");
                }
            }
            Message::Close(code, reason) => bail!("Rex closed the control connection ({code}): {reason}"),
            Message::Binary(_) => bail!("Rex sent binary on the control connection"),
        }
        let pending: Arc<Mutex<HashMap<String, Reply>>> = Arc::default();
        let closed = Arc::new(AtomicBool::new(false));
        let (events_tx, events) = mpsc::channel();
        let (p, c) = (pending.clone(), closed.clone());
        std::thread::Builder::new().name("rex-control".into()).spawn(move || {
            while let Ok(Message::Text(text)) = reader.read() {
                let Ok(msg) = serde_json::from_str::<Value>(&text) else { continue };
                match msg["type"].as_str() {
                    Some("response") => {
                        let id = msg["id"].as_str().unwrap_or_default();
                        let Some(tx) = p.lock().unwrap().remove(id) else { continue };
                        let _ = tx.send(match msg.get("error").filter(|e| !e.is_null()) {
                            Some(e) => Err(RexError {
                                code: e["code"].as_str().unwrap_or("internal").to_owned(),
                                message: e["message"].as_str().unwrap_or("Rex request failed").to_owned(),
                            }),
                            None => Ok(msg.get("payload").cloned().unwrap_or(Value::Null)),
                        });
                    }
                    Some("event") => {
                        if events_tx.send(msg["payload"].clone()).is_err() {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            c.store(true, Ordering::SeqCst);
            for (_, tx) in p.lock().unwrap().drain() {
                let _ = tx.send(Err(RexError { code: "unavailable".into(), message: "lost the Rex server".into() }));
            }
        })?;
        let control = Control { socket: socket.to_owned(), writer, pending, next_id: AtomicU64::new(1), closed };
        Ok((Arc::new(control), events))
    }

    pub fn call(&self, method: &str, payload: Value) -> Result<Value> {
        self.call_timeout(method, payload, Duration::from_secs(10))
    }

    pub fn call_timeout(&self, method: &str, payload: Value, timeout: Duration) -> Result<Value> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(RexError { code: "unavailable".into(), message: "lost the Rex server".into() }.into());
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed).to_string();
        let (tx, rx) = mpsc::channel();
        self.pending.lock().unwrap().insert(id.clone(), tx);
        let request = json!({"type": "request", "id": id, "method": method, "payload": payload});
        if let Err(e) = self.writer.text(&request.to_string()) {
            self.pending.lock().unwrap().remove(&id);
            return Err(e.context(method.to_owned()));
        }
        match rx.recv_timeout(timeout) {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(anyhow::Error::new(e).context(method.to_owned())),
            Err(_) => {
                self.pending.lock().unwrap().remove(&id);
                Err(anyhow!("{method}: no reply from Rex"))
            }
        }
    }

    /// Calls a block method (`com.superlogical.terminal.write`) with its own arguments.
    pub fn block_call(&self, session: &str, block: &str, method: &str, args: Value) -> Result<Value> {
        self.call(method, json!({"session_id": session, "block_id": block, "args": args}))
    }
}

/// The Rex error code behind a failed call, if Rex answered at all.
pub fn error_code(e: &anyhow::Error) -> Option<&str> {
    e.downcast_ref::<RexError>().map(|e| e.code.as_str())
}
