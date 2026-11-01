//! Splits a Rex terminal stream into its parts: the Ghostty snapshot it
//! starts with, the program's output, and Rex's own messages, which arrive as
//! `ESC _ rex1;<nonce>;<json> ESC \` with the stream's nonce. A message with
//! another nonce was printed by a program and stays in the output.

use serde_json::Value;

pub enum Piece {
    /// Part of the snapshot; it ends at the first Rex message.
    Snapshot(Vec<u8>),
    Output(Vec<u8>),
    Message(Value),
}

pub struct Filter {
    marker: Vec<u8>,
    pending: Vec<u8>,
    in_snapshot: bool,
}

const END: &[u8] = b"\x1b\\";

impl Filter {
    pub fn new(nonce: u64) -> Filter {
        Filter { marker: format!("\x1b_rex1;{nonce};").into_bytes(), pending: Vec::new(), in_snapshot: true }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Vec<Piece> {
        self.pending.extend_from_slice(bytes);
        let mut pieces = Vec::new();
        loop {
            match find(&self.pending, &self.marker) {
                Some(at) => {
                    let body_start = at + self.marker.len();
                    let Some(len) = find(&self.pending[body_start..], END) else {
                        // The message isn't whole yet: pass what's before it.
                        let before: Vec<u8> = self.pending.drain(..at).collect();
                        self.emit(&mut pieces, before);
                        break;
                    };
                    let before: Vec<u8> = self.pending.drain(..at).collect();
                    self.emit(&mut pieces, before);
                    let message: Vec<u8> = self.pending.drain(..self.marker.len() + len + END.len()).collect();
                    let json = &message[self.marker.len()..message.len() - END.len()];
                    self.in_snapshot = false;
                    pieces.push(Piece::Message(serde_json::from_slice(json).unwrap_or(Value::Null)));
                }
                None => {
                    // Hold back a tail that could be the start of a marker.
                    let keep = partial_tail(&self.pending, &self.marker);
                    let ready: Vec<u8> = self.pending.drain(..self.pending.len() - keep).collect();
                    self.emit(&mut pieces, ready);
                    break;
                }
            }
        }
        pieces
    }

    fn emit(&self, pieces: &mut Vec<Piece>, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        pieces.push(if self.in_snapshot { Piece::Snapshot(bytes) } else { Piece::Output(bytes) });
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// How many bytes at the end of `bytes` begin `marker`.
fn partial_tail(bytes: &[u8], marker: &[u8]) -> usize {
    (1..marker.len().min(bytes.len() + 1)).rev().find(|&n| bytes.ends_with(&marker[..n])).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(filter: &mut Filter, input: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<Value>) {
        let (mut snapshot, mut output, mut messages) = (Vec::new(), Vec::new(), Vec::new());
        for piece in filter.push(input) {
            match piece {
                Piece::Snapshot(b) => snapshot.extend(b),
                Piece::Output(b) => output.extend(b),
                Piece::Message(m) => messages.push(m),
            }
        }
        (snapshot, output, messages)
    }

    #[test]
    fn the_snapshot_ends_at_the_first_message_and_messages_leave_the_output() {
        let stream = b"GHOSTSNP\x01\x00\x1b\x1b_rex1;42;{\"type\":\"resize\",\"cols\":80}\x1b\\hello\x1b_rex1;7;{}\x1b\\ there\x1b_rex1;42;{\"type\":\"child_exited\",\"exit_code\":3}\x1b\\";
        // Whole, and one byte at a time: a marker cut anywhere still parses.
        let whole = run(&mut Filter::new(42), stream);
        let mut filter = Filter::new(42);
        let mut bytewise = (Vec::new(), Vec::new(), Vec::new());
        for b in stream {
            let (s, o, m) = run(&mut filter, &[*b]);
            bytewise.0.extend(s);
            bytewise.1.extend(o);
            bytewise.2.extend(m);
        }
        for (snapshot, output, messages) in [whole, bytewise] {
            assert_eq!(snapshot, b"GHOSTSNP\x01\x00\x1b");
            assert_eq!(output, b"hello\x1b_rex1;7;{}\x1b\\ there", "another nonce is program output");
            assert_eq!(messages.len(), 2);
            assert_eq!(messages[0]["type"], "resize");
            assert_eq!(messages[1]["exit_code"], 3);
        }
    }
}
