//! Authenticate with EXTERNAL and preserve framing across buffered socket reads.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use super::codec::{
    decode_body, decode_error_body, marshal_method_call, parse_message, Message, Value,
    MESSAGE_KIND_ERROR, MESSAGE_KIND_METHOD_RETURN, MESSAGE_KIND_SIGNAL,
};
use super::endpoint::{BusAddress, BusError, IO_ERROR_NAME, PROTOCOL_ERROR_NAME};

const BUS_DESTINATION: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";
const BUS_INTERFACE: &str = "org.freedesktop.DBus";

/// Reject messages above the D-Bus limit before allocating their body.
const MAX_MESSAGE_BYTES: usize = 1 << 27;

const SASL_LINE_BYTES: usize = 4096;

/// Read chunks to avoid a syscall for each SASL byte.
const SASL_CHUNK_BYTES: usize = 512;

pub struct ManagerClient {
    stream: UnixStream,
    serial: u32,
    /// Preserve bytes read past SASL boundaries, including pipelined binary messages.
    read_ahead: Vec<u8>,
}

impl ManagerClient {
    pub fn connect(address: &BusAddress) -> Result<Self, BusError> {
        let stream = UnixStream::connect(address.socket_path()).map_err(|error| {
            BusError::new(
                IO_ERROR_NAME,
                format!("cannot connect to {address}: {error}"),
            )
        })?;
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .map_err(|error| {
                BusError::new(IO_ERROR_NAME, format!("cannot set bus timeout: {error}"))
            })?;
        stream
            .set_write_timeout(Some(Duration::from_secs(15)))
            .map_err(|error| {
                BusError::new(IO_ERROR_NAME, format!("cannot set bus timeout: {error}"))
            })?;
        let mut client = Self {
            stream,
            serial: 0,
            read_ahead: Vec::new(),
        };
        client.handshake()?;
        Ok(client)
    }

    fn handshake(&mut self) -> Result<(), BusError> {
        let uid = rustix::process::getuid().as_raw();
        let uid_ascii = uid.to_string();
        let mut hex = String::new();
        for byte in uid_ascii.as_bytes() {
            hex.push_str(&format!("{byte:02X}"));
        }
        self.stream
            .write_all(b"\0")
            .and_then(|()| {
                self.stream
                    .write_all(format!("AUTH EXTERNAL {hex}\r\n").as_bytes())
            })
            .map_err(|error| BusError::new(IO_ERROR_NAME, format!("auth write failed: {error}")))?;
        let line = self.read_sasl_line()?;
        if !line.starts_with("OK ") {
            return Err(BusError::new(
                IO_ERROR_NAME,
                format!("bus rejected EXTERNAL auth: {line}"),
            ));
        }
        self.stream.write_all(b"BEGIN\r\n").map_err(|error| {
            BusError::new(IO_ERROR_NAME, format!("begin write failed: {error}"))
        })?;
        self.call(BUS_DESTINATION, BUS_PATH, BUS_INTERFACE, "Hello", "", &[])?;
        Ok(())
    }

    /// Keep bytes following the line for the next SASL response or binary message.
    fn read_sasl_line(&mut self) -> Result<String, BusError> {
        let mut line = Vec::new();
        let mut chunk = [0_u8; SASL_CHUNK_BYTES];
        loop {
            let read = self.read_some(&mut chunk).map_err(|error| {
                BusError::new(IO_ERROR_NAME, format!("auth read failed: {error}"))
            })?;
            if read == 0 {
                return Err(BusError::new(IO_ERROR_NAME, "bus closed during auth"));
            }
            for (index, &byte) in chunk[..read].iter().enumerate() {
                if byte == b'\n' {
                    self.read_ahead.extend_from_slice(&chunk[index + 1..read]);
                    return String::from_utf8(line)
                        .map_err(|_| BusError::new(IO_ERROR_NAME, "auth line is not UTF-8"));
                }
                if byte != b'\r' {
                    line.push(byte);
                    if line.len() > SASL_LINE_BYTES {
                        return Err(BusError::new(IO_ERROR_NAME, "auth line is unbounded"));
                    }
                }
            }
        }
    }

    fn read_some(&mut self, chunk: &mut [u8]) -> std::io::Result<usize> {
        if !self.read_ahead.is_empty() {
            let buffered = self.read_ahead.len().min(chunk.len());
            chunk[..buffered].copy_from_slice(&self.read_ahead[..buffered]);
            self.read_ahead.drain(..buffered);
            return Ok(buffered);
        }
        self.stream.read(chunk)
    }

    /// Drain read-ahead first so bytes pipelined during authentication stay in order.
    fn fill(&mut self, target: &mut [u8]) -> Result<(), BusError> {
        let buffered = self.read_ahead.len().min(target.len());
        target[..buffered].copy_from_slice(&self.read_ahead[..buffered]);
        self.read_ahead.drain(..buffered);
        self.stream
            .read_exact(&mut target[buffered..])
            .map_err(|error| BusError::new(IO_ERROR_NAME, format!("bus read failed: {error}")))
    }

    fn next_serial(&mut self) -> u32 {
        self.serial = self.serial.wrapping_add(1).max(1);
        self.serial
    }

    fn read_message(&mut self) -> Result<Message, BusError> {
        let mut header = [0_u8; 16];
        self.fill(&mut header)?;
        let fields_len =
            u32::from_le_bytes([header[12], header[13], header[14], header[15]]) as usize;
        let body_len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
        let body_start = (16 + fields_len + 7) & !7;
        if body_start + body_len > MAX_MESSAGE_BYTES {
            return Err(BusError::new(
                PROTOCOL_ERROR_NAME,
                format!(
                    "bus message declares {} bytes, over the {MAX_MESSAGE_BYTES}-byte maximum",
                    body_start + body_len
                ),
            ));
        }
        let mut buffer = header.to_vec();
        buffer.resize(16 + fields_len, 0);
        self.fill(&mut buffer[16..])?;
        buffer.resize(body_start + body_len, 0);
        // Consume body-alignment padding from the wire to keep subsequent messages aligned.
        self.fill(&mut buffer[16 + fields_len..])?;
        parse_message(&buffer)
    }

    /// Skip signals while waiting for the matching reply; preserve remote error names.
    pub fn call(
        &mut self,
        destination: &str,
        path: &str,
        interface: &str,
        member: &str,
        signature: &str,
        body: &[Value],
    ) -> Result<Vec<Value>, BusError> {
        let serial = self.next_serial();
        let bytes = marshal_method_call(
            serial,
            destination,
            path,
            interface,
            member,
            signature,
            body,
        )?;
        self.stream
            .write_all(&bytes)
            .map_err(|error| BusError::new(IO_ERROR_NAME, format!("bus write failed: {error}")))?;
        loop {
            let message = self.read_message()?;
            if message.kind == MESSAGE_KIND_SIGNAL || message.reply_serial != Some(serial) {
                continue;
            }
            if message.kind == MESSAGE_KIND_ERROR {
                let name = message
                    .error_name
                    .clone()
                    .unwrap_or_else(|| format!("{PROTOCOL_ERROR_NAME}.UnnamedError"));
                let text = decode_error_body(&message);
                return Err(BusError {
                    name,
                    message: text,
                });
            }
            if message.kind != MESSAGE_KIND_METHOD_RETURN {
                return Err(BusError::new(
                    PROTOCOL_ERROR_NAME,
                    format!("unexpected message kind {}", message.kind),
                ));
            }
            return decode_body(&message);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    use super::{ManagerClient, MESSAGE_KIND_METHOD_RETURN, SASL_LINE_BYTES};

    /// One minimal METHOD_RETURN: fixed header, no fields, no body.
    fn return_header(serial: u32) -> [u8; 16] {
        let mut header = [0_u8; 16];
        header[0] = b'l';
        header[1] = MESSAGE_KIND_METHOD_RETURN;
        header[8..12].copy_from_slice(&serial.to_le_bytes());
        header
    }

    fn pair() -> (ManagerClient, UnixStream) {
        let (stream, peer) = UnixStream::pair().unwrap();
        (
            ManagerClient {
                stream,
                serial: 0,
                read_ahead: Vec::new(),
            },
            peer,
        )
    }

    #[test]
    fn a_peer_declaring_an_oversized_message_is_refused_before_allocation() {
        let (mut client, mut peer) = pair();
        let mut header = [0_u8; 16];
        header[0] = b'l';
        header[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        header[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        peer.write_all(&header).unwrap();
        let error = client
            .read_message()
            .expect_err("an oversized message refuses");
        assert!(error.to_string().contains("maximum"), "{error}");
    }

    #[test]
    fn a_sasl_response_split_across_reads_is_assembled() {
        let (mut client, mut peer) = pair();
        // The newline lands beyond one chunk, so no single `read` can
        // return the whole line.
        let guid = "g".repeat(508);
        peer.write_all(format!("OK {guid}\r\n").as_bytes()).unwrap();
        assert_eq!(client.read_sasl_line().unwrap(), format!("OK {guid}"));
    }

    #[test]
    fn a_response_coalesced_behind_the_first_is_kept_for_the_next_call() {
        let (mut client, mut peer) = pair();
        peer.write_all(b"OK first\r\nREJECTED second\r\n").unwrap();
        // The peer is gone before either read: the second response can
        // only come from buffered read-ahead.
        drop(peer);
        assert_eq!(client.read_sasl_line().unwrap(), "OK first");
        assert_eq!(client.read_sasl_line().unwrap(), "REJECTED second");
    }

    #[test]
    fn read_ahead_past_the_ok_line_opens_the_binary_protocol_in_order() {
        let (mut client, mut peer) = pair();
        let mut written = b"OK 0123\r\n".to_vec();
        written.extend_from_slice(&return_header(7));
        peer.write_all(&written).unwrap();
        drop(peer);
        assert_eq!(client.read_sasl_line().unwrap(), "OK 0123");
        let message = client.read_message().unwrap();
        assert_eq!(message.kind, MESSAGE_KIND_METHOD_RETURN);
        assert_eq!(message.serial, 7);
    }

    #[test]
    fn a_partially_buffered_message_header_finishes_from_the_socket() {
        let (mut client, mut peer) = pair();
        let mut written = b"OK 0123\r\n".to_vec();
        written.extend_from_slice(&return_header(7)[..4]);
        peer.write_all(&written).unwrap();
        assert_eq!(client.read_sasl_line().unwrap(), "OK 0123");
        peer.write_all(&return_header(7)[4..]).unwrap();
        let message = client.read_message().unwrap();
        assert_eq!(message.kind, MESSAGE_KIND_METHOD_RETURN);
        assert_eq!(message.serial, 7);
    }

    #[test]
    fn a_peer_closing_without_a_full_line_ends_auth_as_eof() {
        let (mut client, peer) = pair();
        drop(peer);
        let error = client.read_sasl_line().expect_err("an empty stream is EOF");
        assert!(error.to_string().contains("closed during auth"), "{error}");

        let (mut client, mut peer) = pair();
        peer.write_all(b"OK").unwrap();
        drop(peer);
        let error = client
            .read_sasl_line()
            .expect_err("a mid-line close is EOF");
        assert!(error.to_string().contains("closed during auth"), "{error}");
    }

    #[test]
    fn an_auth_line_over_the_cap_is_refused() {
        let (mut client, mut peer) = pair();
        peer.write_all(&[b'x'; SASL_LINE_BYTES + 1]).unwrap();
        let error = client
            .read_sasl_line()
            .expect_err("a line over the cap refuses");
        assert!(error.to_string().contains("unbounded"), "{error}");
    }

    #[test]
    fn the_cap_admits_a_line_of_exactly_the_bound() {
        let (mut client, mut peer) = pair();
        let mut line = vec![b'x'; SASL_LINE_BYTES];
        line.extend_from_slice(b"\r\n");
        peer.write_all(&line).unwrap();
        assert_eq!(client.read_sasl_line().unwrap().len(), SASL_LINE_BYTES);
    }
}
