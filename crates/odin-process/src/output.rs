use std::io::{self, Read};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

impl CapturedOutput {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

pub(crate) struct OutputCollector {
    bytes: Vec<u8>,
    ceiling: usize,
    exceeded: bool,
}

impl OutputCollector {
    pub(crate) fn new(ceiling: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(ceiling.min(8_192)),
            ceiling,
            exceeded: false,
        }
    }

    pub(crate) fn drain(&mut self, reader: &mut impl Read) -> io::Result<()> {
        let mut buffer = [0_u8; 8_192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(count) => {
                    let remaining = self.ceiling.saturating_sub(self.bytes.len());
                    let retained = count.min(remaining);
                    self.bytes.extend_from_slice(&buffer[..retained]);
                    if retained != count {
                        self.exceeded = true;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn exceeded(&self) -> bool {
        self.exceeded
    }

    pub(crate) fn finish(self) -> CapturedOutput {
        CapturedOutput {
            bytes: self.bytes,
            truncated: self.exceeded,
        }
    }
}
