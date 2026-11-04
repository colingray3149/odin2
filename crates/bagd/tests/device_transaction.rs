//! The flash and read transactions against a scripted firmware on a pseudo-terminal: the command
//! echo, `Size:`/`Ready?` chunk handshake, `write_chunk` appends and the install sequence run the
//! same bytes a Flipper sends, so the file that lands on the fake device is the one asserted.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use bagd::flipper::{FlipperCli, FlipperError};
use rustix::pty::{grantpt, openpt, ptsname, unlockpt, OpenptFlags};

/// Storage chunk the firmware reads per `write_chunk` slice; matches the host's.
const CHUNK: usize = 1024;

#[derive(Default)]
struct Device {
    files: BTreeMap<String, Vec<u8>>,
    /// What `update install` prints before the device reboots.
    install_output: &'static str,
}

struct FakeFlipper {
    node: PathBuf,
    device: Arc<Mutex<Device>>,
    /// The device end of the line stays open across host reconnects; closing it ends the firmware.
    line: Option<File>,
    serving: Option<JoinHandle<()>>,
}

impl FakeFlipper {
    fn attach(install_output: &'static str) -> Self {
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("open a pty");
        grantpt(&master).expect("grant the pty");
        unlockpt(&master).expect("unlock the pty");
        let node = PathBuf::from(
            ptsname(&master, Vec::new())
                .expect("pty node name")
                .to_str()
                .expect("utf-8 pty node")
                .to_owned(),
        );
        let line = File::options()
            .read(true)
            .write(true)
            .open(&node)
            .expect("open the pty line");
        let device = Arc::new(Mutex::new(Device {
            install_output,
            ..Device::default()
        }));
        let serving = {
            let device = Arc::clone(&device);
            std::thread::spawn(move || serve(File::from(master), &device))
        };
        Self {
            node,
            device,
            line: Some(line),
            serving: Some(serving),
        }
    }

    fn put(&self, path: &str, bytes: &[u8]) {
        self.device
            .lock()
            .unwrap()
            .files
            .insert(path.to_owned(), bytes.to_vec());
    }

    fn file(&self, path: &str) -> Option<Vec<u8>> {
        self.device.lock().unwrap().files.get(path).cloned()
    }

    fn cli(&self) -> FlipperCli {
        // The updater reboots without a prompt, so a good install ends by this wait running out.
        FlipperCli::new(&self.node).with_install_wait(Duration::from_millis(200))
    }
}

impl Drop for FakeFlipper {
    fn drop(&mut self) {
        self.line = None;
        if let Some(serving) = self.serving.take() {
            let ended = serving.join();
            if !std::thread::panicking() {
                ended.expect("the fake firmware ends cleanly");
            }
        }
    }
}

/// The next command line, or `None` once the line is closed.
fn read_line(master: &mut File) -> Option<String> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match master.read(&mut byte) {
            Ok(1) if byte[0] == b'\n' => {
                return Some(
                    String::from_utf8_lossy(&line)
                        .trim_end_matches('\r')
                        .to_owned(),
                )
            }
            Ok(1) => line.push(byte[0]),
            _ => return None,
        }
    }
}

fn quoted(command: &str) -> &str {
    command.split('"').nth(1).expect("a quoted path")
}

/// The firmware's side of the serial line, until the host closes it.
fn serve(mut master: File, device: &Mutex<Device>) {
    const PROMPT: &str = ">: ";
    while let Some(command) = read_line(&mut master) {
        if command.is_empty() {
            master.write_all(PROMPT.as_bytes()).unwrap();
            continue;
        }
        write!(master, "{command}\r\n").unwrap();
        if command.starts_with("storage read_chunks") {
            let path = quoted(&command).to_owned();
            let content = device.lock().unwrap().files.get(&path).cloned();
            let Some(content) = content else {
                write!(master, "Storage error: file/dir not exist\r\n{PROMPT}").unwrap();
                continue;
            };
            write!(master, "Size: {}\r\n", content.len()).unwrap();
            for chunk in content.chunks(CHUNK) {
                master.write_all(b"Ready?\r\n").unwrap();
                let mut answer = [0_u8; 1];
                master.read_exact(&mut answer).unwrap();
                assert_eq!(&answer, b"y", "the host answers each readiness line");
                master.write_all(chunk).unwrap();
            }
            master.write_all(PROMPT.as_bytes()).unwrap();
        } else if command.starts_with("storage write_chunk") {
            let declared: usize = command.rsplit(' ').next().unwrap().parse().unwrap();
            master.write_all(b"Ready\r\n").unwrap();
            let mut chunk = vec![0_u8; declared];
            master.read_exact(&mut chunk).unwrap();
            device
                .lock()
                .unwrap()
                .files
                .entry(quoted(&command).to_owned())
                .or_default()
                .extend_from_slice(&chunk);
            master.write_all(PROMPT.as_bytes()).unwrap();
        } else if command.starts_with("storage stat") {
            let size = device
                .lock()
                .unwrap()
                .files
                .get(quoted(&command))
                .map(Vec::len);
            match size {
                Some(size) => write!(master, "File, size: {size}b\r\n{PROMPT}").unwrap(),
                None => write!(master, "Storage error: file/dir not exist\r\n{PROMPT}").unwrap(),
            }
        } else if command.starts_with("storage remove") {
            device.lock().unwrap().files.remove(quoted(&command));
            master.write_all(PROMPT.as_bytes()).unwrap();
        } else if command.starts_with("storage mkdir") {
            write!(master, "Storage error: file/dir already exist\r\n{PROMPT}").unwrap();
        } else if command.starts_with("update install") {
            let output = device.lock().unwrap().install_output;
            master.write_all(output.as_bytes()).unwrap();
        } else {
            write!(master, "unknown command\r\n{PROMPT}").unwrap();
        }
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

#[test]
fn a_file_larger_than_one_chunk_is_read_back_byte_for_byte() {
    let device = FakeFlipper::attach("");
    let content = pattern(CHUNK * 2 + 77);
    device.put("/ext/log.bin", &content);
    let mut cli = device.cli();

    assert_eq!(cli.read_file("/ext/log.bin").unwrap(), content);
    assert!(matches!(
        cli.read_file("/ext/absent.bin"),
        Err(FlipperError::Storage(_))
    ));
    // A refused read leaves the line usable.
    assert_eq!(cli.read_file("/ext/log.bin").unwrap(), content);
}

#[test]
fn flashing_stages_the_package_and_installs_it() {
    let device = FakeFlipper::attach("Verifying update package at '/ext/update/fw.fuf'\r\nOK.\r\n");
    let package = pattern(CHUNK + 300);
    // A stale copy is replaced, not appended to.
    device.put("/ext/update/fw.fuf", b"old bytes");
    let local = tempfile::tempdir().unwrap();
    let image = local.path().join("fw.fuf");
    std::fs::write(&image, &package).unwrap();

    device
        .cli()
        .flash_fuf(&image)
        .expect("the install is affirmed");

    assert_eq!(device.file("/ext/update/fw.fuf"), Some(package));
}
