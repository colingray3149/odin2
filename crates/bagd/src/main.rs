//! Fixed argv for the Flipper Zero on its stable by-id node.
//!
//! `flash` copies one `.fuf` onto `/ext/update` and runs the firmware
//! `update install` command. `read` copies one `/ext` or `/int` file off
//! the device with `storage read_chunks`. Neither command is a shell.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use bagd::flipper::{self, FlipperCli};

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("flipper: {error}");
            ExitCode::from(1)
        }
    }
}

fn run(args: Vec<String>) -> Result<(), flipper::FlipperError> {
    let (port, command, rest) = split(&args)?;
    let mut cli = FlipperCli::new(port);
    match command {
        "flash" => {
            let [image] = one(rest, "flash")?;
            cli.flash_fuf(PathBuf::from(image).as_path())
        }
        "read" => {
            let [device_path, out] = two(rest, "read")?;
            let bytes = cli.read_file(device_path)?;
            std::fs::write(out, &bytes).map_err(|error| {
                flipper::FlipperError::Protocol(format!("cannot write {out}: {error}"))
            })?;
            println!("read {} bytes from {device_path}", bytes.len());
            Ok(())
        }
        other => Err(flipper::FlipperError::Protocol(format!(
            "unknown command {other:?}; want flash or read"
        ))),
    }
}

fn split(args: &[String]) -> Result<(&str, &str, &[String]), flipper::FlipperError> {
    match args {
        [port, command, rest @ ..] => Ok((port, command, rest)),
        _ => Err(flipper::FlipperError::Protocol(
            "usage: flipper <by-id-node> flash <image.fuf> | flipper <by-id-node> read <device-path> <out>"
                .to_owned(),
        )),
    }
}

fn one<'a>(rest: &'a [String], command: &str) -> Result<&'a [String; 1], flipper::FlipperError> {
    rest.try_into().map_err(|_| {
        flipper::FlipperError::Protocol(format!("flipper {command} takes exactly one path"))
    })
}

fn two<'a>(rest: &'a [String], command: &str) -> Result<&'a [String; 2], flipper::FlipperError> {
    rest.try_into().map_err(|_| {
        flipper::FlipperError::Protocol(format!("flipper {command} takes exactly two paths"))
    })
}
