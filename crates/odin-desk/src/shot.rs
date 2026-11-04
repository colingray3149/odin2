//!
//! Screenshots: grim (wlr-screencopy) writes raw PPM for a logical
//! rectangle; it is scaled and encoded as JPEG here, sized for a model.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use image::{codecs::jpeg::JpegEncoder, imageops::FilterType, DynamicImage, RgbImage};

use crate::niri::Rect;

/// Longest edge and quality, best first, until the base64 fits.
const LADDER: [(u32, u8); 5] = [(1568, 80), (1280, 75), (1024, 70), (800, 65), (640, 60)];
/// The base64 budget of one image in a tool result (Odin's `VIEW_IMAGE_BASE64`).
const MAX_BASE64: usize = 640 * 1024;
/// Every screenshot is also kept here for the owner (`/tmp` ages files out after a week).
pub(crate) const SAVED: &str = "/tmp/odin-desk";

/// One encoded screenshot and where its pixels are on the desktop.
pub(crate) struct Shot {
    pub jpeg: Vec<u8>,
    pub width: u32,
    pub height: u32,
    /// The desktop rectangle the image shows.
    pub rect: Rect,
    pub saved: PathBuf,
}

impl Shot {
    /// The desktop point under image pixel (x, y).
    pub(crate) fn to_desktop(&self, x: f64, y: f64) -> Result<(f64, f64), String> {
        if !(0.0..=f64::from(self.width)).contains(&x)
            || !(0.0..=f64::from(self.height)).contains(&y)
        {
            return Err(format!(
                "({x}, {y}) is outside your last screenshot ({}x{})",
                self.width, self.height
            ));
        }
        Ok((
            self.rect.x + x * self.rect.w / f64::from(self.width),
            self.rect.y + y * self.rect.h / f64::from(self.height),
        ))
    }
}

/// Captures `rect` with grim, run as `command` (the session's environment).
pub(crate) fn capture(
    mut command: Command,
    rect: Rect,
    serial: u64,
    saved: &Path,
) -> Result<Shot, String> {
    let grim = command.get_program().to_owned();
    let mut child = command
        .args(["-t", "ppm", "-g", &rect.grim(), "-"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("grim ({}) could not start: {error}", grim.to_string_lossy()))?;
    let mut ppm = Vec::new();
    child
        .stdout
        .take()
        .ok_or("grim gave no stdout")?
        .read_to_end(&mut ppm)
        .map_err(|error| format!("reading grim's image failed: {error}"))?;
    let output = child
        .wait_with_output()
        .map_err(|error| format!("grim did not finish: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "grim failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let picture = DynamicImage::ImageRgb8(parse_ppm(&ppm)?);
    let (jpeg, width, height) = encode(&picture)?;
    let saved = save(saved, &jpeg, serial)?;
    Ok(Shot {
        jpeg,
        width,
        height,
        rect,
        saved,
    })
}

/// grim's binary PPM: `P6\n<w> <h>\n255\n` then RGB bytes.
fn parse_ppm(bytes: &[u8]) -> Result<RgbImage, String> {
    let bad = |why: &str| format!("grim's PPM is unreadable: {why}");
    let mut fields = Vec::new();
    let mut at = 0;
    while fields.len() < 4 {
        while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
            at += 1;
        }
        let start = at;
        while bytes
            .get(at)
            .is_some_and(|byte| !byte.is_ascii_whitespace())
        {
            at += 1;
        }
        if start == at {
            return Err(bad("short header"));
        }
        fields.push(
            std::str::from_utf8(&bytes[start..at])
                .map_err(|error| bad(&format!("header is not text: {error}")))?,
        );
    }
    let number = |text: &str| {
        text.parse::<u32>()
            .map_err(|error| bad(&format!("size is not a number: {error}")))
    };
    if fields[0] != "P6" || fields[3] != "255" {
        return Err(bad("not an 8-bit P6 image"));
    }
    let (width, height) = (number(fields[1])?, number(fields[2])?);
    let pixels = bytes
        .get(at + 1..)
        .ok_or_else(|| bad("no pixels"))?
        .to_vec();
    RgbImage::from_raw(width, height, pixels)
        .ok_or_else(|| bad("pixel data does not match its size"))
}

fn encode(picture: &DynamicImage) -> Result<(Vec<u8>, u32, u32), String> {
    let longest = picture.width().max(picture.height());
    for (edge, quality) in LADDER {
        let scaled = if longest > edge {
            picture.resize(edge, edge, FilterType::Triangle)
        } else {
            picture.clone()
        };
        let mut jpeg = Vec::new();
        JpegEncoder::new_with_quality(&mut jpeg, quality)
            .encode_image(&scaled.to_rgb8())
            .map_err(|error| format!("the screenshot could not be encoded: {error}"))?;
        if jpeg.len().div_ceil(3) * 4 <= MAX_BASE64 {
            return Ok((jpeg, scaled.width(), scaled.height()));
        }
    }
    Err("the screenshot does not fit a tool result even at 640 px".to_owned())
}

fn save(directory: &Path, jpeg: &[u8], serial: u64) -> Result<PathBuf, String> {
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
    let failed = |error: std::io::Error| {
        format!(
            "keeping the screenshot in {} failed: {error}",
            directory.display()
        )
    };
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .map_err(failed)?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let path = directory.join(format!("{stamp}-{serial}.jpg"));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut file| file.write_all(jpeg))
        .map_err(failed)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_reads_the_ppm_grim_writes_keeps_a_copy_and_names_a_grim_failure() {
        let dir = tempfile::tempdir().unwrap();
        let kept = dir.path().join("kept");
        let rect = Rect {
            x: 0.0,
            y: 0.0,
            w: 2.0,
            h: 2.0,
        };
        let grim = crate::fixture::script(
            dir.path(),
            "grim",
            "printf 'P6\\n2 2\\n255\\n\\001\\002\\003\\004\\005\\006\\007\\010\\011\\012\\013\\014'",
        );
        let shot = capture(Command::new(&grim), rect, 7, &kept).unwrap();
        assert_eq!((shot.width, shot.height), (2, 2));
        assert_eq!(std::fs::read(&shot.saved).unwrap(), shot.jpeg);
        assert!(shot.saved.starts_with(&kept));

        let grim = crate::fixture::script(dir.path(), "grim", "echo no output >&2; exit 3");
        let error = capture(Command::new(grim), rect, 8, &kept).err().unwrap();
        assert!(error.contains("no output"), "{error}");
    }
}
