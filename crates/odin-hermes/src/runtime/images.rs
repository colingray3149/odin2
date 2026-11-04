//! Images a seat's model sees: photos the owner sends ride his turn as image
//! blocks, and `media_view` returns one image it was asked to look at. Both
//! are JPEGs downscaled until they fit a byte bound, because one OMP stdin
//! frame (prompt or host tool result) is at most 1 MiB.

use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use image::{codecs::jpeg::JpegEncoder, imageops::FilterType, DynamicImage, ImageDecoder as _};
use serde_json::{json, Value};

/// Images one turn carries; more are named but not attached.
pub(crate) const MAX_TURN_IMAGES: usize = 4;
/// Base64 bytes of one turn image: four fit a prompt frame beside its text.
pub const TURN_IMAGE_BASE64: usize = 160 * 1024;
/// Longest edge and JPEG quality, tried in order until the image fits.
const LADDER: [(u32, u8); 6] = [
    (1568, 80),
    (1280, 80),
    (1280, 70),
    (1024, 70),
    (800, 65),
    (640, 60),
];

/// Where a staged photo's seat-sized JPEG lives beside the original.
pub(crate) fn turn_image_path(dir: &Path, index: usize) -> PathBuf {
    dir.join(format!("{index}.view.jpg"))
}

/// The marker a staged photo leaves in the turn text; the bridge replaces it
/// with "image N, attached to this message" and the image block itself.
pub(crate) fn turn_image_marker(intake: &str) -> String {
    format!("{MARKER_OPEN}{intake}{MARKER_CLOSE}")
}
/// Whether a turn's text carries a staged photo.
pub(crate) fn carries_image(text: &str) -> bool {
    text.contains(MARKER_OPEN)
}
const MARKER_OPEN: &str = "<odin-image intake=\"";
const MARKER_CLOSE: &str = "\">";

/// Whether an attachment is a picture, by MIME type or file extension.
pub(crate) fn is_image(content_type: Option<&str>, filename: &str) -> bool {
    content_type.is_some_and(|kind| kind.starts_with("image/"))
        || filename.rsplit_once('.').is_some_and(|(_, extension)| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "jpg" | "jpeg" | "png" | "gif" | "webp" | "heic" | "heif"
            )
        })
}

/// The image as a JPEG of at most `max_base64` base64 bytes, upright and no
/// larger than 1568 px on its long edge.
pub fn view_jpeg(bytes: &[u8], max_base64: usize) -> Result<Vec<u8>, String> {
    let reader = image::ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|error| format!("the image could not be read: {error}"))?;
    let format = reader.format();
    let mut decoder = reader.into_decoder().map_err(|error| match format {
        None => "it is not an image Odin can decode (JPEG, PNG, GIF or WebP)".to_owned(),
        Some(format) => format!("its {format:?} data could not be decoded: {error}"),
    })?;
    let orientation = decoder
        .orientation()
        .map_err(|error| format!("its orientation could not be read: {error}"))?;
    let mut picture = DynamicImage::from_decoder(decoder)
        .map_err(|error| format!("the image could not be decoded: {error}"))?;
    picture.apply_orientation(orientation);
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
            .map_err(|error| format!("the image could not be encoded as JPEG: {error}"))?;
        if jpeg.len().div_ceil(3) * 4 <= max_base64 {
            return Ok(jpeg);
        }
    }
    Err(format!("it does not fit {max_base64} bytes even at 640 px"))
}

/// One image content block of a provider message or tool result.
pub fn image_block(jpeg: &[u8]) -> Value {
    json!({
        "type": "image",
        "mimeType": "image/jpeg",
        "data": base64::engine::general_purpose::STANDARD.encode(jpeg),
    })
}


/// Resolves staged-photo markers in a turn into image blocks, reading only
/// seat-sized JPEGs beneath the intake root.
pub struct IntakeImages {
    root: PathBuf,
}

impl IntakeImages {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            root: state_dir.join("intake"),
        }
    }

    fn jpeg(&self, intake: &str) -> Result<Vec<u8>, String> {
        let (message, index) = intake
            .split_once('/')
            .filter(|(message, _)| {
                !message.is_empty() && message.bytes().all(|byte| byte.is_ascii_digit())
            })
            .and_then(|(message, index)| Some((message, index.parse::<u16>().ok()?)))
            .filter(|(_, index)| *index > 0)
            .ok_or_else(|| format!("{intake:?} is not an intake id"))?;
        let file = odin_confined_fs::Capability::seal(&self.root)
            .and_then(|root| root.open_read(&turn_image_path(Path::new(message), index.into())))
            .map_err(|error| format!("intake {intake} has no staged image: {error}"))?;
        let mut jpeg = Vec::new();
        file.take(TURN_IMAGE_BASE64 as u64)
            .read_to_end(&mut jpeg)
            .map_err(|error| format!("intake {intake}'s image could not be read: {error}"))?;
        Ok(jpeg)
    }
}

impl odin_omp::live::control::TurnImages for IntakeImages {
    fn attach(&self, text: &str) -> (String, Vec<Value>) {
        let mut out = String::with_capacity(text.len());
        let mut images = Vec::new();
        let mut rest = text;
        while let Some(at) = rest.find(MARKER_OPEN) {
            out.push_str(&rest[..at]);
            let after = &rest[at + MARKER_OPEN.len()..];
            let Some(end) = after.find(MARKER_CLOSE).filter(|end| *end <= 26) else {
                out.push_str(MARKER_OPEN);
                rest = after;
                continue;
            };
            let intake = &after[..end];
            rest = &after[end + MARKER_CLOSE.len()..];
            if images.len() == MAX_TURN_IMAGES {
                out.push_str(&format!(
                    "not attached, since one message carries at most {MAX_TURN_IMAGES} images; \
                     look at it with media_view {{\"intake\":\"{intake}\"}}"
                ));
                continue;
            }
            match self.jpeg(intake) {
                Ok(jpeg) => {
                    images.push(image_block(&jpeg));
                    out.push_str(&format!("image {}, attached to this message", images.len()));
                }
                Err(reason) => out.push_str(&format!("not attached: {reason}")),
            }
        }
        out.push_str(rest);
        (out, images)
    }
}

#[cfg(test)]
mod tests {
    use odin_omp::live::control::TurnImages as _;

    use super::*;

    fn photo(width: u32, height: u32) -> Vec<u8> {
        // Noise, so JPEG cannot compress it away.
        let picture = image::RgbImage::from_fn(width, height, |x, y| {
            let n = x
                .wrapping_mul(2_654_435_761)
                .wrapping_add(y.wrapping_mul(40_503));
            image::Rgb([(n >> 3) as u8, (n >> 11) as u8, (n >> 19) as u8])
        });
        let mut png = Vec::new();
        DynamicImage::ImageRgb8(picture)
            .write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        png
    }

    #[test]
    fn a_large_photo_shrinks_until_it_fits_and_text_is_refused() {
        let jpeg = view_jpeg(&photo(2000, 1500), TURN_IMAGE_BASE64).unwrap();
        assert!(jpeg.len().div_ceil(3) * 4 <= TURN_IMAGE_BASE64);
        let shrunk = image::load_from_memory(&jpeg).unwrap();
        assert!(shrunk.width().max(shrunk.height()) <= 1568);
        let small =
            image::load_from_memory(&view_jpeg(&photo(300, 200), TURN_IMAGE_BASE64).unwrap())
                .unwrap();
        assert_eq!(
            (small.width(), small.height()),
            (300, 200),
            "never upscaled"
        );
        assert!(view_jpeg(b"just some text", TURN_IMAGE_BASE64)
            .unwrap_err()
            .contains("not an image"));
    }

    #[test]
    fn markers_become_numbered_images_and_never_leave_the_intake_root() {
        let state = tempfile::tempdir().unwrap();
        let dir = state.path().join("intake/100");
        std::fs::create_dir_all(&dir).unwrap();
        let jpeg = view_jpeg(&photo(64, 48), TURN_IMAGE_BASE64).unwrap();
        for index in 1..=5 {
            std::fs::write(turn_image_path(&dir, index), &jpeg).unwrap();
        }
        let images = IntakeImages::new(state.path());
        let text = turn_image_marker("100/9")
            + " "
            + &turn_image_marker("../100/1")
            + "\n"
            + &(1..=5)
                .map(|index| {
                    format!(
                        "[photo {index}: {}]\n",
                        turn_image_marker(&format!("100/{index}"))
                    )
                })
                .collect::<String>();
        assert!(carries_image(&text) && !carries_image("[photo 1]"));
        let (out, blocks) = images.attach(&text);
        assert_eq!(blocks.len(), 4);
        assert_eq!(blocks[0]["mimeType"], "image/jpeg");
        assert!(
            out.contains("[photo 1: image 1, attached to this message]"),
            "{out}"
        );
        assert!(
            out.contains("[photo 4: image 4, attached to this message]"),
            "{out}"
        );
        assert!(
            out.contains("[photo 5: not attached, since one message carries at most 4 images"),
            "{out}"
        );
        assert!(
            out.contains("not attached: intake 100/9 has no staged image"),
            "{out}"
        );
        assert!(
            out.contains("not attached: \"../100/1\" is not an intake id"),
            "{out}"
        );
        assert!(!out.contains(MARKER_OPEN), "{out}");
        assert_eq!(
            images.attach("no photos here"),
            ("no photos here".to_owned(), Vec::new())
        );
    }
}
