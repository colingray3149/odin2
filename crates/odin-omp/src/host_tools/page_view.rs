//! One exported page as the image block a model actually sees.
//!
//! `media.view` cannot read a workload pod's `/export`. `report.view` reads
//! one page PNG there and returns it as an `images` block; the side channel
//! attaches that block to the tool result. The JPEG matches the seat view
//! bound: longest edge at most 1568 px, base64 at most 640 KiB.

use std::io::Cursor;

use base64::Engine as _;
use image::codecs::jpeg::JpegEncoder;
use image::{DynamicImage, ImageReader};
use serde_json::{json, Value};

/// Base64 bytes of the one page a `report.view` result carries.
pub const PAGE_VIEW_BASE64: usize = 640 * 1024;
/// The largest page PNG `report.view` brings back to show, and the most this decodes.
pub const MAX_PAGE_PNG_BYTES: usize = 8 * 1024 * 1024;
/// Longest edge and JPEG quality, tried until the page fits.
const LADDER: [(u32, u8); 6] = [
    (1568, 80),
    (1280, 80),
    (1280, 70),
    (1024, 70),
    (800, 65),
    (640, 60),
];

/// The page as one image block, or why it cannot be shown.
pub fn page_image(png: &[u8]) -> Result<Value, String> {
    if png.len() > MAX_PAGE_PNG_BYTES {
        return Err(format!(
            "the page is over the {MAX_PAGE_PNG_BYTES}-byte limit"
        ));
    }
    let jpeg = page_jpeg(png)?;
    Ok(json!({
        "type": "image",
        "mimeType": "image/jpeg",
        "data": base64::engine::general_purpose::STANDARD.encode(jpeg),
    }))
}

fn page_jpeg(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|error| format!("the page could not be read: {error}"))?;
    if reader.format() != Some(image::ImageFormat::Png) {
        return Err("the page is not a PNG".to_owned());
    }
    let picture = DynamicImage::from_decoder(
        reader
            .into_decoder()
            .map_err(|error| format!("the page PNG could not be decoded: {error}"))?,
    )
    .map_err(|error| format!("the page could not be decoded: {error}"))?;
    let longest = picture.width().max(picture.height());
    for (edge, quality) in LADDER {
        let scaled = if longest > edge {
            picture.resize(edge, edge, image::imageops::FilterType::Triangle)
        } else {
            picture.clone()
        };
        let mut jpeg = Vec::new();
        JpegEncoder::new_with_quality(&mut jpeg, quality)
            .encode_image(&scaled.to_rgb8())
            .map_err(|error| format!("the page could not be encoded as JPEG: {error}"))?;
        if jpeg.len().div_ceil(3) * 4 <= PAGE_VIEW_BASE64 {
            return Ok(jpeg);
        }
    }
    Err(format!(
        "the page does not fit {PAGE_VIEW_BASE64} bytes even at 640 px"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(width: u32, height: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        image::ImageEncoder::write_image(
            image::codecs::png::PngEncoder::new(&mut bytes),
            &[0x3a, 0x7a, 0xc2, 0xff].repeat((width * height) as usize),
            width,
            height,
            image::ExtendedColorType::Rgba8,
        )
        .expect("png");
        bytes
    }

    #[test]
    fn a_page_png_becomes_one_jpeg_image_block() {
        let block = page_image(&png(80, 140)).expect("view");
        assert_eq!(block["type"], "image");
        assert_eq!(block["mimeType"], "image/jpeg");
        let data = block["data"].as_str().expect("data");
        assert!(data.len() <= PAGE_VIEW_BASE64, "{}", data.len());
        let jpeg = base64::engine::general_purpose::STANDARD
            .decode(data)
            .expect("base64");
        assert!(jpeg.starts_with(&[0xff, 0xd8]));
    }

    /// A page too busy to fit at full size steps down the ladder until it does, and still shows.
    #[test]
    fn a_detailed_page_is_downscaled_until_it_fits() {
        let side = 1000u32;
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let noise: Vec<u8> = (0..side * side * 4)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect();
        let mut page = Vec::new();
        image::ImageEncoder::write_image(
            image::codecs::png::PngEncoder::new(&mut page),
            &noise,
            side,
            side,
            image::ExtendedColorType::Rgba8,
        )
        .expect("png");
        let block = page_image(&page).expect("a stepped-down view");
        let data = block["data"].as_str().expect("data");
        assert!(data.len() <= PAGE_VIEW_BASE64, "{}", data.len());
        let jpeg = base64::engine::general_purpose::STANDARD
            .decode(data)
            .expect("base64");
        let shown = image::load_from_memory(&jpeg).expect("jpeg decodes");
        assert!(
            shown.width() < side,
            "the page was scaled down: {}",
            shown.width()
        );
    }

    #[test]
    fn a_page_over_the_limit_is_refused_before_it_is_decoded() {
        let error = page_image(&vec![0; MAX_PAGE_PNG_BYTES + 1]).expect_err("too large");
        assert!(error.contains("over the"), "{error}");
    }
}
