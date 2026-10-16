//! Images (`docs/15-client.md` §3, media policy).
//!
//! Only JPEG and PNG are accepted, recognised by their first bytes (never
//! by name or MIME type). Everything else is a plain file: never decoded,
//! never previewed.
//!
//! * [`sanitize`] runs on the **sender**: decode, apply the EXIF
//!   orientation, shrink to at most [`MAX_SIDE`] pixels on the long side,
//!   and encode a new file (JPEG at quality 85, or PNG when the picture has
//!   transparency). Nothing of the original file survives but its pixels:
//!   EXIF (GPS, camera, time), XMP, ICC profiles and trailing data are gone.
//! * [`thumbnail`] runs on the **receiver**, inside `mediad`: decode and
//!   shrink to raw RGBA for display.
//!
//! Both refuse inputs over [`MAX_INPUT`] bytes and pictures over
//! [`MAX_PIXELS`] before decoding any pixel data, so a small file can't
//! claim a huge canvas. This crate has no `unsafe` and runs where a bug
//! can't reach keys: the receiver's decoder in its own confined process.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod call;
pub mod callvideo;
mod exif;
mod resize;
pub mod video;
pub mod voice;

/// Largest file accepted for decoding.
pub const MAX_INPUT: usize = 64 << 20;
/// Largest picture accepted (25 megapixels).
pub const MAX_PIXELS: u64 = 25_000_000;
/// Longest side of a sent picture.
pub const MAX_SIDE: u32 = 4096;
/// JPEG quality of sent pictures.
pub const JPEG_QUALITY: u8 = 85;

/// Why an image could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MediaError {
    /// Not a JPEG or PNG.
    #[error("not a JPEG or PNG image")]
    NotAnImage,
    /// Over [`MAX_INPUT`] or [`MAX_PIXELS`], or zero-sized.
    #[error("the image is too large")]
    TooLarge,
    /// The decoder refused it.
    #[error("the image is damaged")]
    Damaged,
    /// Encoding failed.
    #[error("couldn't encode the image")]
    Encode,
    /// A kind of file Enclave doesn't read (say, a float WAV).
    #[error("unsupported format")]
    Unsupported,
}

/// Result type.
pub type Result<T> = core::result::Result<T, MediaError>;

/// Image formats accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// JPEG.
    Jpeg,
    /// PNG.
    Png,
}

impl Format {
    /// MIME type.
    pub fn mime(self) -> &'static str {
        match self {
            Format::Jpeg => "image/jpeg",
            Format::Png => "image/png",
        }
    }

    /// File extension.
    pub fn extension(self) -> &'static str {
        match self {
            Format::Jpeg => "jpg",
            Format::Png => "png",
        }
    }
}

/// The format of `bytes`, from its signature.
pub fn detect(bytes: &[u8]) -> Option<Format> {
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some(Format::Jpeg)
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some(Format::Png)
    } else {
        None
    }
}

/// Decoded pixels, 8-bit RGBA, row by row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rgba {
    /// Width.
    pub width: u32,
    /// Height.
    pub height: u32,
    /// `width × height × 4` bytes.
    pub pixels: Vec<u8>,
}

impl Rgba {
    fn opaque(&self) -> bool {
        self.pixels.chunks_exact(4).all(|p| p[3] == 255)
    }
}

/// A re-encoded picture, ready to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sanitized {
    /// Its format.
    pub format: Format,
    /// Width.
    pub width: u32,
    /// Height.
    pub height: u32,
    /// The new file.
    pub bytes: Vec<u8>,
}

/// Decode `bytes` to upright RGBA.
pub fn decode(bytes: &[u8]) -> Result<Rgba> {
    if bytes.len() > MAX_INPUT {
        return Err(MediaError::TooLarge);
    }
    match detect(bytes).ok_or(MediaError::NotAnImage)? {
        Format::Jpeg => decode_jpeg(bytes),
        Format::Png => decode_png(bytes),
    }
}

/// Re-encode a picture for sending (see the crate docs).
pub fn sanitize(bytes: &[u8]) -> Result<Sanitized> {
    sanitize_max(bytes, MAX_SIDE)
}

/// [`sanitize`], shrunk to at most `max_side` pixels on the long side
/// (stickers).
pub fn sanitize_max(bytes: &[u8], max_side: u32) -> Result<Sanitized> {
    let img = decode(bytes)?;
    let img = resize::fit(&img, max_side.clamp(1, MAX_SIDE));
    if img.opaque() {
        let mut out = Vec::new();
        let rgb: Vec<u8> = img
            .pixels
            .chunks_exact(4)
            .flat_map(|p| [p[0], p[1], p[2]])
            .collect();
        jpeg_encoder::Encoder::new(&mut out, JPEG_QUALITY)
            .encode(
                &rgb,
                u16::try_from(img.width).map_err(|_| MediaError::TooLarge)?,
                u16::try_from(img.height).map_err(|_| MediaError::TooLarge)?,
                jpeg_encoder::ColorType::Rgb,
            )
            .map_err(|_| MediaError::Encode)?;
        Ok(Sanitized {
            format: Format::Jpeg,
            width: img.width,
            height: img.height,
            bytes: out,
        })
    } else {
        let mut out = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut out, img.width, img.height);
            enc.set_color(png::ColorType::Rgba);
            enc.set_depth(png::BitDepth::Eight);
            let mut w = enc.write_header().map_err(|_| MediaError::Encode)?;
            w.write_image_data(&img.pixels)
                .map_err(|_| MediaError::Encode)?;
            w.finish().map_err(|_| MediaError::Encode)?;
        }
        Ok(Sanitized {
            format: Format::Png,
            width: img.width,
            height: img.height,
            bytes: out,
        })
    }
}

/// Decode and shrink to at most `max_side` pixels on the long side.
pub fn thumbnail(bytes: &[u8], max_side: u32) -> Result<Rgba> {
    let img = decode(bytes)?;
    Ok(resize::fit(&img, max_side.max(1)))
}

fn check_size(width: u64, height: u64) -> Result<()> {
    if width == 0 || height == 0 || width * height > MAX_PIXELS {
        return Err(MediaError::TooLarge);
    }
    Ok(())
}

fn decode_jpeg(bytes: &[u8]) -> Result<Rgba> {
    use zune_core::bytestream::ZCursor;
    use zune_core::colorspace::ColorSpace;
    use zune_core::options::DecoderOptions;
    let opts = DecoderOptions::default()
        .jpeg_set_out_colorspace(ColorSpace::RGBA)
        .set_max_width(1 << 16)
        .set_max_height(1 << 16);
    let mut d = zune_jpeg::JpegDecoder::new_with_options(ZCursor::new(bytes), opts);
    d.decode_headers().map_err(|_| MediaError::Damaged)?;
    let info = d.info().ok_or(MediaError::Damaged)?;
    let (w, h) = (u32::from(info.width), u32::from(info.height));
    check_size(u64::from(w), u64::from(h))?;
    let pixels = d.decode().map_err(|_| MediaError::Damaged)?;
    if pixels.len() != w as usize * h as usize * 4 {
        return Err(MediaError::Damaged);
    }
    let orientation = d.exif().and_then(|e| exif::orientation(e)).unwrap_or(1);
    Ok(exif::orient(
        Rgba {
            width: w,
            height: h,
            pixels,
        },
        orientation,
    ))
}

fn decode_png(bytes: &[u8]) -> Result<Rgba> {
    let limits = png::Limits {
        bytes: MAX_PIXELS as usize * 8,
    };
    let mut d = png::Decoder::new_with_limits(std::io::Cursor::new(bytes), limits);
    d.set_transformations(png::Transformations::normalize_to_color8());
    let mut r = d.read_info().map_err(|_| MediaError::Damaged)?;
    let (w, h) = {
        let i = r.info();
        (i.width, i.height)
    };
    check_size(u64::from(w), u64::from(h))?;
    let mut buf = vec![0; r.output_buffer_size().ok_or(MediaError::TooLarge)?];
    let out = r.next_frame(&mut buf).map_err(|_| MediaError::Damaged)?;
    buf.truncate(out.buffer_size());
    let (w, h) = (out.width, out.height);
    let n = w as usize * h as usize;
    let pixels: Vec<u8> = match out.color_type {
        png::ColorType::Rgba => buf,
        png::ColorType::Rgb => buf
            .chunks_exact(3)
            .flat_map(|p| [p[0], p[1], p[2], 255])
            .collect(),
        png::ColorType::GrayscaleAlpha => buf
            .chunks_exact(2)
            .flat_map(|p| [p[0], p[0], p[0], p[1]])
            .collect(),
        png::ColorType::Grayscale => buf.iter().flat_map(|&g| [g, g, g, 255]).collect(),
        png::ColorType::Indexed => return Err(MediaError::Damaged),
    };
    if pixels.len() != n * 4 {
        return Err(MediaError::Damaged);
    }
    Ok(Rgba {
        width: w,
        height: h,
        pixels,
    })
}
