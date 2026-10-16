//! AV1 decoding for `mediad` (`docs/15-client.md` §5.3).
//!
//! rav1d is the Rust port of dav1d, but it exposes only dav1d's C
//! interface, so calling it takes `unsafe`. This crate is the one place
//! that does: a declared exception (PLAN §22, "rav1d … sandbox; software
//! decoding"), kept as small as it can be. It is built without rav1d's
//! assembly, single-threaded, for 8-bit 4:2:0 only, with a frame-size
//! limit, and it only ever runs inside `mediad`: confined, with no network,
//! no files and a 2 GiB address-space cap.
//!
//! [`Decoder::decode`] takes one temporal unit (the bytes of one frame as
//! the encoder produced them) and returns the frames that came out, as
//! tightly packed I420 planes.

use rav1d::include::dav1d::data::Dav1dData;
use rav1d::include::dav1d::dav1d::{Dav1dContext, Dav1dSettings};
use rav1d::include::dav1d::headers::DAV1D_PIXEL_LAYOUT_I420;
use rav1d::include::dav1d::picture::Dav1dPicture;
use rav1d::src::lib::{
    dav1d_close, dav1d_data_create, dav1d_data_unref, dav1d_default_settings, dav1d_get_picture,
    dav1d_open, dav1d_picture_unref, dav1d_send_data,
};
use std::mem::MaybeUninit;
use std::ptr::NonNull;

/// Largest frame decoded, in pixels (the sender never makes more than
/// 480 × 480).
pub const MAX_FRAME_PIXELS: u32 = 1920 * 1080;
/// Largest temporal unit accepted.
pub const MAX_UNIT: usize = 1 << 20;

/// Why decoding failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Av1Error {
    /// The decoder couldn't start.
    #[error("decoder unavailable")]
    Open,
    /// Not a valid AV1 stream, or one we don't decode (not 8-bit 4:2:0,
    /// too large).
    #[error("bad AV1 data")]
    Bad,
}

/// One decoded frame: 8-bit I420, planes packed without padding.
#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Luma, `width × height`.
    pub y: Vec<u8>,
    /// Blue-difference chroma, `⌈width/2⌉ × ⌈height/2⌉`.
    pub u: Vec<u8>,
    /// Red-difference chroma, as `u`.
    pub v: Vec<u8>,
}

/// An AV1 decoder.
pub struct Decoder {
    ctx: Option<Dav1dContext>,
}

/// dav1d's "try again": minus the platform's `EAGAIN` (11 on Linux and
/// Windows, 35 on macOS and iOS), as rav1d defines it.
const EAGAIN: i32 = -libc::EAGAIN;

impl Decoder {
    /// A new decoder.
    pub fn new() -> Result<Self, Av1Error> {
        let mut s = MaybeUninit::<Dav1dSettings>::uninit();
        // SAFETY: `dav1d_default_settings` writes a whole `Dav1dSettings`
        // through the pointer, which points to writable memory of that type.
        unsafe { dav1d_default_settings(NonNull::from(&mut s).cast()) };
        // SAFETY: initialized by the call above.
        let mut s = unsafe { s.assume_init() };
        s.n_threads = 1;
        s.max_frame_delay = 1;
        s.frame_size_limit = MAX_FRAME_PIXELS;
        // No logging (the default writes to stderr): a logger is a cookie
        // and a callback, both optional pointers, and all-zero means
        // `None` for both, which rav1d reads as "no logger".
        // SAFETY: every field of the logger is an `Option` of a non-null
        // pointer type, for which all-zero bytes are `None`.
        s.logger = unsafe { std::mem::zeroed() };
        let mut ctx: Option<Dav1dContext> = None;
        // SAFETY: both pointers come from live, exclusive references of the
        // types dav1d_open expects; it writes the context into `ctx`.
        let r = unsafe { dav1d_open(Some(NonNull::from(&mut ctx)), Some(NonNull::from(&mut s))) };
        if r.0 != 0 || ctx.is_none() {
            return Err(Av1Error::Open);
        }
        Ok(Self { ctx })
    }

    /// Decode one temporal unit; returns the frames it completed (usually
    /// one).
    pub fn decode(&mut self, unit: &[u8]) -> Result<Vec<Frame>, Av1Error> {
        if unit.is_empty() || unit.len() > MAX_UNIT {
            return Err(Av1Error::Bad);
        }
        let mut data = Dav1dData::default();
        // SAFETY: `data` is a live `Dav1dData`; dav1d_data_create allocates
        // `unit.len()` bytes owned by it and returns their address.
        let buf = unsafe { dav1d_data_create(Some(NonNull::from(&mut data)), unit.len()) };
        if buf.is_null() {
            return Err(Av1Error::Bad);
        }
        // SAFETY: `buf` points to `unit.len()` writable bytes that don't
        // overlap `unit`.
        unsafe { std::ptr::copy_nonoverlapping(unit.as_ptr(), buf, unit.len()) };
        let mut frames = Vec::new();
        let result = (|| {
            // dav1d takes the data or asks for pictures to be fetched first;
            // either way it makes progress, but never trust that blindly.
            for _ in 0..64 {
                // SAFETY: the context is open; `data` is a live Dav1dData
                // that dav1d consumes (setting its size to 0) when it takes it.
                let r = unsafe { dav1d_send_data(self.ctx, Some(NonNull::from(&mut data))) };
                if r.0 != 0 && r.0 != EAGAIN {
                    return Err(Av1Error::Bad);
                }
                while let Some(f) = self.picture()? {
                    frames.push(f);
                }
                if data.sz == 0 {
                    return Ok(());
                }
            }
            Err(Av1Error::Bad)
        })();
        // SAFETY: `data` is a live Dav1dData; unref releases what is left.
        unsafe { dav1d_data_unref(Some(NonNull::from(&mut data))) };
        result.map(|()| frames)
    }

    /// The next finished picture, if any.
    fn picture(&mut self) -> Result<Option<Frame>, Av1Error> {
        let mut pic = Dav1dPicture::default();
        // SAFETY: the context is open and `pic` is a live, default Dav1dPicture
        // for dav1d to fill.
        let r = unsafe { dav1d_get_picture(self.ctx, Some(NonNull::from(&mut pic))) };
        // rav1d writes a picture (an empty one, holding an allocation) into
        // `pic` whatever it answers, so it is released on every path.
        let frame = (r.0 == 0).then(|| copy_out(&pic));
        // SAFETY: `pic` holds what dav1d_get_picture wrote; this releases
        // it, and nothing borrows it any more.
        unsafe { dav1d_picture_unref(Some(NonNull::from(&mut pic))) };
        match frame {
            None if r.0 == EAGAIN => Ok(None),
            None => Err(Av1Error::Bad),
            Some(f) => f.map(Some),
        }
    }
}

/// Copy a picture's planes out of dav1d's buffers.
fn copy_out(pic: &Dav1dPicture) -> Result<Frame, Av1Error> {
    let p = &pic.p;
    if p.bpc != 8 || p.layout != DAV1D_PIXEL_LAYOUT_I420 || p.w <= 0 || p.h <= 0 {
        return Err(Av1Error::Bad);
    }
    let (w, h) = (p.w as usize, p.h as usize);
    if w * h > MAX_FRAME_PIXELS as usize {
        return Err(Av1Error::Bad);
    }
    let (cw, ch) = (w.div_ceil(2), h.div_ceil(2));
    let plane = |i: usize, stride: isize, pw: usize, ph: usize| -> Result<Vec<u8>, Av1Error> {
        let base = pic.data[i].ok_or(Av1Error::Bad)?.cast::<u8>();
        if stride < pw as isize {
            return Err(Av1Error::Bad);
        }
        let mut out = Vec::with_capacity(pw * ph);
        for row in 0..ph {
            // SAFETY: dav1d's 8-bit plane `i` has `ph` rows of at least `pw`
            // bytes, `stride` bytes apart, valid while the picture is held.
            let line = unsafe {
                std::slice::from_raw_parts(base.as_ptr().offset(row as isize * stride), pw)
            };
            out.extend_from_slice(line);
        }
        Ok(out)
    };
    Ok(Frame {
        width: w as u32,
        height: h as u32,
        y: plane(0, pic.stride[0], w, h)?,
        u: plane(1, pic.stride[1], cw, ch)?,
        v: plane(2, pic.stride[1], cw, ch)?,
    })
}

impl Drop for Decoder {
    fn drop(&mut self) {
        // SAFETY: `ctx` was opened by dav1d_open; dav1d_close takes it and
        // leaves `None`.
        unsafe { dav1d_close(Some(NonNull::from(&mut self.ctx))) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Found by the nightly fuzzer (a leak of rav1d's empty picture when
    /// it had none to give); run under valgrind or LeakSanitizer to see it.
    #[test]
    fn garbage_is_refused_without_leaking() {
        let mut d = Decoder::new().unwrap_or_else(|_| unreachable!());
        assert!(d.decode(&[0]).is_err() || d.decode(&[0]).is_ok_and(|f| f.is_empty()));
        let _ = d.decode(&[0x12, 0, 0x0a]);
    }
}
