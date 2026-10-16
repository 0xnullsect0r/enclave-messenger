//! Linux (and the BSDs): GStreamer, the desktop's own media framework,
//! loaded when a video is read (`libgstreamer-1.0.so.0`, `libgstapp`), so
//! Enclave neither links it nor needs it to start. `decodebin` picks the
//! decoder the system has for the file; the pipeline turns the picture
//! the way the camera held it, makes it RGBA at 30 frames a second, and
//! the sound 48 kHz mono, into two app sinks read here.

use super::{FPS, VideoError, VideoEvent};
use libloading::Library;
use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};

type Ptr = *mut c_void;
/// A sample's bytes, and the picture size its caps give (if any).
type Sampled = (Vec<u8>, Option<(u32, u32)>);

/// `GstMapInfo` (its layout is part of GStreamer's stable ABI).
#[repr(C)]
struct MapInfo {
    memory: Ptr,
    flags: c_int,
    data: *mut u8,
    size: usize,
    maxsize: usize,
    user_data: [Ptr; 4],
    reserved: [Ptr; 4],
}

/// `GError`.
#[repr(C)]
struct GError {
    domain: u32,
    code: c_int,
    message: *mut c_char,
}

const STATE_NULL: c_int = 1;
const STATE_PLAYING: c_int = 4;
const CHANGE_FAILURE: c_int = 0;
const MESSAGE_ERROR: c_uint = 1 << 1;
const MAP_READ: c_int = 1;
const FORMAT_TIME: c_int = 3;
/// 50 ms, in nanoseconds.
const WAIT_NS: u64 = 50_000_000;

/// The functions used, from the loaded libraries (kept loaded with them).
struct Gst {
    init_check: unsafe extern "C" fn(*mut c_int, *mut *mut *mut c_char, *mut *mut GError) -> c_int,
    parse_launch: unsafe extern "C" fn(*const c_char, *mut *mut GError) -> Ptr,
    bin_get_by_name: unsafe extern "C" fn(Ptr, *const c_char) -> Ptr,
    set_state: unsafe extern "C" fn(Ptr, c_int) -> c_int,
    get_bus: unsafe extern "C" fn(Ptr) -> Ptr,
    bus_pop_filtered: unsafe extern "C" fn(Ptr, c_uint) -> Ptr,
    message_parse_error: unsafe extern "C" fn(Ptr, *mut *mut GError, *mut *mut c_char),
    query_duration: unsafe extern "C" fn(Ptr, c_int, *mut i64) -> c_int,
    object_unref: unsafe extern "C" fn(Ptr),
    mini_object_unref: unsafe extern "C" fn(Ptr),
    sample_get_buffer: unsafe extern "C" fn(Ptr) -> Ptr,
    sample_get_caps: unsafe extern "C" fn(Ptr) -> Ptr,
    caps_get_structure: unsafe extern "C" fn(Ptr, c_uint) -> Ptr,
    structure_get_int: unsafe extern "C" fn(Ptr, *const c_char, *mut c_int) -> c_int,
    buffer_map: unsafe extern "C" fn(Ptr, *mut MapInfo, c_int) -> c_int,
    buffer_unmap: unsafe extern "C" fn(Ptr, *mut MapInfo),
    try_pull_sample: unsafe extern "C" fn(Ptr, u64) -> Ptr,
    is_eos: unsafe extern "C" fn(Ptr) -> c_int,
    error_free: unsafe extern "C" fn(*mut GError),
    free: unsafe extern "C" fn(Ptr),
    _libs: [Library; 3],
}

impl Gst {
    fn load() -> Result<Self, VideoError> {
        // SAFETY: loading the system's GLib and GStreamer libraries runs
        // only their initialisers, which have no preconditions.
        let open = |name: &str| unsafe { Library::new(name) }.map_err(|_| VideoError::NoDecoder);
        let glib = open("libglib-2.0.so.0")?;
        let gst = open("libgstreamer-1.0.so.0")?;
        let app = open("libgstapp-1.0.so.0")?;
        macro_rules! sym {
            ($lib:expr, $name:literal) => {
                // SAFETY: the symbol has the C signature of the field it
                // goes into (GStreamer 1.x's stable API), and the library
                // stays loaded as long as the pointer (`_libs`).
                *unsafe { $lib.get(concat!($name, "\0").as_bytes()) }
                    .map_err(|_| VideoError::NoDecoder)?
            };
        }
        Ok(Self {
            init_check: sym!(gst, "gst_init_check"),
            parse_launch: sym!(gst, "gst_parse_launch"),
            bin_get_by_name: sym!(gst, "gst_bin_get_by_name"),
            set_state: sym!(gst, "gst_element_set_state"),
            get_bus: sym!(gst, "gst_element_get_bus"),
            bus_pop_filtered: sym!(gst, "gst_bus_pop_filtered"),
            message_parse_error: sym!(gst, "gst_message_parse_error"),
            query_duration: sym!(gst, "gst_element_query_duration"),
            object_unref: sym!(gst, "gst_object_unref"),
            mini_object_unref: sym!(gst, "gst_mini_object_unref"),
            sample_get_buffer: sym!(gst, "gst_sample_get_buffer"),
            sample_get_caps: sym!(gst, "gst_sample_get_caps"),
            caps_get_structure: sym!(gst, "gst_caps_get_structure"),
            structure_get_int: sym!(gst, "gst_structure_get_int"),
            buffer_map: sym!(gst, "gst_buffer_map"),
            buffer_unmap: sym!(gst, "gst_buffer_unmap"),
            try_pull_sample: sym!(app, "gst_app_sink_try_pull_sample"),
            is_eos: sym!(app, "gst_app_sink_is_eos"),
            error_free: sym!(glib, "g_error_free"),
            free: sym!(glib, "g_free"),
            _libs: [glib, gst, app],
        })
    }

    /// A GError's message, freeing it.
    fn take_error(&self, e: *mut GError) -> String {
        if e.is_null() {
            return "unknown error".into();
        }
        // SAFETY: `e` is a GError GStreamer handed us; its message is a
        // NUL-terminated string (or null), and we free it once.
        unsafe {
            let msg = if (*e).message.is_null() {
                "unknown error".to_string()
            } else {
                CStr::from_ptr((*e).message).to_string_lossy().into_owned()
            };
            (self.error_free)(e);
            msg
        }
    }

    /// An error the pipeline posted, if any.
    fn bus_error(&self, pipeline: Ptr) -> Option<String> {
        // SAFETY: `pipeline` is a live element; the bus and message we get
        // are ours to unref, the parsed error and debug string to free.
        unsafe {
            let bus = (self.get_bus)(pipeline);
            if bus.is_null() {
                return None;
            }
            let msg = (self.bus_pop_filtered)(bus, MESSAGE_ERROR);
            (self.object_unref)(bus);
            if msg.is_null() {
                return None;
            }
            let mut err: *mut GError = std::ptr::null_mut();
            let mut debug: *mut c_char = std::ptr::null_mut();
            (self.message_parse_error)(msg, &mut err, &mut debug);
            if !debug.is_null() {
                (self.free)(debug.cast());
            }
            (self.mini_object_unref)(msg);
            Some(self.take_error(err))
        }
    }

    /// A sample's bytes, and its caps' width and height if it has them.
    fn sample(&self, sample: Ptr) -> Option<Sampled> {
        // SAFETY: `sample` is a GstSample we own (unreffed by the caller);
        // its buffer and caps are borrowed from it, the mapping is undone
        // before it goes, and `data` is valid for `size` bytes meanwhile.
        unsafe {
            let buffer = (self.sample_get_buffer)(sample);
            if buffer.is_null() {
                return None;
            }
            let mut map: MapInfo = std::mem::zeroed();
            if (self.buffer_map)(buffer, &mut map, MAP_READ) == 0 {
                return None;
            }
            let bytes = std::slice::from_raw_parts(map.data, map.size).to_vec();
            (self.buffer_unmap)(buffer, &mut map);
            let caps = (self.sample_get_caps)(sample);
            let size = if caps.is_null() {
                None
            } else {
                let s = (self.caps_get_structure)(caps, 0);
                let (mut w, mut h) = (0, 0);
                (!s.is_null()
                    && (self.structure_get_int)(s, c"width".as_ptr(), &mut w) != 0
                    && (self.structure_get_int)(s, c"height".as_ptr(), &mut h) != 0
                    && w > 0
                    && h > 0)
                    .then_some((w as u32, h as u32))
            };
            Some((bytes, size))
        }
    }
}

/// The pipeline for `path`: the file decoded, its picture and sound into
/// the app sinks `v` and `a`.
fn pipeline(path: &std::path::Path) -> Result<CString, VideoError> {
    let p = path
        .to_str()
        .ok_or_else(|| VideoError::Unreadable("the file's name".into()))?
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    CString::new(format!(
        "filesrc location=\"{p}\" ! decodebin name=d \
         d. ! queue ! videoflip video-direction=auto ! videoconvert ! videorate \
         ! video/x-raw,format=RGBA,framerate={FPS}/1 ! appsink name=v sync=false max-buffers=4 \
         d. ! queue ! audioconvert ! audioresample \
         ! audio/x-raw,format=S16LE,rate=48000,channels=1,layout=interleaved \
         ! appsink name=a sync=false max-buffers=64"
    ))
    .map_err(|_| VideoError::Unreadable("the file's name".into()))
}

pub(super) fn read(
    path: &std::path::Path,
    each: &mut dyn FnMut(VideoEvent<'_>) -> bool,
) -> Result<(), VideoError> {
    let g = Gst::load()?;
    let description = pipeline(path)?;
    // SAFETY: GStreamer may be initialised any number of times; the
    // pipeline and its sinks are live until the unrefs below, and every
    // sample pulled is unreffed once it is read.
    unsafe {
        let mut err: *mut GError = std::ptr::null_mut();
        if (g.init_check)(std::ptr::null_mut(), std::ptr::null_mut(), &mut err) == 0 {
            g.take_error(err);
            return Err(VideoError::NoDecoder);
        }
        let mut err: *mut GError = std::ptr::null_mut();
        let pipe = (g.parse_launch)(description.as_ptr(), &mut err);
        if pipe.is_null() {
            return Err(VideoError::Unreadable(g.take_error(err)));
        }
        if !err.is_null() {
            // A missing element (say, `videoflip` too old): not fatal.
            g.take_error(err);
        }
        let v = (g.bin_get_by_name)(pipe, c"v".as_ptr());
        let a = (g.bin_get_by_name)(pipe, c"a".as_ptr());
        let result = if v.is_null() || a.is_null() {
            Err(VideoError::Unreadable("GStreamer is missing parts".into()))
        } else if (g.set_state)(pipe, STATE_PLAYING) == CHANGE_FAILURE {
            Err(VideoError::Unreadable(
                g.bus_error(pipe).unwrap_or_else(|| "it won't play".into()),
            ))
        } else {
            pump(&g, pipe, v, a, each)
        };
        (g.set_state)(pipe, STATE_NULL);
        for e in [v, a] {
            if !e.is_null() {
                (g.object_unref)(e);
            }
        }
        (g.object_unref)(pipe);
        result
    }
}

/// Pull frames and sound until the picture ends.
///
/// # Safety
///
/// `pipe`, `v` and `a` are a live pipeline and its two app sinks.
unsafe fn pump(
    g: &Gst,
    pipe: Ptr,
    v: Ptr,
    a: Ptr,
    each: &mut dyn FnMut(VideoEvent<'_>) -> bool,
) -> Result<(), VideoError> {
    let mut started = false;
    let mut size = (0, 0);
    let sound = |g: &Gst, wait: u64, each: &mut dyn FnMut(VideoEvent<'_>) -> bool| -> bool {
        loop {
            // SAFETY: `a` is a live app sink; the sample is unreffed after
            // reading.
            let s = unsafe { (g.try_pull_sample)(a, wait) };
            if s.is_null() {
                return true;
            }
            let bytes = g.sample(s).map(|(b, _)| b).unwrap_or_default();
            // SAFETY: we own the sample.
            unsafe { (g.mini_object_unref)(s) };
            let pcm: Vec<i16> = bytes
                .chunks_exact(2)
                .map(|c| i16::from_le_bytes([c[0], c[1]]))
                .collect();
            if !pcm.is_empty() && !each(VideoEvent::Sound(&pcm)) {
                return false;
            }
        }
    };
    let mut idle = 0u32;
    loop {
        if let Some(why) = g.bus_error(pipe) {
            return Err(VideoError::Unreadable(why));
        }
        // SAFETY: `v` is a live app sink.
        let s = unsafe { (g.try_pull_sample)(v, WAIT_NS) };
        if s.is_null() {
            // SAFETY: as above.
            if unsafe { (g.is_eos)(v) } != 0 {
                break;
            }
            idle += 1;
            // Nothing for 30 s: give up.
            if idle > 600 {
                return Err(VideoError::Unreadable("it stopped".into()));
            }
        } else {
            idle = 0;
            let got = g.sample(s);
            // SAFETY: we own the sample.
            unsafe { (g.mini_object_unref)(s) };
            let Some((rgba, caps)) = got else { continue };
            if !started {
                let Some((w, h)) = caps else {
                    return Err(VideoError::Unreadable("no picture size".into()));
                };
                size = (w, h);
                let mut ns = 0i64;
                // SAFETY: `pipe` is live; the answer goes into `ns`.
                let duration_ms =
                    if unsafe { (g.query_duration)(pipe, FORMAT_TIME, &mut ns) } != 0 && ns > 0 {
                        ns as u64 / 1_000_000
                    } else {
                        0
                    };
                started = true;
                if !each(VideoEvent::Start {
                    width: w,
                    height: h,
                    duration_ms,
                }) {
                    return Err(VideoError::Stopped);
                }
            }
            if rgba.len() != size.0 as usize * size.1 as usize * 4 {
                return Err(VideoError::Unreadable("a frame of another size".into()));
            }
            if !each(VideoEvent::Frame(&rgba)) {
                return Err(VideoError::Stopped);
            }
        }
        if !sound(g, 0, each) {
            return Err(VideoError::Stopped);
        }
    }
    if !started {
        return Err(VideoError::Unreadable("it has no picture".into()));
    }
    // The rest of the sound.
    if !sound(g, WAIT_NS, each) {
        return Err(VideoError::Stopped);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real file through the real decoder, where this system has
    /// GStreamer's tools to make one (CI and most desktops).
    #[test]
    fn reads_a_video_file_with_sound() {
        let dir = std::env::temp_dir().join(format!("enclave-video-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("test.mkv");
        let made = std::process::Command::new("gst-launch-1.0")
            .args([
                "-q",
                "videotestsrc",
                "num-buffers=24",
                "!",
                "video/x-raw,width=96,height=64,framerate=24/1",
                "!",
                "videoconvert",
                "!",
                "avenc_mpeg4",
                "!",
                "matroskamux",
                "name=m",
                "!",
                "filesink",
            ])
            .arg(format!("location={}", file.display()))
            .args([
                "audiotestsrc",
                "num-buffers=44",
                "!",
                "audio/x-raw,rate=44100,channels=2",
                "!",
                "audioconvert",
                "!",
                "avenc_aac",
                "!",
                "m.",
            ])
            .status();
        if !made.is_ok_and(|s| s.success()) {
            eprintln!("skipping: no GStreamer tools to make a test video");
            return;
        }
        let (mut start, mut frames, mut sound) = (None, 0usize, 0usize);
        read(&file, &mut |e| {
            match e {
                VideoEvent::Start { width, height, .. } => start = Some((width, height)),
                VideoEvent::Frame(f) => {
                    assert_eq!(f.len(), 96 * 64 * 4);
                    frames += 1;
                }
                VideoEvent::Sound(s) => sound += s.len(),
            }
            true
        })
        .unwrap();
        assert_eq!(start, Some((96, 64)));
        // One second at 24 fps comes out as about 30 frames.
        assert!((28..=31).contains(&frames), "{frames}");
        // About a second of sound at 48 kHz.
        assert!(sound > 40_000, "{sound}");
        // Not a video.
        std::fs::write(dir.join("not.mkv"), b"hello").unwrap();
        assert!(read(&dir.join("not.mkv"), &mut |_| true).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
