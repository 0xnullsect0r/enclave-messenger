//! The screen on Linux: on Wayland (and in a Flatpak) through the desktop
//! portal, which asks which screen or window to share and hands over a
//! PipeWire stream of it; on X11 by reading the root window.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Each picture: width, height, RGBA.
pub type Send = Box<dyn Fn(u32, u32, Vec<u8>) + std::marker::Send>;

type Ready = std::sync::mpsc::Sender<Result<pipewire::channel::Sender<()>, String>>;

/// The capture: stops when dropped.
pub struct Capture {
    quit: Option<pipewire::channel::Sender<()>>,
    stop: Arc<AtomicBool>,
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(q) = self.quit.take() {
            let _ = q.send(());
        }
    }
}

/// Start: the portal on Wayland, the root window on X11.
pub fn start(send: Send) -> Result<Capture, String> {
    let stop = Arc::new(AtomicBool::new(false));
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some()
        || std::env::var_os("FLATPAK_ID").is_some()
        || std::env::var_os("DISPLAY").is_none();
    if wayland {
        let quit = portal(send)?;
        Ok(Capture {
            quit: Some(quit),
            stop,
        })
    } else {
        x11(send, Arc::clone(&stop))?;
        Ok(Capture { quit: None, stop })
    }
}

/// The portal's screen cast: the person picks what to share in the
/// system's dialog; its PipeWire stream comes to a loop on a thread of its
/// own.
fn portal(send: Send) -> Result<pipewire::channel::Sender<()>, String> {
    use ashpd::desktop::screencast::{CursorMode, Screencast, SelectSourcesOptions, SourceType};
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("screen-share".into())
        .spawn(move || {
            let ready: Ready = ready_tx;
            // The session lives as long as this thread: the portal ends the
            // cast when it goes.
            let opened = futures_lite::future::block_on(async {
                let proxy = Screencast::new().await.map_err(|e| e.to_string())?;
                let session = proxy
                    .create_session(Default::default())
                    .await
                    .map_err(|e| e.to_string())?;
                proxy
                    .select_sources(
                        &session,
                        SelectSourcesOptions::default()
                            .set_cursor_mode(CursorMode::Embedded)
                            .set_sources(SourceType::Monitor | SourceType::Window)
                            .set_multiple(false),
                    )
                    .await
                    .and_then(|r| r.response())
                    .map_err(|e| e.to_string())?;
                let streams = proxy
                    .start(&session, None, Default::default())
                    .await
                    .and_then(|r| r.response())
                    .map_err(|_| "Screen sharing was cancelled.".to_string())?;
                let node = streams
                    .streams()
                    .first()
                    .map(|s| s.pipe_wire_node_id())
                    .ok_or("nothing was chosen to share")?;
                let fd = proxy
                    .open_pipe_wire_remote(&session, Default::default())
                    .await
                    .map_err(|e| e.to_string())?;
                Ok::<_, String>((node, fd, session, proxy))
            });
            let (node, fd, _session, _proxy) = match opened {
                Ok(o) => o,
                Err(e) => {
                    let _ = ready.send(Err(e));
                    return;
                }
            };
            if let Err(e) = pipewire_loop(node, fd, send, ready.clone()) {
                let _ = ready.send(Err(e));
            }
        })
        .map_err(|e| e.to_string())?;
    ready_rx
        .recv()
        .map_err(|_| "screen sharing stopped".to_string())?
}

/// Receive the stream until told to quit.
fn pipewire_loop(
    node: u32,
    fd: std::os::fd::OwnedFd,
    send: Send,
    ready: Ready,
) -> Result<(), String> {
    use pipewire::spa::param::format::{FormatProperties, MediaSubtype, MediaType};
    use pipewire::spa::param::video::{VideoFormat, VideoInfoRaw};
    use pipewire::spa::param::{ParamType, format_utils};
    use pipewire::spa::pod::{self, Pod, serialize::PodSerializer};
    use pipewire::spa::utils::{Direction, Fraction, Rectangle, SpaTypes};
    use pipewire::stream::{StreamFlags, StreamRc};
    let e = |e: pipewire::Error| e.to_string();
    pipewire::init();
    let main_loop = pipewire::main_loop::MainLoopRc::new(None).map_err(e)?;
    let context = pipewire::context::ContextRc::new(&main_loop, None).map_err(e)?;
    let core = context.connect_fd_rc(fd, None).map_err(e)?;
    let stream = StreamRc::new(
        core,
        "Enclave screen share",
        pipewire::properties::properties! {
            *pipewire::keys::MEDIA_TYPE => "Video",
            *pipewire::keys::MEDIA_CATEGORY => "Capture",
            *pipewire::keys::MEDIA_ROLE => "Screen",
        },
    )
    .map_err(e)?;
    let _listener = stream
        .add_local_listener_with_user_data(VideoInfoRaw::default())
        .param_changed(|_, info, id, param| {
            let Some(param) = param else { return };
            if id != ParamType::Format.as_raw() {
                return;
            }
            if let Ok((MediaType::Video, MediaSubtype::Raw)) = format_utils::parse_format(param) {
                let _ = info.parse(param);
            }
        })
        .process(move |stream, info| {
            let Some(mut buffer) = stream.dequeue_buffer() else {
                return;
            };
            let datas = buffer.datas_mut();
            let Some(d) = datas.first_mut() else { return };
            let size = info.size();
            let (w, h) = (size.width, size.height);
            let offset = d.chunk().offset() as usize;
            let stride = usize::try_from(d.chunk().stride()).unwrap_or(0);
            let format = info.format();
            let Some(bytes) = d.data() else { return };
            if w == 0 || h == 0 {
                return;
            }
            let row_len = w as usize * 4;
            let stride = if stride == 0 { row_len } else { stride };
            let mut rgba = Vec::with_capacity(row_len * h as usize);
            for y in 0..h as usize {
                let at = offset + y * stride;
                let Some(row) = bytes.get(at..at + row_len) else {
                    return;
                };
                for p in row.chunks_exact(4) {
                    match format {
                        VideoFormat::BGRx | VideoFormat::BGRA => {
                            rgba.extend_from_slice(&[p[2], p[1], p[0], 255]);
                        }
                        VideoFormat::RGBx | VideoFormat::RGBA => {
                            rgba.extend_from_slice(&[p[0], p[1], p[2], 255]);
                        }
                        _ => return,
                    }
                }
            }
            send(w, h, rgba);
        })
        .register()
        .map_err(e)?;
    let obj = pod::object!(
        SpaTypes::ObjectParamFormat,
        ParamType::EnumFormat,
        pod::property!(FormatProperties::MediaType, Id, MediaType::Video),
        pod::property!(FormatProperties::MediaSubtype, Id, MediaSubtype::Raw),
        pod::property!(
            FormatProperties::VideoFormat,
            Choice,
            Enum,
            Id,
            VideoFormat::BGRx,
            VideoFormat::BGRx,
            VideoFormat::BGRA,
            VideoFormat::RGBx,
            VideoFormat::RGBA
        ),
        pod::property!(
            FormatProperties::VideoSize,
            Choice,
            Range,
            Rectangle,
            Rectangle {
                width: 1920,
                height: 1080
            },
            Rectangle {
                width: 1,
                height: 1
            },
            Rectangle {
                width: 8192,
                height: 8192
            }
        ),
        pod::property!(
            FormatProperties::VideoFramerate,
            Choice,
            Range,
            Fraction,
            Fraction { num: 5, denom: 1 },
            Fraction { num: 0, denom: 1 },
            Fraction { num: 60, denom: 1 }
        ),
    );
    let values =
        PodSerializer::serialize(std::io::Cursor::new(Vec::new()), &pod::Value::Object(obj))
            .map_err(|e| format!("{e:?}"))?
            .0
            .into_inner();
    let mut params = [Pod::from_bytes(&values).ok_or("bad format")?];
    stream
        .connect(
            Direction::Input,
            Some(node),
            StreamFlags::AUTOCONNECT | StreamFlags::MAP_BUFFERS,
            &mut params,
        )
        .map_err(e)?;
    let (quit_tx, quit_rx) = pipewire::channel::channel::<()>();
    let ml = main_loop.clone();
    let _quit = quit_rx.attach(main_loop.loop_(), move |()| ml.quit());
    let _ = ready.send(Ok(quit_tx));
    main_loop.run();
    Ok(())
}

/// X11: the root window, five times a second.
fn x11(send: Send, stop: Arc<AtomicBool>) -> Result<(), String> {
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::{ConnectionExt, ImageFormat};
    let (conn, screen) = x11rb::connect(None).map_err(|e| e.to_string())?;
    let root = conn.setup().roots.get(screen).ok_or("no X screen")?;
    let (window, w, h) = (root.root, root.width_in_pixels, root.height_in_pixels);
    std::thread::Builder::new()
        .name("screen-share".into())
        .spawn(move || {
            let gap = std::time::Duration::from_millis(u64::from(1000 / super::FPS));
            while !stop.load(Ordering::SeqCst) {
                let at = std::time::Instant::now();
                let pixels = usize::from(w) * usize::from(h);
                if let Ok(c) = conn.get_image(ImageFormat::Z_PIXMAP, window, 0, 0, w, h, !0)
                    && let Ok(img) = c.reply()
                    && img.depth >= 24
                    && img.data.len() >= pixels * 4
                {
                    // 24/32-bit TrueColor: B, G, R, pad.
                    let rgba = img
                        .data
                        .chunks_exact(4)
                        .take(pixels)
                        .flat_map(|p| [p[2], p[1], p[0], 255])
                        .collect();
                    send(u32::from(w), u32::from(h), rgba);
                }
                std::thread::sleep(gap.saturating_sub(at.elapsed()));
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}
