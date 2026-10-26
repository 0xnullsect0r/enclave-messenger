//! The app's shell: the window, its callbacks, and the vault's outputs
//! applied to it ([`run`]). The desktop programs and the Android and iOS
//! apps start here.
//!
//! `enclave` opens the profile in the platform's data directory (or
//! `--profile DIR`), or sets one up on a server picked from the server
//! list built into release builds (`--server-list FILE` and `--foundation
//! FILE` otherwise). Keys live in a separate `enclave-vault` process when
//! it is installed next to this binary (`--single-process` keeps them in a
//! thread instead). Servers are reached over the mixnet (through
//! `enclave-netd` and `enclave-nymd`; `--nym-env` for a local mixnet or
//! the sandbox); `--server SERVER_ID=nym:ADDRESS` names the home server
//! directly, and `--server SERVER_ID=HOST:PORT` a dev server
//! (`enclave-server`) over TCP in a build with the `dev-transport` feature
//! (never a release; add `--kt-pins FILE`, written by the server, to use
//! usernames). `enclave --demo` (a build with the `demo` feature) runs a
//! self-contained demo: a local server and a demo contact, nothing leaves
//! the computer. `enclave --panic-wipe [--profile DIR]` erases the profile
//! without opening it (`docs/14-storage.md` §5), for an OS shortcut.
use crate::{AppWindow, Screen, Sheet, vault, view};
use enclave_ipc::{Cmd, Out};
use enclave_vault::Mode;
use slint::{ComponentHandle, Model as _};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

/// Largest file sent from here (`enclave_core::files::MAX_ATTACHMENT`);
/// it crosses to the vault in parts ([`stage`]).
const MAX_FILE: u64 = 100 * 1024 * 1024;
/// Largest backup read from here (with its photos and files).
const MAX_BACKUP: u64 = enclave_ipc::MAX_STAGED as u64;

/// Hand `bytes` to the vault in parts it keeps for the next command;
/// false when they fit in that command itself.
fn stage(t: &tokio::sync::mpsc::UnboundedSender<Cmd>, bytes: &[u8]) -> bool {
    if bytes.len() <= enclave_ipc::FILE_PART {
        return false;
    }
    for part in bytes.chunks(enclave_ipc::FILE_PART) {
        let _ = t.send(Cmd::Stage(part.to_vec()));
    }
    true
}
/// Largest picture file read for a sticker pack (it is redrawn small).
const MAX_STICKER_FILE: u64 = 4 * 1024 * 1024;
/// Most bytes read for one pack (one IPC message).
const MAX_PACK_FILES: u64 = 14 * 1024 * 1024;
/// The largest picture read for a profile photo (it is redrawn at 512 px).
const PHOTO_MAX_BYTES: u64 = 16 * 1024 * 1024;

#[cfg(desktop)]
/// The Downloads folder (or home, or the temporary directory).
fn downloads() -> std::path::PathBuf {
    directories::UserDirs::new()
        .and_then(|u| {
            u.download_dir()
                .map(std::path::Path::to_path_buf)
                .or_else(|| Some(u.home_dir().to_path_buf()))
        })
        .unwrap_or_else(std::env::temp_dir)
}

#[cfg(desktop)]
/// A file's name as the sender gave it, made safe to suggest: its last
/// component only, never hidden.
fn safe_name(name: &str) -> String {
    std::path::Path::new(name)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.') && !n.is_empty())
        .unwrap_or_else(|| "file".into())
}

#[cfg(desktop)]
/// Ask where to save a file the vault handed over (an attachment, a
/// backup), starting in Downloads with its name, and write it there.
fn save_with_dialog(ui: &AppWindow, name: String, bytes: Vec<u8>) {
    let w = ui.as_weak();
    let _ = slint::spawn_local(async move {
        let chosen = rfd::AsyncFileDialog::new()
            .set_directory(downloads())
            .set_file_name(safe_name(&name))
            .save_file()
            .await;
        let note = match chosen {
            Some(f) => match std::fs::write(f.path(), &bytes) {
                Ok(()) => format!("Saved to {}", f.path().display()),
                Err(e) => format!("Couldn't save {name}: {e}"),
            },
            None => format!("{name} wasn't saved."),
        };
        if let Some(ui) = w.upgrade() {
            ui.set_file_note(crate::i18n::tr(&note).into());
        }
    });
}

#[cfg(desktop)]
/// Where "Open with…" leaves the file it hands over: one folder only this
/// user reads, emptied each time and when the app starts.
fn open_dir() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("enclave-open-{}", whoami_tag()))
}

#[cfg(desktop)]
fn whoami_tag() -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .hash(&mut h);
    format!("{:08x}", h.finish() as u32)
}

#[cfg(desktop)]
/// "Open with…": write the file (the window warned first) and hand it to
/// the system, which opens it in the app that takes its kind.
fn open_with(ui: &AppWindow, name: &str, bytes: &[u8]) {
    let dir = open_dir();
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join(safe_name(name));
    let written = std::fs::create_dir_all(&dir).and_then(|()| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        std::fs::write(&path, bytes)
    });
    let opened = written.and_then(|()| {
        #[cfg(target_os = "linux")]
        let mut c = std::process::Command::new("xdg-open");
        #[cfg(target_os = "macos")]
        let mut c = std::process::Command::new("open");
        #[cfg(windows)]
        let mut c = std::process::Command::new("explorer.exe");
        c.arg(&path).spawn().map(|_| ())
    });
    if let Err(e) = opened {
        ui.set_file_note(crate::i18n::tr(&format!("Couldn't open {name}: {e}")).into());
    }
}

#[cfg(desktop)]
/// "Open in maps": hand the place to the system's maps handler (`geo:` on
/// Linux, Apple Maps on macOS, Windows Maps), after the window's warning.
fn open_map(lat: f64, lon: f64, label: &str) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    let (mut c, uri) = (
        std::process::Command::new("xdg-open"),
        format!("geo:{lat:.6},{lon:.6}"),
    );
    #[cfg(target_os = "macos")]
    let (mut c, uri) = (
        std::process::Command::new("open"),
        format!(
            "maps://?ll={lat:.6},{lon:.6}&q={}",
            url_escape(if label.is_empty() { "Location" } else { label })
        ),
    );
    #[cfg(windows)]
    let (mut c, uri) = (
        std::process::Command::new("explorer.exe"),
        format!("bingmaps:?cp={lat:.6}~{lon:.6}&lvl=16"),
    );
    #[cfg(not(target_os = "macos"))]
    let _ = label;
    c.arg(uri).spawn().map(|_| ())
}

#[cfg(all(desktop, target_os = "macos"))]
/// Percent-encode for a URL's query.
fn url_escape(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Two coordinates as the window shows them, "52.520000, 13.405000".
fn parse_coordinates(s: &str) -> Option<(f64, f64)> {
    let (a, b) = s.split_once(',')?;
    let (lat, lon) = (a.trim().parse::<f64>().ok()?, b.trim().parse::<f64>().ok()?);
    ((-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon)).then_some((lat, lon))
}

#[cfg(desktop)]
/// Say on the terminal which window system and scale the window got, once
/// it is up: a blurry window on a high-DPI screen is one drawn at a smaller
/// scale and stretched (under XWayland, say), which this shows.
fn log_window(ui: &AppWindow) {
    let weak = ui.as_weak();
    slint::Timer::single_shot(std::time::Duration::from_millis(500), move || {
        use slint::winit_030::WinitWindowAccessor as _;
        use slint::winit_030::winit::raw_window_handle::{HasWindowHandle as _, RawWindowHandle};
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let system = ui
            .window()
            .with_winit_window(|w| match w.window_handle().map(|h| h.as_raw()) {
                Ok(RawWindowHandle::Wayland(_)) => "Wayland",
                Ok(RawWindowHandle::Xlib(_) | RawWindowHandle::Xcb(_)) => "X11",
                Ok(RawWindowHandle::Win32(_)) => "Windows",
                Ok(RawWindowHandle::AppKit(_)) => "macOS",
                _ => "unknown",
            })
            .unwrap_or("unknown");
        eprintln!(
            "enclave: window on {system}, scale {:.2}",
            ui.window().scale_factor()
        );
    });
}

#[cfg(desktop)]
/// Show a desktop notification, unless the window is in front (the person
/// sees the message already). Shown from a thread of its own: on Linux it
/// is a D-Bus call.
fn notify(ui: &AppWindow, n: enclave_ipc::Notice) {
    use slint::winit_030::WinitWindowAccessor as _;
    let in_front = ui
        .window()
        .with_winit_window(|w| w.has_focus() && w.is_minimized() != Some(true))
        .unwrap_or(false);
    if in_front {
        return;
    }
    let _ = std::thread::Builder::new()
        .name("enclave-notify".into())
        .spawn(move || {
            let mut note = notify_rust::Notification::new();
            note.appname("Enclave")
                .summary(&n.title)
                .body(&crate::format::preview(&n.body));
            #[cfg(windows)]
            note.app_id(NOTIFY_APP_ID);
            #[cfg(all(unix, not(target_os = "macos")))]
            note.icon("com.aricummings.Enclave");
            let _ = note.show();
        });
}

/// Where crash reports go when the person chooses to send one: Enclave
/// Support's username, set when the foundation publishes it
/// (`ENCLAVE_SUPPORT` at build time). Without it the app offers only
/// saving the report.
const SUPPORT: Option<&str> = option_env!("ENCLAVE_SUPPORT");

/// Show this device's crash reports and handle what the person does with
/// them: read, save as a file, send to Enclave Support as a message
/// request (end-to-end encrypted like any other), or delete.
fn crash_reports(
    ui: &AppWindow,
    dir: Option<std::path::PathBuf>,
    tx: tokio::sync::mpsc::UnboundedSender<Cmd>,
) {
    let Some(dir) = dir else {
        return;
    };
    let show = |ui: &AppWindow, dir: &std::path::Path| {
        let rows: Vec<crate::CrashRow> = enclave_crash::reports(dir)
            .iter()
            .map(|r| crate::CrashRow {
                process: r.process().into(),
                when: crash_time(r.at).into(),
                text: r.text.clone().into(),
            })
            .collect();
        ui.set_crash_reports(slint::ModelRc::new(slint::VecModel::from(rows)));
    };
    ui.set_support_known(SUPPORT.is_some());
    show(ui, &dir);
    let report = {
        let dir = dir.clone();
        move |i: i32| {
            usize::try_from(i)
                .ok()
                .and_then(|i| enclave_crash::reports(&dir).into_iter().nth(i))
        }
    };
    let w = ui.as_weak();
    let r = report.clone();
    ui.on_save_crash(move |i| {
        if let (Some(ui), Some(rep)) = (w.upgrade(), r(i)) {
            let name = format!("enclave-crash-{}.txt", rep.at);
            save_with_dialog(&ui, name, rep.text.into_bytes());
        }
    });
    let w = ui.as_weak();
    let r = report.clone();
    let d = dir.clone();
    ui.on_send_crash(move |i| {
        if let (Some(support), Some(rep)) = (SUPPORT, r(i)) {
            let _ = tx.send(Cmd::Add(support.to_string(), rep.text.clone()));
            let _ = enclave_crash::remove(&rep);
            if let Some(ui) = w.upgrade() {
                show(&ui, &d);
            }
        }
    });
    let w = ui.as_weak();
    let d = dir.clone();
    ui.on_delete_crash(move |i| {
        if let Some(rep) = report(i) {
            let _ = enclave_crash::remove(&rep);
        }
        if let Some(ui) = w.upgrade() {
            show(&ui, &d);
        }
    });
    let w = ui.as_weak();
    ui.on_delete_crashes(move || {
        enclave_crash::remove_all(&dir);
        if let Some(ui) = w.upgrade() {
            show(&ui, &dir);
        }
    });
}

/// The voice note playing: which (`conversation:seq`) and its sound.
type Playing = Arc<std::sync::Mutex<Option<(String, crate::audio::Playback)>>>;

/// Voice notes: recording from the microphone (sent as a WAV recording,
/// which the vault re-encodes), and playing.
fn voice_notes(ui: &AppWindow, tx: tokio::sync::mpsc::UnboundedSender<Cmd>, playing: Playing) {
    let recording: Rc<RefCell<Option<crate::audio::Recorder>>> = Rc::default();
    let (r, w) = (Rc::clone(&recording), ui.as_weak());
    ui.on_record_voice(move || {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        enclave_platform::phone::ask_microphone();
        match crate::audio::Recorder::start() {
            Ok(rec) => *r.borrow_mut() = Some(rec),
            Err(e) => {
                if let Some(ui) = w.upgrade() {
                    ui.set_voice_recording(false);
                    ui.set_status_line(
                        format!("{}: {e}", crate::i18n::tr("Couldn't record")).into(),
                    );
                }
            }
        }
    });
    let (r, w, t) = (Rc::clone(&recording), ui.as_weak(), tx.clone());
    ui.on_stop_voice(move |send| {
        let Some(rec) = r.borrow_mut().take() else {
            return;
        };
        if !send {
            return;
        }
        let wav = rec.finish();
        // Under a fifth of a second is a slip of the finger.
        if wav.len() < 44 + 2 * crate::audio::RATE as usize / 5 {
            return;
        }
        if let Some(ui) = w.upgrade() {
            let id = ui.get_current_id().to_string();
            let _ = t.send(Cmd::SendFile(id, "voice.wav".into(), wav, String::new()));
        }
    });
    let (p, t) = (Arc::clone(&playing), tx);
    ui.on_play_voice(move |id, seq| {
        if let Ok(mut p) = p.lock() {
            *p = None;
        }
        if let Ok(seq) = seq.parse() {
            let _ = t.send(Cmd::PlayVoice(id.to_string(), seq));
        }
    });
    let w = ui.as_weak();
    ui.on_stop_playing(move || {
        if let Ok(mut p) = playing.lock() {
            *p = None;
        }
        if let Some(ui) = w.upgrade() {
            ui.set_voice_playing("".into());
        }
    });
}

/// Release updates: "Check for updates", "Verify this build", and (where
/// this install updates itself) "Update" (`crate::updater`).
fn updates(ui: &AppWindow, tx: tokio::sync::mpsc::UnboundedSender<Cmd>) {
    let t = tx.clone();
    ui.on_check_updates(move || {
        let _ = t.send(Cmd::CheckUpdates);
    });
    let t = tx.clone();
    ui.on_start_call(move |conversation, video, direct| {
        // A phone asks for the microphone now, not at install.
        #[cfg(any(target_os = "android", target_os = "ios"))]
        enclave_platform::phone::ask_microphone();
        let _ = t.send(Cmd::StartCall(conversation.to_string(), video, direct));
    });
    let t = tx.clone();
    ui.on_answer_call(move || {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        enclave_platform::phone::ask_microphone();
        let _ = t.send(Cmd::AnswerCall);
    });
    let t = tx.clone();
    ui.on_answer_call_direct(move || {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        enclave_platform::phone::ask_microphone();
        let _ = t.send(Cmd::AnswerCallDirect);
    });
    let t = tx.clone();
    ui.on_decline_call(move || {
        let _ = t.send(Cmd::DeclineCall);
    });
    let t = tx.clone();
    ui.on_end_call(move || {
        let _ = t.send(Cmd::EndCall);
    });
    let t = tx.clone();
    ui.on_mute_call(move |on| {
        let _ = t.send(Cmd::CallMute(on));
    });
    let t = tx.clone();
    ui.on_camera_call(move |on| {
        let _ = t.send(Cmd::CallCamera(on));
    });
    let t = tx.clone();
    ui.on_start_group_call(move |conversation, video| {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        enclave_platform::phone::ask_microphone();
        let _ = t.send(Cmd::StartGroupCall(conversation.to_string(), video));
    });
    let t = tx.clone();
    ui.on_join_group_call(move |conversation| {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        enclave_platform::phone::ask_microphone();
        let _ = t.send(Cmd::JoinGroupCall(conversation.to_string()));
    });
    let t = tx.clone();
    ui.on_hand_call(move |up| {
        let _ = t.send(Cmd::CallHand(up));
    });
    let t = tx.clone();
    ui.on_react_call(move |emoji| {
        let _ = t.send(Cmd::CallReact(emoji.to_string()));
    });
    let t = tx.clone();
    ui.on_screen_call(move |on| {
        let _ = t.send(Cmd::CallScreen(on));
    });
    let t = tx.clone();
    ui.on_create_call_link(move |lobby| {
        let _ = t.send(Cmd::CreateCallLink(lobby));
    });
    let t = tx.clone();
    ui.on_admit_call(move |who| {
        let _ = t.send(Cmd::AdmitToCall(u32::from_ne_bytes(who.to_ne_bytes())));
    });
    let t = tx.clone();
    ui.on_refuse_call(move |who| {
        let _ = t.send(Cmd::RefuseFromCall(u32::from_ne_bytes(who.to_ne_bytes())));
    });
    #[cfg(desktop)]
    {
        use crate::updater::{self, Install};
        match updater::install() {
            Install::Managed(how) => {
                ui.set_can_self_update(false);
                ui.set_update_how(crate::i18n::tr(how).into());
            }
            _ => ui.set_can_self_update(true),
        }
        let t = tx.clone();
        ui.on_verify_build(move || {
            let t = t.clone();
            // Hashing the programs takes a moment: not on the UI thread.
            let _ = std::thread::Builder::new()
                .name("enclave-verify".into())
                .spawn(move || {
                    let _ = t.send(Cmd::VerifyBuild(updater::build_hashes()));
                });
        });
        let w = ui.as_weak();
        ui.on_get_update(move || {
            let Some(ui) = w.upgrade() else {
                return;
            };
            let tag = ui.get_update_release().to_string();
            if tag.is_empty() || !ui.get_update_progress().is_empty() {
                return;
            }
            ui.set_update_progress(crate::i18n::tr("Starting…").into());
            let w = w.clone();
            let _ = std::thread::Builder::new()
                .name("enclave-update".into())
                .spawn(move || {
                    let show = {
                        let w = w.clone();
                        move |p: String| {
                            let _ = w.upgrade_in_event_loop(move |ui| {
                                ui.set_update_progress(crate::i18n::tr(&p).into());
                            });
                        }
                    };
                    match updater::update(&tag, show.clone()) {
                        // The installer, or the new copy, takes over.
                        Ok(()) => {
                            let _ = slint::quit_event_loop();
                        }
                        Err(e) => show(format!("The update didn't install: {e}")),
                    }
                });
        });
    }
    #[cfg(not(desktop))]
    {
        // Phones update from their store; Android's direct APK users get
        // the notice and the store's or F-Droid's update.
        ui.set_can_self_update(false);
        ui.set_update_how(
            crate::i18n::tr("Update Enclave from the store you installed it from.").into(),
        );
        let _ = tx;
    }
}

/// "9 Oct 2026, 14:02" in local time.
fn crash_time(at: u64) -> String {
    use chrono::TimeZone;
    chrono::Local
        .timestamp_opt(at as i64, 0)
        .single()
        .map(|t| t.format("%-d %b %Y, %H:%M").to_string())
        .unwrap_or_default()
}

/// The app's id for notifications (Windows toasts need the installer's
/// Start menu shortcut to carry it, `packaging/windows`).
#[cfg(all(desktop, windows))]
const NOTIFY_APP_ID: &str = "com.aricummings.Enclave";

/// Put a scanned code into the field `target` names (see `scan` in the UI).
fn put_code(ui: &AppWindow, target: i32, code: &str) {
    let code: slint::SharedString = code.trim().into();
    match target {
        1 => ui.set_add_link(code),
        2 => ui.set_meet_input(code),
        3 => ui.set_share_request_input(code),
        4 => ui.set_link_code(code),
        _ => {
            // The next empty share field.
            if ui.get_restore_s1().is_empty() {
                ui.set_restore_s1(code);
            } else if ui.get_restore_s2().is_empty() {
                ui.set_restore_s2(code);
            } else if ui.get_restore_s3().is_empty() {
                ui.set_restore_s3(code);
            } else if ui.get_restore_s4().is_empty() {
                ui.set_restore_s4(code);
            } else {
                ui.set_restore_s5(code);
            }
        }
    }
}

/// Put chosen files into the path field `what` names (see `browse`).
fn put_paths(ui: &AppWindow, what: i32, paths: &[String]) {
    if paths.is_empty() {
        return;
    }
    let joined: slint::SharedString = paths.join("; ").into();
    match what {
        0 => ui.set_restore_file(joined),
        1 => ui.set_check_file(joined),
        3 => ui.set_pack_paths(joined),
        // Our profile photo: used at once.
        4 => ui.invoke_set_photo(paths[0].clone().into()),
        5 => ui.set_story_path(paths[0].clone().into()),
        // A video to send: read and sent at once, with the caption.
        6 => {
            ui.invoke_send_video_file(paths[0].clone().into(), ui.get_attach_caption());
            ui.set_attach_caption("".into());
            ui.set_sheet(crate::Sheet::None);
        }
        _ => ui.set_attach_path(joined),
    }
}

#[cfg(desktop)]
thread_local! {
    /// The scan in progress, owned by the UI thread.
    static SCAN: std::cell::RefCell<Option<crate::camera::Scan>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(desktop)]
/// Scan a code with the camera into the field `target` names (see `scan`
/// in the UI).
fn scan(ui: &AppWindow, target: i32) {
    use crate::camera::{self, Event};
    ui.set_scan_error("".into());
    ui.set_scan_frame(slint::Image::default());
    ui.set_scanning(true);
    let w = ui.as_weak();
    let running = camera::start(move |e| {
        let _ = w.upgrade_in_event_loop(move |ui| {
            if !ui.get_scanning() {
                return;
            }
            match e {
                Event::Frame(width, height, grey) => {
                    let mut buf = slint::SharedPixelBuffer::<slint::Rgb8Pixel>::new(width, height);
                    for (px, g) in buf.make_mut_slice().iter_mut().zip(grey) {
                        *px = slint::Rgb8Pixel { r: g, g, b: g };
                    }
                    ui.set_scan_frame(slint::Image::from_rgb8(buf));
                }
                Event::Code(code) => {
                    put_code(&ui, target, &code);
                    stop_scan(&ui);
                }
                Event::Failed(why) => ui.set_scan_error(crate::i18n::tr(&why).into()),
            }
        });
    });
    SCAN.with(|s| *s.borrow_mut() = Some(running));
}

#[cfg(desktop)]
/// Turn the camera off and close the scan view.
fn stop_scan(ui: &AppWindow) {
    SCAN.with(|s| s.borrow_mut().take());
    ui.set_scanning(false);
    ui.set_scan_frame(slint::Image::default());
}

#[cfg(desktop)]
/// The system's file dialog for one of the path fields (`browse` in the
/// UI): the chosen paths go into the field.
fn browse(ui: &AppWindow, what: i32) {
    let w = ui.as_weak();
    let _ = slint::spawn_local(async move {
        let d = rfd::AsyncFileDialog::new().set_directory(downloads());
        let paths: Vec<String> = match what {
            0 | 1 => d
                .add_filter(crate::i18n::tr("Enclave backup"), &["enclave"])
                .set_title(crate::i18n::tr("Choose your backup"))
                .pick_file()
                .await
                .into_iter()
                .collect(),
            3 => d
                .add_filter(
                    crate::i18n::tr("Pictures"),
                    &["png", "jpg", "jpeg", "gif", "webp"],
                )
                .set_title(crate::i18n::tr("Choose pictures for the pack"))
                .pick_files()
                .await
                .unwrap_or_default(),
            4 => d
                .add_filter(
                    crate::i18n::tr("Pictures"),
                    &["png", "jpg", "jpeg", "gif", "webp"],
                )
                .set_title(crate::i18n::tr("Choose your photo"))
                .pick_file()
                .await
                .into_iter()
                .collect(),
            5 => d
                .add_filter(
                    crate::i18n::tr("Pictures"),
                    &["png", "jpg", "jpeg", "gif", "webp"],
                )
                .set_title(crate::i18n::tr("Choose a picture for your story"))
                .pick_file()
                .await
                .into_iter()
                .collect(),
            6 => d
                .add_filter(
                    crate::i18n::tr("Videos"),
                    &["mp4", "m4v", "mov", "mkv", "webm", "avi", "3gp", "wmv"],
                )
                .set_title(crate::i18n::tr("Choose a video to send"))
                .pick_file()
                .await
                .into_iter()
                .collect(),
            _ => d
                .set_title(crate::i18n::tr("Choose a file to send"))
                .pick_file()
                .await
                .into_iter()
                .collect(),
        }
        .iter()
        .map(|f| f.path().display().to_string())
        .collect();
        if let Some(ui) = w.upgrade() {
            put_paths(&ui, what, &paths);
        }
    });
}

/// Run the app with `args` (the first is the program's name) until its
/// window closes.
pub fn run(args: Vec<String>) -> Result<(), slint::PlatformError> {
    // Started from a terminal, its messages still show there.
    enclave_platform::process::attach_parent_console();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("enclave {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return Ok(());
    }
    // The panic wipe from outside the window (an OS shortcut can run it):
    // erase the profile without opening it, and stop. Only `--profile`
    // matters (no server needs to be named).
    if args.iter().any(|a| a == "--panic-wipe") {
        let Some(profile) = args
            .iter()
            .position(|a| a == "--profile")
            .and_then(|i| args.get(i + 1))
            .map(std::path::PathBuf::from)
            .or_else(enclave_vault::default_profile)
        else {
            eprintln!("enclave: --panic-wipe needs --profile DIR");
            std::process::exit(2);
        };
        match enclave_vault::lock::erase_profile(&profile) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("enclave: couldn't erase {}: {e}", profile.display());
                std::process::exit(1);
            }
        }
    }
    let mode = match Mode::from_args(&args) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("enclave: {e}");
            std::process::exit(2);
        }
    };
    // Crash reports (enclave-crash) for this process; the vault writes its
    // own into the same folder.
    let crashes = match &mode {
        Mode::Server { profile, .. } => Some(profile.join(enclave_crash::DIR)),
        _ => None,
    };
    if let Some(dir) = &crashes {
        enclave_crash::install(dir, "app");
    }
    // A link the system opened the app with (an `enclave:` link, or the
    // https page's): to the window already open on this profile, if any.
    let opened = args
        .iter()
        .skip(1)
        .find(|a| a.starts_with("enclave:") || a.starts_with("https://"))
        .cloned();
    let profile = match &mode {
        Mode::Server { profile, .. } => Some(profile.clone()),
        _ => None,
    };
    // Started again while running (perhaps in the background): the open
    // copy shows its window, or takes the link, and this one stops.
    #[cfg(desktop)]
    if let Some(p) = &profile
        && crate::handoff::send(p, opened.as_deref().unwrap_or(crate::background::SHOW))
    {
        std::process::exit(0);
    }
    let single_process = args.iter().any(|a| a == "--single-process");
    // Install checks: quit once the vault's first state is shown.
    let smoke = args.iter().any(|a| a == "--smoke-exit");
    // Where a phone check (which may not see the app's output) looks for
    // the vault's first state.
    let smoke_file = profile
        .as_ref()
        .filter(|_| smoke)
        .map(|p| p.join("smoke-started"));
    // What "Open with…" handed over last time goes.
    #[cfg(desktop)]
    let _ = std::fs::remove_dir_all(open_dir());
    // Wayland matches the window to its .desktop file by this id.
    let _ = slint::set_xdg_app_id("com.aricummings.Enclave");
    let ui = AppWindow::new()?;
    // The person's language, for the window and for what the vault writes.
    let lang = crate::i18n::set_language(&crate::i18n::system_language());
    let _ = slint::select_bundled_translation(lang.unwrap_or(""));
    let ((tx, mut out), _separate) = vault::start(mode, single_process);
    // Links opened later: from another copy of the app, or (macOS) from
    // the system. They wait in the vault until the profile is unlocked.
    #[cfg(desktop)]
    if let Some(p) = &profile {
        let (t, w) = (tx.clone(), ui.as_weak());
        crate::handoff::listen(p, move |l| {
            // Either way the window comes back (it may be hidden).
            let (t2, w) = (t.clone(), w.clone());
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = w.upgrade() {
                    crate::background::show(&ui, &t2);
                }
            });
            if l != crate::background::SHOW {
                let _ = t.send(Cmd::OpenLink(l));
            }
        });
    }
    // Closing the window leaves Enclave running where there is a status
    // area (PC-48); kept until the app quits.
    #[cfg(desktop)]
    let _tray = crate::background::start(&ui, tx.clone());
    #[cfg(target_os = "macos")]
    {
        let (t, w) = (tx.clone(), ui.as_weak());
        enclave_platform::open_url::on_open_url(move |l| {
            let (t2, w) = (t.clone(), w.clone());
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = w.upgrade() {
                    crate::background::show(&ui, &t2);
                }
            });
            let _ = t.send(Cmd::OpenLink(l));
        });
    }
    if let Some(l) = opened {
        let _ = tx.send(Cmd::OpenLink(l));
    }
    // Outputs from the vault, applied on the UI thread.
    let w = ui.as_weak();
    let lan_tx = tx.clone();
    let video_tx = tx.clone();
    // The voice note playing, shared with its Stop button.
    let playing: Playing = Arc::default();
    voice_notes(&ui, tx.clone(), Arc::clone(&playing));
    std::thread::Builder::new()
        .name("enclave-ui-feed".into())
        .spawn(move || {
            // History for our other device on the local network
            // (`crate::lan`): served, and being received.
            let mut serving: std::collections::HashMap<String, crate::lan::Serving> =
                std::collections::HashMap::new();
            let mut to_serve: std::collections::HashMap<String, Vec<Vec<u8>>> =
                std::collections::HashMap::new();
            // The microphone and speaker, while a call is connecting or on;
            // the camera, while a video call's is on.
            let mut audio: Option<crate::audio::CallAudio> = None;
            let mut camera: Option<CallCamera> = None;
            let mut screen: Option<crate::screen::Share> = None;
            // A large file the vault hands over in parts.
            let mut incoming: Vec<u8> = Vec::new();
            // The next file is for "Open with…".
            let mut open_next = false;
            while let Some(o) = out.blocking_recv() {
                if let (Some(f), Out::Snapshot(_)) = (&smoke_file, &o) {
                    eprintln!("enclave: the vault is ready");
                    let _ = std::fs::write(f, b"started\n");
                }
                // Files are written here, in the UI process, where the
                // person chooses: the vault can't reach anything outside
                // its profile.
                let o = match o {
                    Out::CallAudio(pcm) => {
                        if let Some(a) = &audio {
                            a.play(&pcm);
                        }
                        continue;
                    }
                    Out::CallVideo(width, height, rgba) => {
                        let _ = w.upgrade_in_event_loop(move |ui| {
                            let buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
                                &rgba, width, height,
                            );
                            ui.set_call_remote(slint::Image::from_rgba8(buf));
                            ui.set_call_has_remote(true);
                            ui.set_call_remote_screen(width >= enclave_ipc::SCREEN_WIDTH);
                        });
                        continue;
                    }
                    Out::VoiceAudio(key, first, pcm) => {
                        let mut p = playing.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        match p.as_mut() {
                            Some((k, back)) if *k == key && !first => back.extend(&pcm),
                            _ if first => {
                                let (w2, k2) = (w.clone(), key.clone());
                                let done = move || {
                                    let _ = w2.upgrade_in_event_loop(move |ui| {
                                        if ui.get_voice_playing() == k2.as_str() {
                                            ui.set_voice_playing("".into());
                                        }
                                    });
                                };
                                *p = match crate::audio::Playback::start(pcm, done) {
                                    Ok(back) => {
                                        let k = key.clone();
                                        let _ = w.upgrade_in_event_loop(move |ui| {
                                            ui.set_voice_playing(k.into());
                                        });
                                        Some((key, back))
                                    }
                                    Err(e) => {
                                        eprintln!("enclave: voice note: {e}");
                                        let _ = w.upgrade_in_event_loop(|ui| ui.set_voice_playing("".into()));
                                        None
                                    }
                                };
                            }
                            // A piece of a note that was stopped.
                            _ => {}
                        }
                        continue;
                    }
                    Out::CallTile(who, width, height, rgba) => {
                        let _ = w.upgrade_in_event_loop(move |ui| {
                            use slint::Model;
                            let id = i32::from_ne_bytes(who.to_ne_bytes());
                            let peers = ui.get_call_peers();
                            if let Some(i) = (0..peers.row_count())
                                .find(|i| peers.row_data(*i).is_some_and(|t| t.id == id))
                                && let Some(mut t) = peers.row_data(i)
                            {
                                let buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
                                    &rgba, width, height,
                                );
                                t.picture = slint::Image::from_rgba8(buf);
                                t.has_picture = true;
                                peers.set_row_data(i, t);
                            }
                        });
                        continue;
                    }
                    Out::Snapshot(s) => {
                        let c = &s.call;
                        let sharing = matches!(c.state, 3 | 4) && c.screen && c.video_width > 0;
                        if sharing && screen.is_none() {
                            let (tx, w) = (lan_tx.clone(), w.clone());
                            match crate::screen::Share::start(move |frame| {
                                let (pw, ph) = (enclave_ipc::SCREEN_WIDTH / 4, enclave_ipc::SCREEN_HEIGHT / 4);
                                let preview = crate::screen::contain(
                                    enclave_ipc::SCREEN_WIDTH,
                                    enclave_ipc::SCREEN_HEIGHT,
                                    &frame,
                                    pw,
                                    ph,
                                );
                                let _ = tx.send(Cmd::CallFrame(
                                    enclave_ipc::SCREEN_WIDTH,
                                    enclave_ipc::SCREEN_HEIGHT,
                                    frame,
                                ));
                                let _ = w.upgrade_in_event_loop(move |ui| {
                                    let buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
                                        &preview, pw, ph,
                                    );
                                    ui.set_call_self(slint::Image::from_rgba8(buf));
                                });
                            }, {
                                let tx = lan_tx.clone();
                                move |why: String| {
                                    if !why.is_empty() {
                                        eprintln!("enclave: screen share: {why}");
                                    }
                                    let _ = tx.send(Cmd::CallScreen(false));
                                }
                            }) {
                                Ok(sh) => screen = Some(sh),
                                Err(e) => {
                                    eprintln!("enclave: screen share: {e}");
                                    let _ = lan_tx.send(Cmd::CallScreen(false));
                                }
                            }
                        } else if !sharing {
                            screen = None;
                        }
                        let film = matches!(c.state, 3 | 4) && c.camera && !c.screen && c.video_width > 0;
                        if film && camera.is_none() {
                            camera = Some(CallCamera::start(
                                c.video_width,
                                c.video_height,
                                lan_tx.clone(),
                                w.clone(),
                            ));
                        } else if !film {
                            camera = None;
                        }
                        if c.state == 0 || c.state == 5 {
                            let _ = w.upgrade_in_event_loop(|ui| ui.set_call_has_remote(false));
                        }
                        let on = matches!(s.call.state, 3 | 4);
                        if on && audio.is_none() {
                            let tx = lan_tx.clone();
                            match crate::audio::CallAudio::start(move |f| {
                                let _ = tx.send(Cmd::CallMic(f));
                            }) {
                                Ok(a) => audio = Some(a),
                                Err(e) => eprintln!("enclave: call audio: {e}"),
                            }
                        } else if !on {
                            audio = None;
                        }
                        Out::Snapshot(s)
                    }
                    Out::File(name, bytes) => {
                        if std::mem::take(&mut open_next) {
                            let _ = w.upgrade_in_event_loop(move |ui| open_with(&ui, &name, &bytes));
                        } else {
                            let _ = w.upgrade_in_event_loop(move |ui| save_with_dialog(&ui, name, bytes));
                        }
                        continue;
                    }
                    Out::FilePart(name, part, last) => {
                        incoming.extend_from_slice(&part);
                        if last {
                            let bytes = std::mem::take(&mut incoming);
                            if std::mem::take(&mut open_next) {
                                let _ = w.upgrade_in_event_loop(move |ui| open_with(&ui, &name, &bytes));
                            } else {
                                let _ = w.upgrade_in_event_loop(move |ui| save_with_dialog(&ui, name, bytes));
                            }
                        }
                        continue;
                    }
                    Out::OpenNext => {
                        open_next = true;
                        continue;
                    }
                    Out::Notify(n) => {
                        let n = crate::i18n::notice(n);
                        let _ = w.upgrade_in_event_loop(move |ui| notify(&ui, n));
                        continue;
                    }
                    Out::UpdateBundle(b) => {
                        #[cfg(desktop)]
                        crate::updater::set_bundle(b);
                        #[cfg(not(desktop))]
                        drop(b);
                        continue;
                    }
                    Out::LanChunks(token, chunks, last) => {
                        let all = to_serve.entry(token.clone()).or_default();
                        all.extend(chunks);
                        if last {
                            let all = to_serve.remove(&token).unwrap_or_default();
                            let addrs = match crate::lan::unhex(&token) {
                                Some(t) => {
                                    let (s, addrs) = crate::lan::serve(t, all);
                                    serving.insert(token.clone(), s);
                                    addrs
                                }
                                None => Vec::new(),
                            };
                            let _ = lan_tx.send(Cmd::LanServing(token, addrs));
                        }
                        continue;
                    }
                    Out::LanStop(token) => {
                        serving.remove(&token);
                        continue;
                    }
                    Out::LanFetch(token, addrs, count) => {
                        let Some(t) = crate::lan::unhex(&token) else {
                            let _ = lan_tx.send(Cmd::LanFailed(token));
                            continue;
                        };
                        let tx = lan_tx.clone();
                        crate::lan::fetch(t, addrs, count, move |r| {
                            let _ = tx.send(match r {
                                crate::lan::Fetched::Batch(c, last) => {
                                    Cmd::LanChunks(token.clone(), c, last)
                                }
                                crate::lan::Fetched::Failed => Cmd::LanFailed(token.clone()),
                            });
                        });
                        continue;
                    }
                    Out::RecordProgress(n) => {
                        crate::video::progress(n);
                        continue;
                    }
                    Out::Invite(link) => {
                        let copied = copy_with_timeout(link.clone());
                        let _ = w.upgrade_in_event_loop(move |ui| {
                            ui.set_status_line(
                                crate::i18n::tr(&if copied {
                                    "Invite link copied. It works for 7 days, for as many people as you chose, and is cleared from the clipboard after 60 seconds.".to_string()
                                } else {
                                    format!("Your invite link (it works for 7 days): {link}")
                                })
                                .into(),
                            )
                        });
                        continue;
                    }
                    other => other,
                };
                let vt = video_tx.clone();
                let _ = w.upgrade_in_event_loop(move |ui| match o {
                    Out::VideoPiece(p) => crate::video::piece(&ui, p, &vt),
                    Out::Snapshot(s) => {
                        view::apply(&ui, &s);
                        if smoke {
                            println!("enclave: started");
                            let _ = slint::quit_event_loop();
                        }
                    }
                    Out::Effect(e) => view::apply_effect(&ui, e),
                    Out::Preview(p) => view::apply_preview(&ui, p),
                    Out::Clip(c) => view::apply_clip(&ui, c),
                    Out::OpenLink(l) => {
                        ui.set_add_link(l.into());
                        ui.set_sheet(Sheet::Add);
                        let _ = ui.show();
                    }
                    Out::PackPreview(title, n) => view::apply_pack_preview(&ui, &title, n),
                    Out::Gifs(names) => view::apply_gifs(&ui, &names),
                    Out::Gallery(rows) => {
                        let rows: Vec<crate::GalleryRow> = rows
                            .into_iter()
                            .map(|g| crate::GalleryRow {
                                conversation: g.conversation.into(),
                                name: g.name.into(),
                                seq: g.seq.to_string().into(),
                                file: g.file.into(),
                                picture: g.picture,
                                outgoing: g.outgoing,
                                time: g.time.into(),
                            })
                            .collect();
                        ui.set_gallery_rows(slint::ModelRc::new(slint::VecModel::from(rows)));
                    }
                    Out::File(..)
                    | Out::FilePart(..)
                    | Out::OpenNext
                    | Out::Invite(_)
                    | Out::Notify(_)
                    | Out::LanChunks(..)
                    | Out::LanStop(_)
                    | Out::LanFetch(..)
                    | Out::UpdateBundle(_)
                    | Out::CallAudio(_)
                    | Out::CallVideo(..)
                    | Out::CallTile(..)
                    | Out::VoiceAudio(..)
                    | Out::RecordProgress(_) => {}
                });
            }
        })
        .map_err(|e| slint::PlatformError::Other(e.to_string()))?;
    let t = tx.clone();
    ui.on_get_started({
        let w = ui.as_weak();
        move || {
            if let Some(ui) = w.upgrade() {
                ui.set_screen(Screen::Name);
            }
            let _ = &t;
        }
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_create_account(move |name| {
        if name.trim().is_empty() {
            return;
        }
        if let Some(ui) = w.upgrade() {
            ui.set_screen(Screen::SettingUp);
            ui.set_status_line(
                crate::i18n::tr("This can take a minute: everything goes through Tor.").into(),
            );
        }
        let passphrase = w
            .upgrade()
            .map(|ui| {
                let p = ui.get_new_passphrase().to_string();
                ui.set_new_passphrase("".into());
                p
            })
            .unwrap_or_default();
        let _ = t.send(Cmd::Create(name.to_string(), passphrase));
    });
    let t = tx.clone();
    ui.on_unlock(move |p| {
        let _ = t.send(Cmd::Unlock(p.to_string()));
    });
    let t = tx.clone();
    ui.on_lock_now(move || {
        let _ = t.send(Cmd::Lock);
    });
    let t = tx.clone();
    ui.on_set_app_lock(move |p| {
        let _ = t.send(Cmd::SetAppLock(p.to_string()));
    });
    let t = tx.clone();
    ui.on_set_lock_timeout(move |secs| {
        let _ = t.send(Cmd::SetLockTimeout(u32::try_from(secs).unwrap_or(0)));
    });
    let t = tx.clone();
    ui.on_set_emergency_pin(move |p| {
        let _ = t.send(Cmd::SetEmergencyPin(p.to_string()));
    });
    let t = tx.clone();
    ui.on_set_passphrase(move |p| {
        let _ = t.send(Cmd::SetPassphrase(p.to_string()));
    });
    let t = tx.clone();
    ui.on_new_invite(move |uses| {
        let _ = t.send(Cmd::NewInvite(u8::try_from(uses.clamp(1, 20)).unwrap_or(1)));
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_restore(move |words, s1, s2, s3, s4, s5, path| {
        let secrets: Vec<String> = if words.trim().is_empty() {
            [&s1, &s2, &s3, &s4, &s5]
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else {
            vec![words.trim().to_string()]
        };
        // No file: the backup kept on the server.
        if path.trim().is_empty() {
            let _ = t.send(Cmd::RestoreFromServer(secrets));
            return;
        }
        // The backup is read here, in the UI process: the vault never
        // touches the person's files.
        let archive = match std::fs::read(path.trim()) {
            Ok(b) if b.len() as u64 <= MAX_BACKUP => b,
            Ok(_) => {
                if let Some(ui) = w.upgrade() {
                    ui.set_restore_error(
                        crate::i18n::tr("That file is too large to be an Enclave backup.").into(),
                    );
                }
                return;
            }
            Err(e) => {
                if let Some(ui) = w.upgrade() {
                    ui.set_restore_error(
                        crate::i18n::tr(&format!("Couldn't open that file: {e}")).into(),
                    );
                }
                return;
            }
        };
        let archive = if stage(&t, &archive) {
            Vec::new()
        } else {
            archive
        };
        let _ = t.send(Cmd::Restore(secrets, archive));
    });
    let t = tx.clone();
    ui.on_save_backup(move |media| {
        let _ = t.send(Cmd::SaveBackup(media));
    });
    let t = tx.clone();
    ui.on_set_server_backup(move |on| {
        let _ = t.send(Cmd::ServerBackup(on));
    });
    ui.set_version(env!("CARGO_PKG_VERSION").into());
    // The system's reduce-motion setting (`docs/17-design.md` §5).
    ui.global::<crate::Tokens>()
        .set_reduce_motion(enclave_platform::window::reduce_motion());
    // And its text size, up to 200% (`docs/18-a11y-i18n.md` A-5).
    ui.global::<crate::Tokens>()
        .set_text_scale(enclave_platform::window::text_scale());
    // Notifications come from the app's bundle (an unbundled build keeps
    // the system's default sender).
    #[cfg(all(desktop, target_os = "macos"))]
    let _ = notify_rust::set_application("com.aricummings.Enclave");
    ui.set_can_hide_capture(enclave_platform::window::CAN_EXCLUDE_FROM_CAPTURE);
    ui.set_capture_platform(if cfg!(windows) {
        1
    } else if cfg!(target_os = "macos") {
        2
    } else if cfg!(target_os = "android") {
        3
    } else if cfg!(target_os = "ios") {
        4
    } else {
        0
    });
    // Kept out of screen capture from the first frame (the profile's
    // setting follows with its first snapshot).
    let w = ui.as_weak();
    slint::Timer::single_shot(Duration::ZERO, move || {
        if let Some(ui) = w.upgrade() {
            view::apply_screen_security(&ui);
        }
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_unlock_biometric(move || {
        let window = w.upgrade().map_or(0, |ui| {
            enclave_platform::window::native_id(&ui.window().window_handle())
        });
        let _ = t.send(Cmd::UnlockBiometric(window));
    });
    let t = tx.clone();
    ui.on_set_biometric(move |on| {
        let _ = t.send(Cmd::SetBiometric(on));
    });
    let t = tx.clone();
    ui.on_set_screen_security(move |on| {
        let _ = t.send(Cmd::SetScreenSecurity(on));
    });
    crash_reports(&ui, crashes, tx.clone());
    updates(&ui, tx.clone());
    let w = ui.as_weak();
    ui.on_load_licences(move || {
        if let Some(ui) = w.upgrade()
            && ui.get_licences().row_count() == 0
        {
            ui.set_licences(view::licences());
        }
    });
    let w = ui.as_weak();
    ui.on_scan(move |target| {
        if let Some(ui) = w.upgrade() {
            scan(&ui, target);
        }
    });
    let w = ui.as_weak();
    ui.on_stop_scan(move || {
        if let Some(ui) = w.upgrade() {
            stop_scan(&ui);
        }
    });
    let w = ui.as_weak();
    ui.on_browse(move |what| {
        if let Some(ui) = w.upgrade() {
            browse(&ui, what);
        }
    });
    let t = tx.clone();
    ui.on_pick_server(move |purpose, id| {
        let id = id.to_string();
        let _ = t.send(match purpose {
            0 => Cmd::PickServer(id),
            1 => Cmd::MoveHome(id),
            _ => Cmd::VoteGroupHost(id),
        });
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_check_backup(move |words, path| {
        // A file is read here, in the UI process, as for a restore.
        let archive = if path.trim().is_empty() {
            Vec::new()
        } else {
            match std::fs::read(path.trim()) {
                Ok(b) if b.len() as u64 <= MAX_BACKUP => b,
                _ => {
                    if let Some(ui) = w.upgrade() {
                        ui.set_backup_check(crate::i18n::tr("Couldn't open that file.").into());
                    }
                    return;
                }
            }
        };
        let archive = if stage(&t, &archive) {
            Vec::new()
        } else {
            archive
        };
        let _ = t.send(Cmd::CheckBackup(words.trim().to_string(), archive));
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_give_shares(move |threshold| {
        let Some(ui) = w.upgrade() else { return };
        use slint::Model;
        let ids: Vec<String> = ui
            .get_friends()
            .iter()
            .filter(|p| p.selected)
            .map(|p| p.id.to_string())
            .collect();
        let _ = t.send(Cmd::GiveShares(ids, u32::try_from(threshold).unwrap_or(2)));
    });
    let t = tx.clone();
    ui.on_reveal_share(move |id| {
        let _ = t.send(Cmd::RevealShare(id.to_string()));
    });
    let t = tx.clone();
    ui.on_release_share(move |code| {
        let _ = t.send(Cmd::ReleaseShare(code.to_string()));
    });
    let t = tx.clone();
    ui.on_set_root_pin(move |p| {
        let _ = t.send(Cmd::SetRootPin(p.to_string()));
    });
    let t = tx.clone();
    ui.on_set_previews(move |on| {
        let _ = t.send(Cmd::SetPreviews(on));
    });
    let t = tx.clone();
    ui.on_transcription_model(move |on| {
        let _ = t.send(Cmd::TranscriptionModel(on));
    });
    let t = tx.clone();
    ui.on_transcribe(move |id, seq| {
        if let Ok(seq) = seq.parse() {
            let _ = t.send(Cmd::Transcribe(id.to_string(), seq));
        }
    });
    let t = tx.clone();
    ui.on_secure_account(move || {
        let _ = t.send(Cmd::SecureAccount);
    });
    let t = tx.clone();
    ui.on_unlock_root(move |p| {
        let _ = t.send(Cmd::UnlockRoot(p.to_string()));
    });
    let t = tx.clone();
    ui.on_delete_account(move || {
        let _ = t.send(Cmd::DeleteAccount);
    });
    let t = tx.clone();
    ui.on_erase_device(move || {
        let _ = t.send(Cmd::EraseDevice);
    });
    let t = tx.clone();
    ui.on_ask_shares(move || {
        let _ = t.send(Cmd::AskShares);
    });
    let t = tx.clone();
    ui.on_create_poll(move |id, q, a, b, c, d, anonymous| {
        let options = [a, b, c, d]
            .iter()
            .map(|o| o.trim().to_string())
            .filter(|o| !o.is_empty())
            .collect();
        let _ = t.send(Cmd::CreatePoll(
            id.to_string(),
            q.to_string(),
            options,
            anonymous,
        ));
    });
    let t = tx.clone();
    ui.on_vote(move |id, seq, choice| {
        if let (Ok(seq), Ok(choice)) = (seq.parse(), u32::try_from(choice)) {
            let _ = t.send(Cmd::Vote(id.to_string(), seq, choice));
        }
    });
    let t = tx.clone();
    ui.on_close_poll(move |id, seq| {
        if let Ok(seq) = seq.parse() {
            let _ = t.send(Cmd::ClosePoll(id.to_string(), seq));
        }
    });
    let t = tx.clone();
    ui.on_new_group_invite(move |id, uses, approve| {
        let uses = u8::try_from(uses.clamp(1, 20)).unwrap_or(1);
        let _ = t.send(Cmd::NewGroupInvite(id.to_string(), uses, approve));
    });
    let t = tx.clone();
    ui.on_cancel_invites(move || {
        let _ = t.send(Cmd::CancelInvites);
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_select(move |id| {
        // Another conversation opens at its newest message.
        if let Some(ui) = w.upgrade() {
            ui.set_scroll_offset(0.0);
            ui.set_pins_open(false);
            ui.set_reply_seq("".into());
            ui.set_mention_open(false);
        }
        let _ = t.send(Cmd::Select(id.to_string()));
    });
    let t = tx.clone();
    ui.on_send(move |id, text| {
        enclave_platform::window::haptic(enclave_platform::window::Haptic::Tick);
        let _ = t.send(Cmd::Send(id.to_string(), text.to_string()));
    });
    let t = tx.clone();
    ui.on_send_reply(move |id, text, seq| {
        enclave_platform::window::haptic(enclave_platform::window::Haptic::Tick);
        if let Ok(seq) = seq.parse() {
            let _ = t.send(Cmd::SendReply(id.to_string(), text.to_string(), seq));
        }
    });
    let t = tx.clone();
    ui.on_open_file(move |id, seq| {
        if let Ok(seq) = seq.parse() {
            let _ = t.send(Cmd::OpenFile(id.to_string(), seq));
        }
    });
    let t = tx.clone();
    ui.on_forward(move |from, seq, to| {
        if let Ok(seq) = seq.parse() {
            let _ = t.send(Cmd::Forward(from.to_string(), seq, to.to_string()));
        }
    });
    let t = tx.clone();
    ui.on_accept(move |id| {
        let _ = t.send(Cmd::Accept(id.to_string()));
    });
    let t = tx.clone();
    ui.on_decline(move |id| {
        let _ = t.send(Cmd::Decline(id.to_string()));
    });
    let t = tx.clone();
    ui.on_add_contact(move |link, text| {
        let _ = t.send(Cmd::Add(link.to_string(), text.to_string()));
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_mark_checked(move |id| {
        let _ = t.send(Cmd::Check(id.to_string()));
        if let Some(ui) = w.upgrade() {
            let mut cur = ui.get_current();
            cur.verified = true;
            ui.set_current(cur);
        }
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_set_privacy(move |p| {
        if let Some(ui) = w.upgrade() {
            ui.set_privacy(p);
        }
        let _ = t.send(Cmd::Privacy(p));
    });
    let t = tx.clone();
    ui.on_words_saved(move || {
        let _ = t.send(Cmd::WordsSaved);
    });
    let t = tx.clone();
    ui.on_toggle_pick(move |id| {
        let _ = t.send(Cmd::TogglePick(id.to_string()));
    });
    let t = tx.clone();
    ui.on_create_group(move |name| {
        let _ = t.send(Cmd::CreateGroup(name.to_string()));
    });
    let t = tx.clone();
    ui.on_link_scan(move |code| {
        let _ = t.send(Cmd::LinkScan(code.to_string()));
    });
    let t = tx.clone();
    ui.on_link_pick(move |i| {
        let _ = t.send(Cmd::LinkPick(i));
    });
    let w = ui.as_weak();
    ui.on_open_sheet(move |s| {
        if let Some(ui) = w.upgrade() {
            ui.set_sheet(s);
        }
    });
    let t = tx.clone();
    ui.on_add_members(move |id| {
        let _ = t.send(Cmd::AddMembers(id.to_string()));
    });
    let t = tx.clone();
    ui.on_remove_member(move |id, member| {
        let _ = t.send(Cmd::RemoveMember(id.to_string(), member.to_string()));
    });
    let t = tx.clone();
    ui.on_set_group_admin(move |id, member, on| {
        let _ = t.send(Cmd::SetGroupAdmin(id.to_string(), member.to_string(), on));
    });
    let t = tx.clone();
    ui.on_leave_group(move |id| {
        let _ = t.send(Cmd::LeaveGroup(id.to_string()));
    });
    let t = tx.clone();
    ui.on_search(move |q| {
        let _ = t.send(Cmd::Search(q.to_string()));
    });
    let t = tx.clone();
    ui.on_add_pack(move |id, seq| {
        if let Ok(seq) = seq.parse() {
            let _ = t.send(Cmd::AddPack(id.to_string(), seq));
        }
    });
    let t = tx.clone();
    ui.on_remove_pack(move |id| {
        let _ = t.send(Cmd::RemovePack(id.to_string()));
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_preview_pack(move |id, seq| {
        if let Some(ui) = w.upgrade() {
            ui.set_pack_preview_cells(slint::ModelRc::default());
        }
        if let Ok(seq) = seq.parse() {
            let _ = t.send(Cmd::PreviewPack(id.to_string(), seq));
        }
    });
    let t = tx.clone();
    ui.on_send_sticker(move |id, pack, index| {
        let index = u32::try_from(index).unwrap_or(0);
        let _ = t.send(Cmd::SendSticker(id.to_string(), pack.to_string(), index));
    });
    let t = tx.clone();
    ui.on_load_stickers(move || {
        let _ = t.send(Cmd::LoadStickers);
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_play_clip(move |id, seq| {
        let Ok(seq) = seq.parse() else {
            return;
        };
        if let Some(ui) = w.upgrade() {
            ui.set_player_frames(slint::ModelRc::default());
            ui.set_player_once(false);
            ui.set_sheet(Sheet::Player);
        }
        let _ = t.send(Cmd::PlayClip(id.to_string(), seq));
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_open_view_once(move |id, seq| {
        let Ok(seq) = seq.parse() else {
            return;
        };
        if let Some(ui) = w.upgrade() {
            ui.set_player_frames(slint::ModelRc::default());
            ui.set_player_once(true);
            ui.set_sheet(Sheet::Player);
        }
        let _ = t.send(Cmd::OpenViewOnce(id.to_string(), seq));
    });
    let w = ui.as_weak();
    ui.on_open_map(move |coords, label| {
        let Some(ui) = w.upgrade() else {
            return;
        };
        let Some((lat, lon)) = parse_coordinates(&coords) else {
            return;
        };
        #[cfg(desktop)]
        let opened = open_map(lat, lon, &label).is_ok();
        #[cfg(not(desktop))]
        let opened = enclave_platform::phone::open_map(lat, lon, &label);
        if !opened {
            ui.set_file_note(crate::i18n::tr("No maps app here opens places.").into());
        }
    });
    #[cfg(not(desktop))]
    {
        let w = ui.as_weak();
        ui.on_locate(move || {
            if let Some(ui) = w.upgrade() {
                ui.set_locating(true);
            }
            let w = w.clone();
            enclave_platform::phone::locate(move |r| {
                let _ = w.upgrade_in_event_loop(move |ui| {
                    ui.set_locating(false);
                    match r {
                        Ok((lat, lon)) => {
                            ui.set_location_lat(format!("{lat:.6}").into());
                            ui.set_location_lon(format!("{lon:.6}").into());
                        }
                        Err(e) => ui.set_location_note(crate::i18n::tr(&e).into()),
                    }
                });
            });
        });
    }
    let t = tx.clone();
    ui.on_load_gallery(move || {
        let _ = t.send(Cmd::AllFiles);
    });
    let t = tx.clone();
    ui.on_stop_video(move || crate::video::stop(&t));
    let recording: std::rc::Rc<std::cell::RefCell<Option<crate::video::Recording>>> =
        std::rc::Rc::default();
    let (t, w, r) = (tx.clone(), ui.as_weak(), std::rc::Rc::clone(&recording));
    ui.on_start_recording(move |conv| {
        if let Some(ui) = w.upgrade() {
            ui.set_record_time("".into());
            ui.set_record_note("".into());
            ui.set_record_preview(slint::Image::default());
        }
        *r.borrow_mut() = Some(crate::video::Recording::start(
            conv.to_string(),
            t.clone(),
            w.clone(),
        ));
    });
    let (t, r) = (tx.clone(), std::rc::Rc::clone(&recording));
    ui.on_finish_recording(move |caption| {
        if let Some(rec) = r.borrow_mut().take() {
            rec.finish(caption.trim().to_string(), &t);
        }
    });
    let (t, r) = (tx.clone(), std::rc::Rc::clone(&recording));
    ui.on_cancel_recording(move || {
        if let Some(rec) = r.borrow_mut().take() {
            rec.cancel(&t);
        }
    });
    let (t, w) = (tx.clone(), ui.as_weak());
    ui.on_send_video_file(move |path, caption| {
        let Some(ui) = w.upgrade() else { return };
        let conv = ui.get_current_id().to_string();
        crate::video::send_file(
            path.trim().into(),
            conv,
            caption.trim().to_string(),
            t.clone(),
            w.clone(),
        );
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_open_stories(move |who| {
        if let Some(ui) = w.upgrade() {
            for key in view::show_stories(&ui, who.as_str()) {
                let _ = t.send(Cmd::OpenStory(key));
            }
        }
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_post_story(move |text, path| {
        let path = path.trim();
        let (name, bytes) = if path.is_empty() {
            (String::new(), Vec::new())
        } else {
            match std::fs::metadata(path) {
                Ok(m) if m.len() <= PHOTO_MAX_BYTES => (
                    std::path::Path::new(path)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "story".into()),
                    std::fs::read(path).unwrap_or_default(),
                ),
                _ => (String::new(), Vec::new()),
            }
        };
        if !path.is_empty() && bytes.is_empty() {
            if let Some(ui) = w.upgrade() {
                ui.set_status_line(
                    crate::i18n::tr("Enclave couldn't read that picture. Try another one.").into(),
                );
            }
            return;
        }
        let _ = t.send(Cmd::PostStory(text.trim().to_string(), name, bytes));
    });
    let t = tx.clone();
    ui.on_delete_story(move |key| {
        let _ = t.send(Cmd::DeleteStory(key.to_string()));
    });
    let t = tx.clone();
    ui.on_story_hidden(move |id, hidden| {
        let _ = t.send(Cmd::StoryHidden(id.to_string(), hidden));
    });
    let t = tx.clone();
    ui.on_set_name(move |name| {
        let _ = t.send(Cmd::SetName(name.trim().to_string()));
    });
    let t = tx.clone();
    ui.on_set_about(move |about| {
        let _ = t.send(Cmd::SetAbout(about.trim().to_string()));
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_set_photo(move |path| {
        // The picture is read here and redrawn small in mediad.
        let bytes = if path.is_empty() {
            Vec::new()
        } else {
            match std::fs::metadata(path.as_str()) {
                Ok(m) if m.len() <= PHOTO_MAX_BYTES => {
                    std::fs::read(path.as_str()).unwrap_or_default()
                }
                _ => Vec::new(),
            }
        };
        if !path.is_empty() && bytes.is_empty() {
            if let Some(ui) = w.upgrade() {
                ui.set_status_line(
                    crate::i18n::tr("Enclave couldn't read that picture. Try another one.").into(),
                );
            }
            return;
        }
        let _ = t.send(Cmd::SetPhoto(bytes));
    });
    let t = tx.clone();
    ui.on_change_words(move || {
        let _ = t.send(Cmd::ChangeWords);
    });
    let t = tx.clone();
    let f = tx.clone();
    ui.on_new_folder(move |name| {
        let _ = f.send(Cmd::NewFolder(name.to_string()));
    });
    let f = tx.clone();
    ui.on_delete_folder(move |name| {
        let _ = f.send(Cmd::DeleteFolder(name.to_string()));
    });
    let f = tx.clone();
    ui.on_in_folder(move |name, on| {
        let _ = f.send(Cmd::InFolder(name.to_string(), on));
    });
    let f = tx.clone();
    ui.on_show_folder(move |name| {
        let _ = f.send(Cmd::ShowFolder(name.to_string()));
    });
    let t3 = tx.clone();
    ui.on_set_announcement_only(move |on| {
        let _ = t3.send(Cmd::SetAnnouncementOnly(on));
    });
    let t2 = tx.clone();
    ui.on_set_receipts_setting(move |on| {
        let _ = t2.send(Cmd::ReceiptsSetting(on));
    });
    let t2 = tx.clone();
    ui.on_set_link_previews(move |on| {
        let _ = t2.send(Cmd::LinkPreviewsSetting(on));
    });
    let t2 = tx.clone();
    ui.on_set_gif_search(move |on| {
        let _ = t2.send(Cmd::GifSearchSetting(on));
    });
    let t2 = tx.clone();
    ui.on_search_gifs(move |q| {
        let _ = t2.send(Cmd::GifSearch(q.trim().to_string()));
    });
    let t2 = tx.clone();
    ui.on_send_gif(move |conv, i| {
        let _ = t2.send(Cmd::SendGif(
            conv.to_string(),
            u32::try_from(i).unwrap_or(u32::MAX),
        ));
    });
    ui.on_set_typing_setting(move |on| {
        let _ = t.send(Cmd::TypingSetting(on));
    });
    let t = tx.clone();
    ui.on_draft_changed(move |id, on| {
        let _ = t.send(Cmd::Typing(id.to_string(), on));
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_create_pack(move |title, paths| {
        let Some(ui) = w.upgrade() else {
            return;
        };
        let mut pictures = Vec::new();
        let mut total = 0u64;
        for p in paths.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            let read = std::fs::metadata(p).and_then(|m| {
                total += m.len();
                if m.len() > MAX_STICKER_FILE || total > MAX_PACK_FILES {
                    Err(std::io::Error::other("too large for a sticker pack"))
                } else {
                    std::fs::read(p)
                }
            });
            match read {
                Ok(b) => pictures.push(b),
                Err(e) => {
                    ui.set_pack_error(crate::i18n::tr(&format!("Couldn't read {p}: {e}.")).into());
                    return;
                }
            }
        }
        if pictures.is_empty() || pictures.len() > 40 {
            ui.set_pack_error(crate::i18n::tr("A pack needs 1 to 40 pictures.").into());
            return;
        }
        let _ = t.send(Cmd::CreatePack(title.trim().to_string(), pictures));
        ui.set_pack_title("".into());
        ui.set_pack_paths("".into());
        ui.set_sheet(Sheet::Stickers);
    });
    let t = tx.clone();
    ui.on_report(move |id, reason, quote, block, costlier| {
        let reason = u8::try_from(reason).unwrap_or(3);
        let _ = t.send(Cmd::Report(id.to_string(), reason, quote, block, costlier));
    });
    let t = tx.clone();
    ui.on_share_location(move |id, lat, lon, label| {
        let _ = t.send(Cmd::ShareLocation(
            id.to_string(),
            lat.to_string(),
            lon.to_string(),
            label.to_string(),
        ));
    });
    let t = tx.clone();
    ui.on_share_contact(move |id, who| {
        let _ = t.send(Cmd::ShareContact(id.to_string(), who.to_string()));
    });
    let t = tx.clone();
    ui.on_add_shared(move |id, seq| {
        if let Ok(seq) = seq.parse() {
            let _ = t.send(Cmd::AddShared(id.to_string(), seq));
        }
    });
    let t = tx.clone();
    ui.on_block(move |id, on| {
        let _ = t.send(Cmd::Block(id.to_string(), on));
    });
    let t = tx.clone();
    ui.on_conv_prefs(move |id, archived, pinned, muted| {
        let _ = t.send(Cmd::ConvPrefs(id.to_string(), archived, pinned, muted));
    });
    let t = tx.clone();
    ui.on_code_words_english_toggled(move |on| {
        let _ = t.send(Cmd::CodeWordsEnglish(on));
    });
    let t = tx.clone();
    ui.on_choose_words_language(move |code| {
        let _ = t.send(Cmd::WordsLanguage(code.to_string()));
    });
    let t = tx.clone();
    ui.on_set_on_record(move |on| {
        let _ = t.send(Cmd::SetOnRecord(on));
    });
    let t = tx.clone();
    ui.on_pin(move |id, seq, on| {
        if let Ok(seq) = seq.parse() {
            let _ = t.send(Cmd::Pin(id.to_string(), seq, on));
        }
    });
    let t = tx.clone();
    ui.on_react(move |id, seq, emoji| {
        if let Ok(seq) = seq.parse() {
            let _ = t.send(Cmd::React(id.to_string(), seq, emoji.to_string()));
        }
    });
    let t = tx.clone();
    ui.on_edit_message(move |id, seq, text| {
        if let Ok(seq) = seq.parse() {
            let _ = t.send(Cmd::Edit(id.to_string(), seq, text.to_string()));
        }
    });
    let t = tx.clone();
    ui.on_delete_message(move |id, seq| {
        if let Ok(seq) = seq.parse() {
            let _ = t.send(Cmd::Delete(id.to_string(), seq));
        }
    });
    let t = tx.clone();
    ui.on_set_timer(move |id, secs| {
        let _ = t.send(Cmd::Timer(id.to_string(), secs.max(0) as u32));
    });
    let t = tx.clone();
    ui.on_save_file(move |id, seq| {
        if let Ok(seq) = seq.parse() {
            let _ = t.send(Cmd::SaveFile(id.to_string(), seq));
        }
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_send_file(move |id, path, caption, view_once| {
        let path = std::path::PathBuf::from(path.trim());
        let result = std::fs::metadata(&path).and_then(|m| {
            if m.len() > MAX_FILE {
                Err(std::io::Error::other("larger than 100 MB"))
            } else {
                std::fs::read(&path)
            }
        });
        match result {
            Ok(bytes) => {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "file".into());
                if view_once {
                    // Always staged: the vault sends what it holds.
                    for part in bytes.chunks(enclave_ipc::FILE_PART) {
                        let _ = t.send(Cmd::Stage(part.to_vec()));
                    }
                    let _ = t.send(Cmd::SendViewOnce(id.to_string(), name, caption.to_string()));
                    if let Some(ui) = w.upgrade() {
                        ui.set_attach_view_once(false);
                    }
                } else if stage(&t, &bytes) {
                    let _ = t.send(Cmd::SendStaged(id.to_string(), name, caption.to_string()));
                } else {
                    let _ = t.send(Cmd::SendFile(
                        id.to_string(),
                        name,
                        bytes,
                        caption.to_string(),
                    ));
                }
            }
            Err(e) => {
                if let Some(ui) = w.upgrade() {
                    ui.set_attach_error(
                        crate::i18n::tr(&format!("Couldn't read that file: {e}.")).into(),
                    );
                }
            }
        }
    });
    let t = tx.clone();
    ui.on_claim_username(move |name| {
        let _ = t.send(Cmd::ClaimUsername(name.to_string()));
    });
    let t = tx.clone();
    ui.on_remove_device(move |id| {
        let _ = t.send(Cmd::RemoveDevice(id.to_string()));
    });
    let t = tx.clone();
    ui.on_send_history(move |id| {
        let _ = t.send(Cmd::SendHistory(id.to_string()));
    });
    let t = tx.clone();
    ui.on_stop_recovery(move || {
        let _ = t.send(Cmd::StopRecovery);
    });
    let t = tx.clone();
    ui.on_backup_route(move |on| {
        let _ = t.send(Cmd::BackupRoute(on));
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_set_bridges(move |b| {
        let _ = t.send(Cmd::SetBridges(b.to_string()));
        if let Some(ui) = w.upgrade() {
            ui.set_bridges_input("".into());
        }
    });
    let t = tx.clone();
    ui.on_approve_recovery(move || {
        let _ = t.send(Cmd::ApproveRecovery);
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_start_join(move || {
        if let Some(ui) = w.upgrade() {
            ui.set_screen(Screen::Join);
        }
        let _ = t.send(Cmd::StartJoin);
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_cancel_join(move || {
        if let Some(ui) = w.upgrade() {
            ui.set_screen(Screen::Welcome);
        }
        let _ = t.send(Cmd::CancelJoin);
    });
    let t = tx.clone();
    ui.on_sheet_changed(move |s| {
        let _ = t.send(Cmd::RevealWords(s == Sheet::Recovery));
        let _ = t.send(Cmd::Meet(s == Sheet::Meet));
    });
    let t = tx.clone();
    ui.on_meet_scan(move |code| {
        let _ = t.send(Cmd::MeetScan(code.to_string()));
    });
    let t = tx.clone();
    ui.on_meet_confirm(move || {
        let _ = t.send(Cmd::MeetConfirm);
    });
    let w = ui.as_weak();
    ui.on_copy_text(move |text| {
        let copied = copy_with_timeout(text.to_string());
        if let Some(ui) = w.upgrade() {
            ui.set_status_line(
                crate::i18n::tr(if copied {
                    "Copied. It's cleared from the clipboard after 60 seconds."
                } else {
                    "Couldn't copy it."
                })
                .into(),
            );
        }
    });
    let _ = Sheet::None;
    // The phone's services (Android: its native methods; iOS: screen
    // security and the keyboard rule, which need the running app).
    #[cfg(not(desktop))]
    {
        slint::Timer::single_shot(Duration::ZERO, enclave_platform::phone::init);
        // The text size again: iOS can only say it once the app runs.
        let w = ui.as_weak();
        slint::Timer::single_shot(Duration::ZERO, move || {
            if let Some(ui) = w.upgrade() {
                ui.global::<crate::Tokens>()
                    .set_text_scale(enclave_platform::window::text_scale());
            }
        });
        phone::delivery(&ui);
    }
    if smoke {
        slint::Timer::single_shot(Duration::from_secs(60), || {
            eprintln!("enclave: the vault didn't start within 60 s");
            std::process::exit(1);
        });
    }
    // On a desktop, hiding the window doesn't end the loop: only quitting
    // does (the status icon, `background`).
    #[cfg(desktop)]
    {
        ui.show()?;
        log_window(&ui);
        slint::run_event_loop_until_quit()?;
        ui.hide()
    }
    #[cfg(not(desktop))]
    {
        enclave_platform::phone::prepare();
        ui.run()
    }
}

const USAGE: &str = "\
usage: enclave [options]

  --profile DIR        the profile to open (default: the system's app data folder)
  --panic-wipe         erase the profile without opening it, and quit
  --single-process     run the vault inside the window's process
  --smoke-exit         quit once started (install checks)
  --version            print the version";

/// Copy, then clear the clipboard after 60 s if it still holds our text.
/// Whether it was copied.
#[cfg(desktop)]
fn copy_with_timeout(text: String) -> bool {
    let Ok(mut cb) = arboard::Clipboard::new() else {
        return false;
    };
    if cb.set_text(text.clone()).is_err() {
        return false;
    }
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(60));
        if let Ok(mut cb) = arboard::Clipboard::new()
            && cb.get_text().ok().as_deref() == Some(text.as_str())
        {
            let _ = cb.clear();
        }
    });
    true
}

/// Android and iOS: the phone's pickers, camera, notifications and
/// clipboard (`enclave_platform::phone`).
#[cfg(not(desktop))]
mod phone {
    use crate::AppWindow;
    use enclave_platform::phone::{self as p, Camera, Pick};
    use slint::ComponentHandle as _;

    /// Ask where to save a file the vault handed over, and write it there.
    pub fn save_with_dialog(ui: &AppWindow, name: String, bytes: Vec<u8>) {
        let w = ui.as_weak();
        let shown = name.clone();
        p::save(&name, bytes, move |r| {
            let note = match r {
                Ok(place) => format!("Saved as {place}"),
                Err(e) if e.is_empty() => format!("{shown} wasn't saved."),
                Err(e) => format!("Couldn't save {shown}: {e}"),
            };
            let _ =
                w.upgrade_in_event_loop(move |ui| ui.set_file_note(crate::i18n::tr(&note).into()));
        });
    }

    /// "Open with…": the system's choice of apps for the file.
    pub fn open_with(ui: &AppWindow, name: &str, bytes: &[u8]) {
        if !p::open_with(name, bytes) {
            ui.set_file_note(crate::i18n::tr(&format!("Couldn't open {name} here.")).into());
        }
    }

    /// A notification (the platform skips it while the app is in front).
    pub fn notify(_ui: &AppWindow, n: enclave_ipc::Notice) {
        p::notify(&n.title, &crate::format::preview(&n.body));
    }

    /// Scan a code with the back camera into the field `target` names.
    pub fn scan(ui: &AppWindow, target: i32) {
        ui.set_scan_error("".into());
        ui.set_scan_frame(slint::Image::default());
        ui.set_scanning(true);
        let w = ui.as_weak();
        p::start_camera(move |e| match e {
            Camera::Frame(fw, fh, grey) => {
                let code = crate::camera::read_qr(fw, fh, &grey);
                let (pw, ph, preview) = crate::camera::preview(fw, fh, &grey, p::MIRROR);
                let _ = w.upgrade_in_event_loop(move |ui| {
                    if !ui.get_scanning() {
                        return;
                    }
                    if let Some(code) = code {
                        super::put_code(&ui, target, &code);
                        stop_scan(&ui);
                        return;
                    }
                    let mut buf = slint::SharedPixelBuffer::<slint::Rgb8Pixel>::new(pw, ph);
                    for (px, g) in buf.make_mut_slice().iter_mut().zip(preview) {
                        *px = slint::Rgb8Pixel { r: g, g, b: g };
                    }
                    ui.set_scan_frame(slint::Image::from_rgb8(buf));
                });
            }
            Camera::Failed(why) => {
                let _ = w.upgrade_in_event_loop(move |ui| {
                    ui.set_scan_error(crate::i18n::tr(&why).into())
                });
            }
            // Colour frames are a call's (start_call_camera), not a scan's.
            Camera::Color(..) => {}
        });
    }

    /// Turn the camera off and close the scan view.
    pub fn stop_scan(ui: &AppWindow) {
        p::stop_camera();
        ui.set_scanning(false);
        ui.set_scan_frame(slint::Image::default());
    }

    /// The phone's file picker for one of the path fields; picked files are
    /// copied where the app can read them.
    pub fn browse(ui: &AppWindow, what: i32) {
        let kind = match what {
            0 | 1 => Pick::Backup,
            3..=5 => Pick::Pictures,
            // Any file: the platform's decoder says whether it's a video.
            6 => Pick::File,
            _ => Pick::File,
        };
        let w = ui.as_weak();
        p::pick(kind, move |paths| {
            let paths: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
            let _ = w.upgrade_in_event_loop(move |ui| super::put_paths(&ui, what, &paths));
        });
    }

    /// Copy, marked sensitive, cleared after 60 s if still there.
    pub fn copy_with_timeout(text: String) -> bool {
        p::copy(&text)
    }

    /// Settings → With the app closed: how messages reach the phone.
    pub fn delivery(ui: &AppWindow) {
        let w = ui.as_weak();
        slint::Timer::single_shot(std::time::Duration::ZERO, move || {
            let Some(ui) = w.upgrade() else {
                return;
            };
            let (way, ways) = p::delivery();
            ui.set_delivery(i32::from(way));
            ui.set_can_unifiedpush(ways & (1 << p::delivery::UNIFIEDPUSH) != 0);
            ui.set_can_firebase(ways & (1 << p::delivery::FIREBASE) != 0);
        });
        let w = ui.as_weak();
        p::on_delivery(move |way| {
            let _ = w.upgrade_in_event_loop(move |ui| ui.set_delivery(i32::from(way)));
        });
        ui.on_set_delivery(|way| p::set_delivery(u8::try_from(way).unwrap_or(0)));
        // Battery optimisation (Android, PC-22): checked again every few
        // seconds, so coming back from the system's setting shows the change.
        ui.set_battery_restricted(p::battery_restricted());
        ui.on_open_battery_settings(p::open_battery_settings);
        let w = ui.as_weak();
        let timer = slint::Timer::default();
        timer.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_secs(5),
            move || {
                if let Some(ui) = w.upgrade() {
                    ui.set_battery_restricted(p::battery_restricted());
                }
            },
        );
        // It runs as long as the app does.
        std::mem::forget(timer);
    }
}
#[cfg(not(desktop))]
use phone::*;

/// The camera during a video call: frames go to the vault at the call's
/// video size, and a small mirrored copy to our own preview. Dropping it
/// turns the camera off.
struct CallCamera {
    #[cfg(desktop)]
    _scan: crate::camera::Scan,
}

impl CallCamera {
    fn start(
        width: u32,
        height: u32,
        tx: tokio::sync::mpsc::UnboundedSender<Cmd>,
        ui: slint::Weak<AppWindow>,
    ) -> Self {
        let send = move |fw: u32, fh: u32, rgb: &[u8]| {
            let frame = crate::camera::fit(fw, fh, rgb, width, height, false);
            let _ = tx.send(Cmd::CallFrame(width, height, frame));
            let (pw, ph) = (width / 2, height / 2);
            let preview = crate::camera::fit(fw, fh, rgb, pw, ph, true);
            let _ = ui.upgrade_in_event_loop(move |ui| {
                let buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
                    &preview, pw, ph,
                );
                ui.set_call_self(slint::Image::from_rgba8(buf));
            });
        };
        #[cfg(desktop)]
        {
            Self {
                _scan: crate::camera::start_video(move |fw, fh, rgb| send(fw, fh, &rgb)),
            }
        }
        #[cfg(not(desktop))]
        {
            enclave_platform::phone::start_call_camera(move |c| {
                if let enclave_platform::phone::Camera::Color(fw, fh, rot, i420) = c
                    && let Some((rw, rh, rgb)) = crate::camera::i420_rgb(fw, fh, rot, &i420)
                {
                    send(rw, rh, &rgb);
                }
            });
            Self {}
        }
    }
}

#[cfg(not(desktop))]
impl Drop for CallCamera {
    fn drop(&mut self) {
        enclave_platform::phone::stop_camera();
    }
}
