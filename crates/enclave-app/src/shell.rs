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
use std::time::Duration;

/// Largest file sent from here (it crosses to the vault in one message).
const MAX_FILE: u64 = 15 * 1024 * 1024;
/// Largest picture file read for a sticker pack (it is redrawn small).
const MAX_STICKER_FILE: u64 = 4 * 1024 * 1024;
/// Most bytes read for one pack (one IPC message).
const MAX_PACK_FILES: u64 = 14 * 1024 * 1024;

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

/// Release updates: "Check for updates", "Verify this build", and (where
/// this install updates itself) "Update" (`crate::updater`).
fn updates(ui: &AppWindow, tx: tokio::sync::mpsc::UnboundedSender<Cmd>) {
    let t = tx.clone();
    ui.on_check_updates(move || {
        let _ = t.send(Cmd::CheckUpdates);
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
    let single_process = args.iter().any(|a| a == "--single-process");
    // Install checks: quit once the vault's first state is shown.
    let smoke = args.iter().any(|a| a == "--smoke-exit");
    // Wayland matches the window to its .desktop file by this id.
    let _ = slint::set_xdg_app_id("com.aricummings.Enclave");
    let ui = AppWindow::new()?;
    // The person's language, for the window and for what the vault writes.
    let lang = crate::i18n::set_language(&crate::i18n::system_language());
    let _ = slint::select_bundled_translation(lang.unwrap_or(""));
    let ((tx, mut out), _separate) = vault::start(mode, single_process);
    // Outputs from the vault, applied on the UI thread.
    let w = ui.as_weak();
    let lan_tx = tx.clone();
    std::thread::Builder::new()
        .name("enclave-ui-feed".into())
        .spawn(move || {
            // History for our other device on the local network
            // (`crate::lan`): served, and being received.
            let mut serving: std::collections::HashMap<String, crate::lan::Serving> =
                std::collections::HashMap::new();
            let mut to_serve: std::collections::HashMap<String, Vec<Vec<u8>>> =
                std::collections::HashMap::new();
            while let Some(o) = out.blocking_recv() {
                // Files are written here, in the UI process, where the
                // person chooses: the vault can't reach anything outside
                // its profile.
                let o = match o {
                    Out::File(name, bytes) => {
                        let _ = w.upgrade_in_event_loop(move |ui| save_with_dialog(&ui, name, bytes));
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
                    Out::Invite(link) => {
                        let copied = copy_with_timeout(link.clone());
                        let _ = w.upgrade_in_event_loop(move |ui| {
                            ui.set_status_line(
                                crate::i18n::tr(&if copied {
                                    "Invite link copied. It works for one person, for 7 days, and is cleared from the clipboard after 60 seconds.".to_string()
                                } else {
                                    format!("Your invite link (it works for one person, for 7 days): {link}")
                                })
                                .into(),
                            )
                        });
                        continue;
                    }
                    other => other,
                };
                let _ = w.upgrade_in_event_loop(move |ui| match o {
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
                    Out::File(..)
                    | Out::Invite(_)
                    | Out::Notify(_)
                    | Out::LanChunks(..)
                    | Out::LanStop(_)
                    | Out::LanFetch(..)
                    | Out::UpdateBundle(_) => {}
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
            ui.set_status_line(crate::i18n::tr("This takes a few seconds.").into());
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
    ui.on_new_invite(move || {
        let _ = t.send(Cmd::NewInvite(1));
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
            Ok(b) if b.len() as u64 <= MAX_FILE => b,
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
                Ok(b) if b.len() as u64 <= MAX_FILE => b,
                _ => {
                    if let Some(ui) = w.upgrade() {
                        ui.set_backup_check(crate::i18n::tr("Couldn't open that file.").into());
                    }
                    return;
                }
            }
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
    ui.on_create_poll(move |id, q, a, b, c, d| {
        let options = [a, b, c, d]
            .iter()
            .map(|o| o.trim().to_string())
            .filter(|o| !o.is_empty())
            .collect();
        let _ = t.send(Cmd::CreatePoll(id.to_string(), q.to_string(), options));
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
    ui.on_new_group_invite(move |id| {
        let _ = t.send(Cmd::NewGroupInvite(id.to_string()));
    });
    let t = tx.clone();
    ui.on_cancel_invites(move || {
        let _ = t.send(Cmd::CancelInvites);
    });
    let t = tx.clone();
    ui.on_select(move |id| {
        let _ = t.send(Cmd::Select(id.to_string()));
    });
    let t = tx.clone();
    ui.on_send(move |id, text| {
        enclave_platform::window::haptic(enclave_platform::window::Haptic::Tick);
        let _ = t.send(Cmd::Send(id.to_string(), text.to_string()));
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
            ui.set_sheet(Sheet::Player);
        }
        let _ = t.send(Cmd::PlayClip(id.to_string(), seq));
    });
    let t = tx.clone();
    ui.on_change_words(move || {
        let _ = t.send(Cmd::ChangeWords);
    });
    let t = tx.clone();
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
    ui.on_send_file(move |id, path, caption| {
        let path = std::path::PathBuf::from(path.trim());
        let result = std::fs::metadata(&path).and_then(|m| {
            if m.len() > MAX_FILE {
                Err(std::io::Error::other("larger than 15 MB"))
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
                let _ = t.send(Cmd::SendFile(
                    id.to_string(),
                    name,
                    bytes,
                    caption.to_string(),
                ));
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
        phone::delivery(&ui);
    }
    if smoke {
        slint::Timer::single_shot(Duration::from_secs(60), || {
            eprintln!("enclave: the vault didn't start within 60 s");
            std::process::exit(1);
        });
    }
    ui.run()
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
            3 => Pick::Pictures,
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
    }
}
#[cfg(not(desktop))]
use phone::*;
