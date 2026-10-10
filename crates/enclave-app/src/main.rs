//! Desktop entry point.
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
#![deny(unsafe_code)]
// A GUI program on Windows: no console window opens with it.
#![cfg_attr(windows, windows_subsystem = "windows")]

use enclave_app::{AppWindow, Screen, Sheet, vault, view};
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

/// A file's name as the sender gave it, made safe to suggest: its last
/// component only, never hidden.
fn safe_name(name: &str) -> String {
    std::path::Path::new(name)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.') && !n.is_empty())
        .unwrap_or_else(|| "file".into())
}

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
            ui.set_file_note(note.into());
        }
    });
}

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
            note.appname("Enclave").summary(&n.title).body(&n.body);
            #[cfg(windows)]
            note.app_id(NOTIFY_APP_ID);
            #[cfg(all(unix, not(target_os = "macos")))]
            note.icon("io.github.EnclaveChat.Enclave");
            let _ = note.show();
        });
}

/// The app's id for notifications (Windows toasts need the installer's
/// Start menu shortcut to carry it, `packaging/windows`).
#[cfg(windows)]
const NOTIFY_APP_ID: &str = "io.github.EnclaveChat.Enclave";

/// The system's file dialog for one of the path fields (`browse` in the
/// UI): the chosen paths go into the field.
fn browse(ui: &AppWindow, what: i32) {
    let w = ui.as_weak();
    let _ = slint::spawn_local(async move {
        let d = rfd::AsyncFileDialog::new().set_directory(downloads());
        let paths: Vec<String> = match what {
            0 | 1 => d
                .add_filter("Enclave backup", &["enclave"])
                .set_title("Choose your backup")
                .pick_file()
                .await
                .into_iter()
                .collect(),
            3 => d
                .add_filter("Pictures", &["png", "jpg", "jpeg", "gif", "webp"])
                .set_title("Choose pictures for the pack")
                .pick_files()
                .await
                .unwrap_or_default(),
            _ => d
                .set_title("Choose a file to send")
                .pick_file()
                .await
                .into_iter()
                .collect(),
        }
        .iter()
        .map(|f| f.path().display().to_string())
        .collect();
        let (Some(ui), false) = (w.upgrade(), paths.is_empty()) else {
            return;
        };
        let joined = paths.join("; ");
        match what {
            0 => ui.set_restore_file(joined.into()),
            1 => ui.set_check_file(joined.into()),
            3 => ui.set_pack_paths(joined.into()),
            _ => ui.set_attach_path(joined.into()),
        }
    });
}

fn main() -> Result<(), slint::PlatformError> {
    // Started from a terminal, its messages still show there.
    enclave_platform::process::attach_parent_console();
    let args: Vec<String> = std::env::args().collect();
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
    let single_process = args.iter().any(|a| a == "--single-process");
    let ui = AppWindow::new()?;
    let ((tx, mut out), _separate) = vault::start(mode, single_process);
    // Outputs from the vault, applied on the UI thread.
    let w = ui.as_weak();
    std::thread::Builder::new()
        .name("enclave-ui-feed".into())
        .spawn(move || {
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
                        let _ = w.upgrade_in_event_loop(move |ui| notify(&ui, n));
                        continue;
                    }
                    Out::Invite(link) => {
                        copy_with_timeout(link);
                        let _ = w.upgrade_in_event_loop(|ui| {
                            ui.set_status_line(
                                "Invite link copied. It works for one person, for 7 days, and is cleared from the clipboard after 60 seconds.".into(),
                            )
                        });
                        continue;
                    }
                    other => other,
                };
                let _ = w.upgrade_in_event_loop(move |ui| match o {
                    Out::Snapshot(s) => view::apply(&ui, &s),
                    Out::Effect(e) => view::apply_effect(&ui, e),
                    Out::Preview(p) => view::apply_preview(&ui, p),
                    Out::Clip(c) => view::apply_clip(&ui, c),
                    Out::File(..) | Out::Invite(_) | Out::Notify(_) => {}
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
            ui.set_status_line("This takes a few seconds.".into());
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
                    ui.set_restore_error("That file is too large to be an Enclave backup.".into());
                }
                return;
            }
            Err(e) => {
                if let Some(ui) = w.upgrade() {
                    ui.set_restore_error(format!("Couldn't open that file: {e}").into());
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
    // Notifications come from the app's bundle (an unbundled build keeps
    // the system's default sender).
    #[cfg(target_os = "macos")]
    let _ = notify_rust::set_application("io.github.EnclaveChat.Enclave");
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
    let w = ui.as_weak();
    ui.on_load_licences(move || {
        if let Some(ui) = w.upgrade()
            && ui.get_licences().row_count() == 0
        {
            ui.set_licences(view::licences());
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
                        ui.set_backup_check("Couldn't open that file.".into());
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
                    ui.set_pack_error(format!("Couldn't read {p}: {e}.").into());
                    return;
                }
            }
        }
        if pictures.is_empty() || pictures.len() > 40 {
            ui.set_pack_error("A pack needs 1 to 40 pictures.".into());
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
                    ui.set_attach_error(format!("Couldn't read that file: {e}.").into());
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
        copy_with_timeout(text.to_string());
        if let Some(ui) = w.upgrade() {
            ui.set_status_line("Copied. It's cleared from the clipboard after 60 seconds.".into());
        }
    });
    let _ = Sheet::None;
    ui.run()
}

/// Copy, then clear the clipboard after 60 s if it still holds our text.
fn copy_with_timeout(text: String) {
    let Ok(mut cb) = arboard::Clipboard::new() else {
        return;
    };
    if cb.set_text(text.clone()).is_err() {
        return;
    }
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(60));
        if let Ok(mut cb) = arboard::Clipboard::new()
            && cb.get_text().ok().as_deref() == Some(text.as_str())
        {
            let _ = cb.clear();
        }
    });
}
