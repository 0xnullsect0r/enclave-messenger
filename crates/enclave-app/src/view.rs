//! Turns display data from the vault ([`enclave_ipc`]) into Slint models on
//! the UI thread.

use crate::{AppWindow, ContactRow, DeviceRow, MessageRow, PickRow, Screen, Sheet};
pub use enclave_ipc::{ClipFrames, Device, Effect, Msg, Pick, Preview, Row, Snapshot};
use slint::{
    Color, Image, Model, ModelRc, Rgb8Pixel, Rgba8Pixel, SharedPixelBuffer, SharedString, VecModel,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

thread_local! {
    /// Picture previews by (conversation, message position), for this run
    /// of the UI. Pixels only: mediad already decoded them.
    static PREVIEWS: RefCell<HashMap<(String, u64), Image>> = RefCell::new(HashMap::new());
}

fn preview(conversation: &str, seq: u64) -> Option<Image> {
    PREVIEWS.with(|p| p.borrow().get(&(conversation.to_string(), seq)).cloned())
}

/// Keep a preview and show it if its conversation is open.
/// A clip's frames: into the player, from the first frame.
pub fn apply_clip(ui: &AppWindow, c: ClipFrames) {
    let frames: Vec<Image> = c
        .frames
        .iter()
        .map(|f| {
            Image::from_rgba8(SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(
                f, c.width, c.height,
            ))
        })
        .collect();
    ui.set_player_index(0);
    ui.set_player_interval(i64::from(c.interval_ms.clamp(20, 2000)));
    ui.set_player_frames(ModelRc::from(Rc::new(VecModel::from(frames))));
}

pub fn apply_preview(ui: &AppWindow, p: Preview) {
    let img = Image::from_rgba8(SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(
        &p.pixels, p.width, p.height,
    ));
    PREVIEWS.with(|c| {
        c.borrow_mut()
            .insert((p.conversation.clone(), p.seq), img.clone())
    });
    if p.conversation.starts_with("stickers/") {
        let model = ui.get_sticker_cells();
        for i in 0..model.row_count() {
            if let Some(mut c) = model.row_data(i)
                && format!("stickers/{}", c.pack) == p.conversation
                && c.index as u64 == p.seq
            {
                c.image = img.clone();
                c.has_image = true;
                model.set_row_data(i, c);
            }
        }
        return;
    }
    if ui.get_current_id().as_str() != p.conversation {
        return;
    }
    let model = ui.get_messages();
    let seq = p.seq.to_string();
    for i in 0..model.row_count() {
        if let Some(mut r) = model.row_data(i)
            && r.seq == seq
        {
            r.image = img.clone();
            r.has_image = true;
            model.set_row_data(i, r);
        }
    }
}

/// Contact art tints: muted, each at least 7:1 against the Paper initials.
const TINTS: [(u8, u8, u8); enclave_ipc::TINT_COUNT] = [
    (0x3F, 0x5A, 0x7A),
    (0x6B, 0x4E, 0x2E),
    (0x7A, 0x3F, 0x5A),
    (0x4E, 0x5F, 0x2E),
    (0x2E, 0x5F, 0x6B),
    (0x6B, 0x2E, 0x2E),
];

/// Initials for contact art: first letters of up to two words.
pub fn initials(name: &str) -> String {
    let s: String = name
        .split_whitespace()
        .filter_map(|w| w.chars().next())
        .take(2)
        .collect();
    if s.is_empty() {
        "?".into()
    } else {
        s.to_uppercase()
    }
}

fn tint(i: usize) -> Color {
    let (r, g, b) = TINTS[i % TINTS.len()];
    Color::from_rgb_u8(r, g, b)
}

fn row(r: &Row) -> ContactRow {
    ContactRow {
        id: r.id.clone().into(),
        name: r.name.clone().into(),
        // Note to self is "Me".
        initials: if r.kind == 2 {
            "Me".into()
        } else {
            initials(&r.name).into()
        },
        tint: tint(r.tint),
        preview: crate::format::preview(&r.preview).into(),
        time: r.time.clone().into(),
        unread: r.unread,
        state: r.state,
        verified: r.verified,
        met: r.met,
        kind: r.kind,
        members: r.members,
        pinned: r.pinned,
        muted: r.muted,
        archived: r.archived,
        blocked: r.blocked,
        admin: r.admin,
        art: (r.art & 0x01ff_ffff) as i32,
        art_tint: art_tint((r.art >> 25) as usize),
    }
}

/// Contact-art tints (`docs/17-design.md` §6.7): Pine and neutrals, never
/// Saffron.
const ART_TINTS: [(u8, u8, u8); 8] = [
    (0x1F, 0x5C, 0x4A),
    (0x2F, 0x7A, 0x63),
    (0x3E, 0x8F, 0x76),
    (0x4E, 0x6B, 0x5E),
    (0x5B, 0x5F, 0x57),
    (0x6F, 0x6A, 0x5E),
    (0x3D, 0x4A, 0x45),
    (0x7C, 0x8C, 0x83),
];

fn art_tint(i: usize) -> Color {
    let (r, g, b) = ART_TINTS[i % ART_TINTS.len()];
    Color::from_rgb_u8(r, g, b)
}

fn pick_row(p: &Pick) -> PickRow {
    PickRow {
        id: p.id.clone().into(),
        name: p.name.clone().into(),
        initials: initials(&p.name).into(),
        tint: tint(p.tint),
        selected: p.selected,
    }
}

fn strings(v: &[String]) -> ModelRc<SharedString> {
    ModelRc::from(Rc::new(VecModel::from(
        v.iter().map(SharedString::from).collect::<Vec<_>>(),
    )))
}

/// A QR code as a Slint image (Ink modules on white, 4-module quiet zone).
/// Medium error correction, or Low for codes too long for it (the sealed
/// recovery share).
pub fn qr_image(text: &str) -> Image {
    let Ok(qr) = qrcodegen::QrCode::encode_text(text, qrcodegen::QrCodeEcc::Medium)
        .or_else(|_| qrcodegen::QrCode::encode_text(text, qrcodegen::QrCodeEcc::Low))
    else {
        return Image::default();
    };
    let border = 4;
    let size = (qr.size() + 2 * border) as u32;
    let mut buf = SharedPixelBuffer::<Rgb8Pixel>::new(size, size);
    let px = buf.make_mut_slice();
    for y in 0..size as i32 {
        for x in 0..size as i32 {
            let dark = qr.get_module(x - border, y - border);
            let c = if dark {
                Rgb8Pixel::new(0x1C, 0x1F, 0x1D)
            } else {
                Rgb8Pixel::new(0xFF, 0xFF, 0xFF)
            };
            px[(y as u32 * size + x as u32) as usize] = c;
        }
    }
    Image::from_rgb8(buf)
}

/// Push a snapshot into the window.
pub fn apply(ui: &AppWindow, s: &Snapshot) {
    ui.set_my_name(s.my_name.clone().into());
    ui.set_my_initials(initials(&s.my_name).into());
    if ui.get_my_link().as_str() != s.my_link {
        ui.set_my_link(s.my_link.clone().into());
        ui.set_my_qr(qr_image(&s.my_link));
    }
    ui.set_contacts(ModelRc::from(Rc::new(VecModel::from(
        s.contacts.iter().map(row).collect::<Vec<_>>(),
    ))));
    ui.set_requests(ModelRc::from(Rc::new(VecModel::from(
        s.requests.iter().map(row).collect::<Vec<_>>(),
    ))));
    ui.set_archived(ModelRc::from(Rc::new(VecModel::from(
        s.archived.iter().map(row).collect::<Vec<_>>(),
    ))));
    match &s.current {
        Some(c) => {
            ui.set_current(row(c));
            ui.set_current_id(c.id.clone().into());
        }
        None => ui.set_current_id(SharedString::new()),
    }
    let conversation = s.current.as_ref().map(|c| c.id.clone()).unwrap_or_default();
    let msgs: Vec<MessageRow> = s
        .messages
        .iter()
        .map(|m| {
            let img = if m.image {
                preview(&conversation, m.seq)
            } else {
                None
            };
            (m, img)
        })
        .map(|(m, img)| MessageRow {
            text: m.text.clone().into(),
            rich: crate::format::styled(&m.text, false),
            rich_revealed: crate::format::styled(&m.text, true),
            spoken: crate::format::spoken(&m.text, false).into(),
            spoken_revealed: crate::format::spoken(&m.text, true).into(),
            outgoing: m.outgoing,
            time: m.time.clone().into(),
            status: m.status,
            sender: m.sender.clone().into(),
            seq: m.seq.to_string().into(),
            can_edit: m.can_edit,
            deleted: m.deleted,
            file: m.file.clone().into(),
            picture: m.image,
            poll_state: m.poll_state,
            poll_ours: m.poll_ours,
            pinned: m.pinned,
            contact_name: m.contact_name.clone().into(),
            contact_initials: initials(&m.contact_name).into(),
            contact_known: m.contact_known,
            location: m.location.clone().into(),
            location_label: m.location_label.clone().into(),
            sticker: m.sticker,
            pack_added: m.pack_added,
            voice: m.voice,
            // Every other point of 64: a bubble-sized waveform.
            waveform: ModelRc::from(Rc::new(VecModel::from(
                m.waveform
                    .iter()
                    .step_by(2)
                    .map(|&w| i32::from(w))
                    .collect::<Vec<_>>(),
            ))),
            clip_time: if m.clip_ms > 0 {
                let s = m.clip_ms.div_ceil(1000);
                format!("{}:{:02}", s / 60, s % 60).into()
            } else {
                SharedString::new()
            },
            voice_time: if m.voice_ms > 0 {
                let s = m.voice_ms.div_ceil(1000);
                format!("{}:{:02}", s / 60, s % 60).into()
            } else {
                SharedString::new()
            },
            poll_options: ModelRc::from(Rc::new(VecModel::from(
                m.poll_options
                    .iter()
                    .enumerate()
                    .map(|(i, t)| crate::PollOption {
                        text: t.clone().into(),
                        count: m.poll_counts.get(i).copied().unwrap_or(0) as i32,
                        mine: m.poll_mine == i as i32 + 1,
                    })
                    .collect::<Vec<_>>(),
            ))),
            has_image: img.is_some(),
            image: img.unwrap_or_default(),
        })
        .collect();
    ui.set_gallery_count(
        s.messages
            .iter()
            .filter(|m| !m.file.is_empty() && !m.deleted)
            .count() as i32,
    );
    ui.set_messages(ModelRc::from(Rc::new(VecModel::from(msgs))));
    ui.set_code_groups(strings(&s.code_groups));
    ui.set_code_words(strings(&s.code_words));
    ui.set_code_words_english(s.code_words_english);
    ui.set_status_line(crate::i18n::tr(&s.status).into());
    ui.set_recovery_words(strings(&s.recovery_words));
    ui.set_recovery_saved(s.recovery_saved);
    ui.set_words_language(s.words_language.clone().into());
    ui.set_privacy(s.privacy);
    ui.set_finishing(s.finishing);
    ui.set_gap(s.gap);
    ui.set_on_record(s.on_record);
    ui.set_closed(s.closed);
    ui.set_add_error(crate::i18n::tr(&s.add_error).into());
    ui.set_my_username(s.my_username.clone().into());
    ui.set_usernames(s.usernames);
    ui.set_username_error(crate::i18n::tr(&s.username_error).into());
    ui.set_busy(s.busy);
    let pick: Vec<PickRow> = s.pick.iter().map(pick_row).collect();
    ui.set_pick(ModelRc::from(Rc::new(VecModel::from(pick))));
    let devices: Vec<DeviceRow> = s
        .devices
        .iter()
        .map(|d| DeviceRow {
            id: d.id.clone().into(),
            label: d.label.clone().into(),
            detail: d.detail.clone().into(),
            removable: d.removable,
            history_action: d.history_action.clone().into(),
        })
        .collect();
    ui.set_devices(ModelRc::from(Rc::new(VecModel::from(devices))));
    ui.set_link_choices(strings(&s.link_choices));
    ui.set_link_status(crate::i18n::tr(&s.link_status).into());
    ui.set_can_link(s.can_link);
    ui.set_can_join(s.can_join);
    if ui.get_join_code().as_str() != s.join_code {
        ui.set_join_code(s.join_code.clone().into());
        if !s.join_code.is_empty() {
            ui.set_join_qr(qr_image(&s.join_code));
        }
    }
    ui.set_join_words(s.join_words.clone().into());
    ui.set_recovery_alert(crate::i18n::tr(&s.recovery_alert).into());
    ui.set_recovery_hold(crate::i18n::tr(&s.recovery_hold).into());
    ui.set_recovery_stopped(s.recovery_stopped);
    ui.set_username_problem(crate::i18n::tr(&s.username_problem).into());
    ui.set_kt_split(crate::i18n::tr(&s.kt_split).into());
    ui.set_route(i32::from(s.route));
    ui.set_tor_blocked(s.tor_blocked);
    ui.set_bridges(s.bridges.clone().into());
    ui.set_bridges_error(s.bridges_error.clone().into());
    ui.set_bridges_restart(s.bridges_restart);
    ui.set_clock_skew(crate::i18n::tr(&s.clock_skew).into());
    ui.set_update_release(s.update_release.clone().into());
    ui.set_update_required(i32::from(s.update_required));
    ui.set_build_check(crate::i18n::tr(&s.build_check).into());
    apply_call(ui, s);
    ui.set_new_device(s.new_device.clone().into());
    ui.set_joining(s.joining.join(", ").into());
    ui.set_restore_error(crate::i18n::tr(&s.restore_error).into());
    ui.set_friends(ModelRc::from(Rc::new(VecModel::from(
        s.friends.iter().map(pick_row).collect::<Vec<_>>(),
    ))));
    ui.set_friends_chosen(s.friends.iter().filter(|p| p.selected).count() as i32);
    ui.set_share_holders(strings(&s.share_holders));
    ui.set_share_threshold(s.share_threshold as i32);
    ui.set_holds_share(s.holds_share);
    if ui.get_share_release().as_str() != s.share_release {
        ui.set_share_release(s.share_release.clone().into());
        if !s.share_release.is_empty() {
            ui.set_share_release_qr(qr_image(&s.share_release));
        }
    }
    ui.set_share_release_words(s.share_release_words.clone().into());
    if ui.get_share_request().as_str() != s.share_request {
        ui.set_share_request(s.share_request.clone().into());
        if !s.share_request.is_empty() {
            ui.set_share_request_qr(qr_image(&s.share_request));
        }
    }
    ui.set_share_request_words(s.share_request_words.clone().into());
    ui.set_pins(strings(&s.pins));
    ui.set_sticker_packs(ModelRc::from(Rc::new(VecModel::from(
        s.sticker_packs
            .iter()
            .map(|p| crate::StickerPackRow {
                id: p.id.clone().into(),
                title: p.title.clone().into(),
                count: p.count as i32,
            })
            .collect::<Vec<_>>(),
    ))));
    let cells: Vec<crate::StickerCell> = s
        .sticker_packs
        .iter()
        .flat_map(|p| {
            (0..p.count).map(move |i| {
                let img = preview(&format!("stickers/{}", p.id), u64::from(i));
                crate::StickerCell {
                    pack: p.id.clone().into(),
                    index: i as i32,
                    has_image: img.is_some(),
                    image: img.unwrap_or_default(),
                }
            })
        })
        .collect();
    ui.set_sticker_cells(ModelRc::from(Rc::new(VecModel::from(cells))));
    ui.set_unlock_error(crate::i18n::tr(&s.unlock_error).into());
    ui.set_can_lock(s.can_lock);
    ui.set_pin_lock(s.pin_lock);
    ui.set_server_backup(s.server_backup);
    ui.set_server_backup_at(s.server_backup_at.clone().into());
    ui.set_backup_check(crate::i18n::tr(&s.backup_check).into());
    apply_servers(ui, s);
    ui.set_file_keys(s.file_keys);
    ui.set_biometric(s.biometric.clone().into());
    ui.set_biometric_on(s.biometric_on);
    if ui.get_screen_security() != s.screen_security {
        ui.set_screen_security(s.screen_security);
        apply_screen_security(ui);
    }
    ui.set_app_lock(s.app_lock);
    ui.set_lock_timeout(i32::try_from(s.lock_timeout).unwrap_or(i32::MAX));
    ui.set_invites(s.invites as i32);
    ui.set_typing_setting(s.typing_setting);
    ui.set_typing(s.typing);
    ui.set_can_change_words(s.can_change_words);
    ui.set_removed(s.removed);
    ui.set_has_root_pin(s.has_root_pin);
    ui.set_securing(s.securing);
    ui.set_previews(s.previews);
    ui.set_pin_error(crate::i18n::tr(&s.pin_error).into());
    ui.set_held_moves(s.held_moves.join(", ").into());
    ui.set_words_pending(s.words_pending);
    ui.set_moved(i32::from(s.moved));
    ui.set_members(ModelRc::from(Rc::new(VecModel::from(
        s.members.iter().map(row).collect::<Vec<_>>(),
    ))));
    ui.set_group_admin(s.group_admin);
    ui.set_addable(ModelRc::from(Rc::new(VecModel::from(
        s.addable.iter().map(pick_row).collect::<Vec<_>>(),
    ))));
    ui.set_timer(s.timer as i32);
    ui.set_search_results(ModelRc::from(Rc::new(VecModel::from(
        s.search.iter().map(row).collect::<Vec<_>>(),
    ))));
    if ui.get_meet_code().as_str() != s.meet_code {
        ui.set_meet_code(s.meet_code.clone().into());
        if !s.meet_code.is_empty() {
            ui.set_meet_qr(qr_image(&s.meet_code));
        }
    }
    // The Seal closes when both have scanned: a haptic pulse with it.
    if ui.get_meet_words().is_empty() && !s.meet_words.is_empty() {
        enclave_platform::window::haptic(enclave_platform::window::Haptic::SealClosed);
    }
    ui.set_meet_words(s.meet_words.clone().into());
    ui.set_meet_name(s.meet_name.clone().into());
    ui.set_meet_error(crate::i18n::tr(&s.meet_error).into());
    ui.set_meet_done(s.meet_done.clone().into());
    if s.locked {
        if ui.get_screen() != Screen::Locked {
            ui.set_screen(Screen::Locked);
        }
    } else if !s.my_name.is_empty() && ui.get_screen() != Screen::Main {
        ui.set_screen(Screen::Main);
    }
}

/// The server picker and what it says about the home server and the open
/// group's.
fn apply_servers(ui: &AppWindow, s: &Snapshot) {
    let named = |id: &str| -> String {
        s.servers.iter().find(|v| v.id == id).map_or_else(
            || format!("a server not in the list ({})", &id[..id.len().min(8)]),
            |v| v.domain.clone(),
        )
    };
    let votes = |id: &str| -> i32 {
        s.group_votes
            .iter()
            .filter_map(|v| v.split_once(':'))
            .find(|(h, _)| *h == id)
            .and_then(|(_, n)| n.parse().ok())
            .unwrap_or(0)
    };
    ui.set_servers(ModelRc::from(Rc::new(VecModel::from(
        s.servers
            .iter()
            .map(|v| crate::ServerOption {
                id: v.id.clone().into(),
                domain: v.domain.clone().into(),
                operator: v.operator.clone().into(),
                votes: votes(&v.id),
            })
            .collect::<Vec<_>>(),
    ))));
    ui.set_home_id(s.home.clone().into());
    ui.set_home_label(
        if s.home.is_empty() {
            String::new()
        } else {
            match s.servers.iter().find(|v| v.id == s.home) {
                Some(v) => format!("{}, run by {}", v.domain, v.operator),
                None => named(&s.home),
            }
        }
        .into(),
    );
    ui.set_moving(s.moving);
    ui.set_can_move(s.can_move);
    ui.set_group_host(s.group_host.clone().into());
    ui.set_group_admins(i32::try_from(s.group_admins).unwrap_or(i32::MAX));
    ui.set_group_host_label(
        if s.group_host.is_empty() {
            String::new()
        } else {
            format!(
                "This group's messages are kept on {}.",
                named(&s.group_host)
            )
        }
        .into(),
    );
    ui.set_group_vote_label(
        if s.group_vote.is_empty() {
            String::new()
        } else {
            format!(" You voted to move it to {}.", named(&s.group_vote))
        }
        .into(),
    );
}

/// Apply a one-off reset from the vault.
pub fn apply_effect(ui: &AppWindow, e: Effect) {
    match e {
        Effect::ContactAdded => {
            ui.set_sheet(Sheet::None);
            ui.set_add_link("".into());
            ui.set_add_text("".into());
        }
        Effect::GroupCreated => {
            ui.set_sheet(Sheet::None);
            ui.set_group_name("".into());
        }
        Effect::UsernameClaimed => ui.set_username_input("".into()),
        Effect::RemovalDone => ui.set_confirm_remove("".into()),
        Effect::PassphraseChanged => ui.set_new_passphrase("".into()),
        Effect::LeftGroup => {
            ui.set_sheet(Sheet::None);
            ui.set_current_id("".into());
        }
        Effect::Erased => {
            ui.set_sheet(Sheet::None);
            ui.set_current_id("".into());
            ui.set_screen(Screen::Welcome);
        }
        Effect::PollCreated => {
            ui.set_sheet(Sheet::None);
            for set in [
                AppWindow::set_poll_question,
                AppWindow::set_poll_a,
                AppWindow::set_poll_b,
                AppWindow::set_poll_c,
                AppWindow::set_poll_d,
            ] {
                set(ui, "".into());
            }
        }
        Effect::FileSent => {
            ui.set_sheet(Sheet::None);
            ui.set_attach_path("".into());
            ui.set_attach_caption("".into());
        }
    }
}

/// Keep the window out of screen capture, or not, as the profile says
/// (`docs/14-storage.md` §5; nothing to do on Linux).
pub fn apply_screen_security(ui: &AppWindow) {
    #[cfg(desktop)]
    enclave_platform::window::exclude_from_capture(
        &slint::ComponentHandle::window(ui).window_handle(),
        ui.get_screen_security(),
    );
    #[cfg(not(desktop))]
    enclave_platform::phone::set_screen_security(ui.get_screen_security());
}

/// The open-source notices (`cargo xtask licenses`), one entry per licence
/// text with the packages under it.
pub fn licences() -> ModelRc<crate::LicenceEntry> {
    const NOTICES: &str = include_str!("../licenses.txt");
    let mut parts = NOTICES.split("\n=== ");
    let intro = parts.next().unwrap_or_default().trim();
    let mut rows = vec![crate::LicenceEntry {
        title: "Enclave".into(),
        text: intro.into(),
    }];
    rows.extend(parts.map(|p| {
        let (title, text) = p.split_once('\n').unwrap_or((p, ""));
        crate::LicenceEntry {
            title: title.into(),
            text: text.trim().into(),
        }
    }));
    ModelRc::from(Rc::new(VecModel::from(rows)))
}

/// The call screen.
fn apply_call(ui: &AppWindow, s: &Snapshot) {
    let c = &s.call;
    ui.set_call_state(i32::from(c.state));
    ui.set_call_name(c.name.clone().into());
    ui.set_call_initials(initials(&c.name).into());
    let t = s
        .contacts
        .iter()
        .find(|r| r.id == c.conversation)
        .map_or(0, |r| r.tint);
    ui.set_call_tint(tint(t));
    ui.set_call_video(c.video);
    ui.set_call_muted(c.muted);
    ui.set_call_camera(c.camera);
    ui.set_call_direct_asked(c.direct_asked);
    ui.set_call_direct(c.direct);
    ui.set_call_group(c.group);
    ui.set_call_hand(c.hand);
    ui.set_call_cameras_full(c.cameras_full);
    ui.set_current_call_live(
        c.live_groups
            .iter()
            .any(|g| s.current.as_ref().is_some_and(|r| &r.id == g)),
    );
    // Pictures come between snapshots (`Out::CallTile`): kept per person.
    let old = ui.get_call_peers();
    let tiles: Vec<crate::CallPeerTile> = c
        .peers
        .iter()
        .map(|p| {
            let id = i32::from_ne_bytes(p.id.to_ne_bytes());
            let before = (0..old.row_count())
                .filter_map(|i| old.row_data(i))
                .find(|t| t.id == id);
            crate::CallPeerTile {
                id,
                name: p.name.clone().into(),
                initials: initials(&p.name).into(),
                tint: tint(p.id as usize),
                hand: p.hand,
                reaction: p.reaction.clone().into(),
                has_picture: before.as_ref().is_some_and(|t| t.has_picture),
                picture: before.map(|t| t.picture).unwrap_or_default(),
            }
        })
        .collect();
    ui.set_call_peers(ModelRc::from(Rc::new(VecModel::from(tiles))));
    ui.set_call_words(c.words.clone().into());
    ui.set_call_note(crate::i18n::tr(&c.error).into());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let elapsed = if c.connected_at > 0 {
        now.saturating_sub(c.connected_at)
    } else {
        0
    };
    ui.set_call_elapsed(i32::try_from(elapsed).unwrap_or(0));
}
