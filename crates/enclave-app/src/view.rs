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
        preview: r.preview.clone().into(),
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
    ui.set_status_line(s.status.clone().into());
    ui.set_recovery_words(strings(&s.recovery_words));
    ui.set_recovery_saved(s.recovery_saved);
    ui.set_words_language(s.words_language.clone().into());
    ui.set_privacy(s.privacy);
    ui.set_finishing(s.finishing);
    ui.set_gap(s.gap);
    ui.set_on_record(s.on_record);
    ui.set_closed(s.closed);
    ui.set_add_error(s.add_error.clone().into());
    ui.set_my_username(s.my_username.clone().into());
    ui.set_usernames(s.usernames);
    ui.set_username_error(s.username_error.clone().into());
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
    ui.set_link_status(s.link_status.clone().into());
    ui.set_can_link(s.can_link);
    ui.set_can_join(s.can_join);
    if ui.get_join_code().as_str() != s.join_code {
        ui.set_join_code(s.join_code.clone().into());
        if !s.join_code.is_empty() {
            ui.set_join_qr(qr_image(&s.join_code));
        }
    }
    ui.set_join_words(s.join_words.clone().into());
    ui.set_recovery_alert(s.recovery_alert.clone().into());
    ui.set_recovery_hold(s.recovery_hold.clone().into());
    ui.set_recovery_stopped(s.recovery_stopped);
    ui.set_username_problem(s.username_problem.clone().into());
    ui.set_kt_split(s.kt_split.clone().into());
    ui.set_route(i32::from(s.route));
    ui.set_tor_blocked(s.tor_blocked);
    ui.set_bridges(s.bridges.clone().into());
    ui.set_bridges_error(s.bridges_error.clone().into());
    ui.set_bridges_restart(s.bridges_restart);
    ui.set_clock_skew(s.clock_skew.clone().into());
    ui.set_new_device(s.new_device.clone().into());
    ui.set_joining(s.joining.join(", ").into());
    ui.set_restore_error(s.restore_error.clone().into());
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
    ui.set_unlock_error(s.unlock_error.clone().into());
    ui.set_can_lock(s.can_lock);
    ui.set_invites(s.invites as i32);
    ui.set_typing_setting(s.typing_setting);
    ui.set_typing(s.typing);
    ui.set_can_change_words(s.can_change_words);
    ui.set_removed(s.removed);
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
    ui.set_meet_words(s.meet_words.clone().into());
    ui.set_meet_name(s.meet_name.clone().into());
    ui.set_meet_error(s.meet_error.clone().into());
    ui.set_meet_done(s.meet_done.clone().into());
    if s.locked {
        if ui.get_screen() != Screen::Locked {
            ui.set_screen(Screen::Locked);
        }
    } else if !s.my_name.is_empty() && ui.get_screen() != Screen::Main {
        ui.set_screen(Screen::Main);
    }
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
