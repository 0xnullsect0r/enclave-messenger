//! Headless screenshots of every screen, light and dark, phone and desktop,
//! rendered with Slint's software renderer. Used for design review and the
//! screenshot diff in CI: `cargo run -p enclave-app --bin enclave-shots -- OUT_DIR`.
//!
//! The people and messages here are illustrative placeholders.
#![deny(unsafe_code)]

use enclave_app::view::{self, Msg, Pick, Row, Snapshot};
use enclave_app::{AppWindow, Screen, Sheet, Tokens};
use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{Platform, WindowAdapter};
use slint::{ComponentHandle, PhysicalSize, Rgb8Pixel};
use std::path::{Path, PathBuf};
use std::rc::Rc;

struct Headless(Rc<MinimalSoftwareWindow>);

impl Platform for Headless {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
        Ok(self.0.clone())
    }
}

/// Mirrored placeholder art from a name (the app's comes from the root
/// key, `enclave_core::art`).
fn placeholder_art(name: &str) -> u32 {
    let h = enclave_crypto::hash::sha3_512(name.as_bytes());
    let bits = u32::from(u16::from_be_bytes([h[0], h[1]])) & 0x7fff;
    let mut cells = 0;
    for row in 0..5 {
        for col in 0..3 {
            if bits & (1 << (3 * row + col)) != 0 {
                cells |= (1 << (5 * row + col)) | (1 << (5 * row + 4 - col));
            }
        }
    }
    cells | (u32::from(h[2] % 8) << 25)
}

fn fixture() -> Snapshot {
    let row = |id: &str,
               name: &str,
               preview: &str,
               time: &str,
               unread: i32,
               state: i32,
               verified: bool,
               tint: usize| Row {
        id: id.into(),
        name: name.into(),
        preview: preview.into(),
        time: time.into(),
        unread,
        state,
        verified,
        met: verified,
        tint,
        kind: 0,
        members: 0,
        art: placeholder_art(name),
        ..Default::default()
    };
    let seq = std::cell::Cell::new(0u64);
    let msg = |text: &str, outgoing: bool, time: &str, status: i32| {
        seq.set(seq.get() + 1);
        Msg {
            text: text.into(),
            outgoing,
            time: time.into(),
            status,
            sender: String::new(),
            seq: seq.get(),
            can_edit: outgoing,
            ..Default::default()
        }
    };
    let words = "absurd amount arctic brisk canyon cedar civil cluster dove eager ember fabric glide harbor ivory jungle kettle lunar meadow noble orbit pepper quartz ridge";
    Snapshot {
        my_name: "Robin Ahmadi".into(),
        my_link:
            "enclave:add#AQx7c2Vh-bGVkIHdpdGggYSBmb2xkZWQgY29ybmVy_c28gdGhlIGxpbmsgbG9va3MgcmVhbA"
                .into(),
        contacts: vec![
            row(
                "a1",
                "Sam Okafor",
                "Tomorrow works. Same café?",
                "14:02",
                2,
                2,
                true,
                0,
            ),
            row(
                "b2",
                "Priya Raman",
                "You: I'll send the draft tonight",
                "11:47",
                0,
                2,
                false,
                1,
            ),
            row("c3", "Lucía Fernández", "", "", 0, 0, false, 2),
            row(
                "d4",
                "Tomasz",
                "Thanks for checking in 🙂",
                "Mon",
                0,
                2,
                false,
                4,
            ),
        ],
        requests: vec![row(
            "e5",
            "Mara Lindqvist",
            "Hi, we met at the workshop on Thursday.",
            "13:20",
            1,
            1,
            false,
            3,
        )],
        archived: Vec::new(),
        current: Some(row(
            "a1",
            "Sam Okafor",
            "Tomorrow works. Same café?",
            "14:02",
            0,
            2,
            true,
            0,
        )),
        messages: vec![
            msg(
                "Are we still on for the interview prep this week?",
                false,
                "13:41",
                2,
            ),
            msg(
                "Yes. I've read the brief twice and have a few questions about the timeline.",
                true,
                "13:44",
                2,
            ),
            msg(
                "Good. Bring them. I'd rather we sort it out face to face.",
                false,
                "13:52",
                2,
            ),
            msg("Tomorrow at ten?", true, "13:58", 2),
            msg("Tomorrow works. Same café?", false, "14:02", 2),
            msg("Same café.", true, "14:03", 0),
        ],
        code_words: "orbit cedar lunar ember quartz harbor noble kettle ridge fabric"
            .split(' ')
            .map(String::from)
            .collect(),
        code_words_english: false,
        code_groups: [
            "38201", "99465", "10273", "58830", "47112", "20958", "61347", "80025", "13690",
            "72481", "56039", "04418",
        ]
        .map(String::from)
        .to_vec(),
        status: String::new(),
        recovery_words: words.split(' ').map(String::from).collect(),
        recovery_saved: false,
        words_language: "en".into(),
        privacy: 0,
        finishing: false,
        gap: false,
        on_record: false,
        closed: false,
        add_error: String::new(),
        busy: false,
        pick: vec![
            enclave_app::view::Pick {
                id: "a1".into(),
                name: "Sam Okafor".into(),
                tint: 0,
                selected: true,
            },
            enclave_app::view::Pick {
                id: "b2".into(),
                name: "Priya Raman".into(),
                tint: 1,
                selected: true,
            },
            enclave_app::view::Pick {
                id: "d4".into(),
                name: "Tomasz".into(),
                tint: 4,
                selected: false,
            },
        ],
        devices: vec![
            view::Device {
                id: "a1".into(),
                label: "This device".into(),
                detail: "Added 2 Sep 2026".into(),
                removable: false,
                history_action: String::new(),
            },
            view::Device {
                id: "b2".into(),
                label: "Linked device".into(),
                detail: "Added 30 Sep 2026 · Message history follows 24 hours after linking".into(),
                removable: true,
                history_action: "Send history now".into(),
            },
        ],
        link_choices: Vec::new(),
        link_status: String::new(),
        can_link: true,
        my_username: "@robin@enclave.example".into(),
        usernames: true,
        username_error: String::new(),
        can_join: false,
        join_code: String::new(),
        join_words: String::new(),
        recovery_alert: String::new(),
        recovery_hold: String::new(),
        recovery_stopped: false,
        meet_code: String::new(),
        meet_words: String::new(),
        meet_name: String::new(),
        meet_error: String::new(),
        meet_done: String::new(),
        timer: 0,
        search: Vec::new(),
        username_problem: String::new(),
        kt_split: String::new(),
        clock_skew: String::new(),
        new_device: String::new(),
        joining: Vec::new(),
        restore_error: String::new(),
        friends: Vec::new(),
        share_holders: Vec::new(),
        share_threshold: 0,
        holds_share: false,
        shown_share: String::new(),
        pins: Vec::new(),
        sticker_packs: Vec::new(),
        members: Vec::new(),
        group_admin: false,
        addable: Vec::new(),
        locked: false,
        unlock_error: String::new(),
        can_lock: true,
        invites: 1,
        typing_setting: false,
        typing: false,
        can_change_words: true,
        words_pending: false,
        moved: 0,
        route: 0,
        tor_blocked: false,
        bridges: String::new(),
        bridges_error: String::new(),
        bridges_restart: false,
    }
}

fn group_fixture(base: &Snapshot) -> Snapshot {
    let mut g = base.clone();
    let row = Row {
        id: "g1".into(),
        name: "Book club".into(),
        preview: "Priya: Chapter 4 by Friday?".into(),
        time: "15:10".into(),
        unread: 0,
        state: 2,
        verified: false,
        met: false,
        tint: 5,
        kind: 1,
        members: 4,
        ..Default::default()
    };
    g.contacts.insert(0, row.clone());
    g.current = Some(row);
    let m = |text: &str, sender: &str, outgoing: bool, time: &str| Msg {
        text: text.into(),
        outgoing,
        time: time.into(),
        status: 1,
        sender: sender.into(),
        ..Default::default()
    };
    g.messages = vec![
        m(
            "Welcome, everyone. First book is on the shelf by the door.",
            "Sam Okafor",
            false,
            "14:40",
        ),
        m("Chapter 4 by Friday?", "Priya Raman", false, "15:02"),
        m("Friday works for me.", "", true, "15:08"),
        m("Same here. I'll bring tea.", "Tomasz", false, "15:10"),
    ];
    g
}

fn render(window: &MinimalSoftwareWindow, ui: &AppWindow, size: (u32, u32), out: &Path) {
    window.set_size(PhysicalSize::new(size.0, size.1));
    ui.window().request_redraw();
    // Let layouts settle (Flickable viewport bindings run after the first pass).
    for _ in 0..3 {
        slint::platform::update_timers_and_animations();
        window.request_redraw();
        let mut buf = vec![Rgb8Pixel::default(); (size.0 * size.1) as usize];
        window.draw_if_needed(|r| {
            r.render(&mut buf, size.0 as usize);
        });
        if let Ok(file) = std::fs::File::create(out) {
            let mut enc = png::Encoder::new(std::io::BufWriter::new(file), size.0, size.1);
            enc.set_color(png::ColorType::Rgb);
            enc.set_depth(png::BitDepth::Eight);
            if let Ok(mut w) = enc.write_header() {
                let bytes: Vec<u8> = buf.iter().flat_map(|p| [p.r, p.g, p.b]).collect();
                let _ = w.write_image_data(&bytes);
            }
        }
    }
}

/// A simple round sticker: a coloured disc with a white seal-like ring, on
/// transparency.
fn sticker_pixels(hue: u8) -> Vec<u8> {
    let colours = [
        (0x1D, 0x56, 0x46),
        (0xF2, 0xB2, 0x30),
        (0x6B, 0x4E, 0x2E),
        (0x3F, 0x5A, 0x7A),
        (0xA8, 0x32, 0x1E),
    ];
    let (r, g, b) = colours[usize::from(hue) % colours.len()];
    let mut px = Vec::with_capacity(96 * 96 * 4);
    for y in 0..96i32 {
        for x in 0..96i32 {
            let d = ((x - 48).pow(2) + (y - 48).pow(2)) as f32;
            let p = if d < 40.0f32.powi(2) {
                if d > 30.0f32.powi(2) && d < 34.0f32.powi(2) {
                    [0xF6, 0xF3, 0xEC, 255]
                } else {
                    [r, g, b, 255]
                }
            } else {
                [0, 0, 0, 0]
            };
            px.extend_from_slice(&p);
        }
    }
    px
}

fn main() -> Result<(), slint::PlatformError> {
    let out = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "target/shots".into()),
    );
    let _ = std::fs::create_dir_all(&out);
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(Headless(window.clone())))
        .map_err(|e| slint::PlatformError::Other(e.to_string()))?;
    let ui = AppWindow::new()?;
    ui.show()?;

    let desktop = (1180, 780);
    let phone = (390, 844);
    let data = fixture();

    for dark in [false, true] {
        let mode = if dark { "dark" } else { "light" };
        ui.global::<Tokens>().set_dark(dark);
        let shot =
            |name: &str, size| render(&window, &ui, size, &out.join(format!("{name}-{mode}.png")));

        ui.set_screen(Screen::Welcome);
        ui.set_sheet(Sheet::None);
        shot("01-welcome", desktop);
        shot("01-welcome-phone", phone);
        let mut joining = Snapshot {
            can_join: true,
            join_code:
                "enclave:link#AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8w"
                    .into(),
            ..Default::default()
        };
        view::apply(&ui, &joining);
        shot("01-welcome-server-phone", phone);
        ui.set_screen(Screen::Join);
        ui.set_status_line("Waiting for your other device…".into());
        shot("18-join-code-phone", phone);
        joining.join_words = "harbor ivory kettle".into();
        view::apply(&ui, &joining);
        ui.set_status_line("Waiting for you to pick them there…".into());
        shot("18-join-words-phone", phone);
        view::apply(&ui, &Snapshot::default());
        ui.set_screen(Screen::Locked);
        ui.set_unlock_error("That passphrase doesn't open this profile.".into());
        shot("25-locked-phone", phone);
        ui.set_unlock_error("".into());
        ui.set_screen(Screen::Name);
        ui.set_name_input("Robin".into());
        shot("02-name", phone);
        ui.set_screen(Screen::SettingUp);
        ui.set_status_line("This takes a few seconds.".into());
        shot("03-setting-up", phone);

        let mut empty = data.clone();
        empty.contacts.clear();
        empty.requests.clear();
        empty.current = None;
        empty.messages.clear();
        view::apply(&ui, &empty);
        shot("04-home-empty", desktop);

        view::apply(&ui, &data);
        shot("05-conversation", desktop);
        shot("05-conversation-phone", phone);

        // The mixnet unreachable for a minute: the backup route offered.
        let mut offline = empty.clone();
        offline.route = 1;
        view::apply(&ui, &offline);
        shot("26-backup-route-phone", phone);
        offline.route = 2;
        view::apply(&ui, &offline);
        shot("26-on-backup-route-phone", phone);
        // Tor blocked: bridges offered.
        offline.route = 0;
        offline.tor_blocked = true;
        view::apply(&ui, &offline);
        shot("27-tor-blocked-phone", phone);
        view::apply(&ui, &data);

        // A picture from Sam, with its preview (as mediad would send it).
        let mut pic = data.clone();
        let id = pic
            .current
            .as_ref()
            .map(|c| c.id.clone())
            .unwrap_or_default();
        pic.messages.push(Msg {
            text: "The view from the café".into(),
            outgoing: false,
            time: "14:05".into(),
            status: 3,
            seq: 900,
            file: "harbour.jpg".into(),
            image: true,
            ..Default::default()
        });
        view::apply(&ui, &pic);
        let (w, h) = (480u32, 320u32);
        let mut px = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                // Evening sky over water, a low sun, and a pier.
                let (r, g, b) = if y < 190 {
                    let t = y as f32 / 190.0;
                    (
                        (236.0 - 60.0 * t) as u8,
                        (196.0 - 70.0 * t) as u8,
                        (150.0 - 20.0 * t) as u8,
                    )
                } else {
                    let t = (y - 190) as f32 / 130.0;
                    (
                        (70.0 - 30.0 * t) as u8,
                        (98.0 - 30.0 * t) as u8,
                        (110.0 - 20.0 * t) as u8,
                    )
                };
                let (dx, dy) = (x as f32 - 330.0, y as f32 - 170.0);
                let sun = dx * dx + dy * dy < 30.0 * 30.0;
                let pier = y > 205 && y < 214 && x < 260;
                let px_ = if sun {
                    (250, 214, 150)
                } else if pier {
                    (40, 36, 34)
                } else {
                    (r, g, b)
                };
                px.extend_from_slice(&[px_.0, px_.1, px_.2, 255]);
            }
        }
        view::apply_preview(
            &ui,
            view::Preview {
                conversation: id,
                seq: 900,
                width: w,
                height: h,
                pixels: px,
            },
        );
        shot("05-picture", desktop);
        pic.messages.push(Msg {
            outgoing: true,
            time: "14:09".into(),
            status: 1,
            seq: 901,
            file: "interview-brief.pdf".into(),
            ..Default::default()
        });
        view::apply(&ui, &pic);
        ui.set_sheet(Sheet::Gallery);
        shot("42-gallery-phone", phone);
        ui.set_sheet(Sheet::None);
        view::apply(&ui, &data);

        let mut request = data.clone();
        request.current = Some(data.requests[0].clone());
        request.messages = vec![Msg {
            text: "Hi, we met at the workshop on Thursday.".into(),
            outgoing: false,
            time: "13:20".into(),
            status: 3,
            sender: String::new(),
            ..Default::default()
        }];
        view::apply(&ui, &request);
        shot("06-request", desktop);

        let mut pending = data.clone();
        pending.current = Some(data.contacts[2].clone());
        pending.messages = vec![Msg {
            text: "Hi Lucía, it's Robin from the book club.".into(),
            outgoing: true,
            time: "09:12".into(),
            status: 3,
            sender: String::new(),
            ..Default::default()
        }];
        view::apply(&ui, &pending);
        shot("07-pending", phone);

        let mut unverified = data.clone();
        unverified.current = Some(data.contacts[1].clone());
        view::apply(&ui, &unverified);
        ui.set_sheet(Sheet::CheckCode);
        shot("08-check-code", desktop);
        shot("08-check-code-phone", phone);

        view::apply(&ui, &data);
        ui.set_sheet(Sheet::MyCode);
        shot("09-my-code", desktop);
        ui.set_sheet(Sheet::Add);
        ui.set_add_link("enclave:link#AAECAwQF".into());
        let mut err = data.clone();
        err.add_error = "This code links a device to your account. Only scan it from Settings → Your devices, on your own new device. No one from Enclave will ever ask you to scan one.".into();
        view::apply(&ui, &err);
        shot("10-add-error", desktop);
        let mut unverified_name = data.clone();
        unverified_name.add_error = "Enclave couldn't confirm that this username is genuine, so it didn't add anyone. Ask them for their invite link instead.".into();
        view::apply(&ui, &unverified_name);
        ui.set_add_link("@sam@enclave.example".into());
        ui.set_add_text("Hi Sam, it's Robin".into());
        shot("10-add-username-phone", phone);
        ui.set_add_link("".into());
        ui.set_add_text("".into());
        let group = group_fixture(&data);
        view::apply(&ui, &group);
        ui.set_sheet(Sheet::None);
        shot("14-group", desktop);
        shot("14-group-phone", phone);
        let mut poll = group.clone();
        poll.messages.push(Msg {
            text: "Which book next?".into(),
            outgoing: false,
            time: "15:10".into(),
            status: 3,
            sender: "Priya Raman".into(),
            seq: 40,
            poll_options: vec![
                "Piranesi".into(),
                "The Dispossessed".into(),
                "Pachinko".into(),
            ],
            poll_counts: vec![2, 3, 1],
            poll_mine: 2,
            poll_state: 1,
            ..Default::default()
        });
        view::apply(&ui, &poll);
        shot("30-poll", desktop);
        shot("30-poll-phone", phone);
        let mut pinned = group.clone();
        if let Some(m) = pinned.messages.iter_mut().find(|m| !m.outgoing) {
            m.pinned = true;
            pinned.pins = vec![format!(
                "{}: {}",
                m.sender,
                m.text.lines().next().unwrap_or("")
            )];
        }
        view::apply(&ui, &pinned);
        shot("36-pinned", desktop);
        shot("36-pinned-phone", phone);
        // Conversation settings, and a list with pinned, muted and archived.
        let mut listed = data.clone();
        if let Some(r) = listed.contacts.get_mut(1) {
            r.pinned = true;
        }
        if let Some(r) = listed.contacts.get_mut(2) {
            r.muted = true;
            r.unread = 3;
        }
        if let Some(mut r) = listed.contacts.pop() {
            r.archived = true;
            listed.archived.push(r);
        }
        if let Some(i) = listed.contacts.iter().position(|r| r.pinned) {
            let r = listed.contacts.remove(i);
            listed.contacts.insert(0, r);
        }
        view::apply(&ui, &listed);
        ui.set_show_archived(true);
        shot("37-list-prefs", desktop);
        ui.set_show_archived(false);
        ui.set_sheet(Sheet::Conversation);
        shot("38-conversation-sheet-phone", phone);
        ui.set_sheet(Sheet::None);
        let mut blocked = data.clone();
        if let Some(r) = blocked.current.as_mut() {
            r.blocked = true;
        }
        if let Some(r) = blocked
            .contacts
            .iter_mut()
            .find(|r| Some(&r.id) == data.current.as_ref().map(|c| &c.id))
        {
            r.blocked = true;
        }
        view::apply(&ui, &blocked);
        shot("39-blocked-phone", phone);
        view::apply(&ui, &data);
        ui.set_sheet(Sheet::Report);
        shot("43-report-phone", phone);
        ui.set_sheet(Sheet::None);
        let mut notes = data.clone();
        let row = Row {
            id: "notes".into(),
            name: "Note to self".into(),
            preview: "Passport renewal: book before June".into(),
            time: "09:12".into(),
            state: 2,
            kind: 2,
            ..Default::default()
        };
        notes.contacts.insert(0, row.clone());
        notes.current = Some(row);
        notes.messages = [
            "Wi-Fi at the cabin: ask Priya",
            "Passport renewal: book before June",
        ]
        .iter()
        .enumerate()
        .map(|(i, t)| Msg {
            text: (*t).into(),
            outgoing: true,
            time: if i == 0 { "Mon 18:40" } else { "09:12" }.into(),
            status: -1,
            seq: i as u64,
            ..Default::default()
        })
        .collect();
        view::apply(&ui, &notes);
        shot("40-notes-phone", phone);
        let mut shared = data.clone();
        shared.messages.push(Msg {
            outgoing: false,
            time: "14:06".into(),
            status: 3,
            seq: 99,
            contact_name: "Tomasz Nowak".into(),
            ..Default::default()
        });
        view::apply(&ui, &shared);
        shot("41-shared-contact-phone", phone);

        // Stickers: one in the conversation, and the picker.
        let mut st = data.clone();
        st.sticker_packs = vec![enclave_ipc::StickerPackRow {
            id: "p1".into(),
            title: "Paper animals".into(),
            count: 5,
        }];
        st.messages.push(Msg {
            outgoing: false,
            time: "14:07".into(),
            status: 3,
            seq: 98,
            sticker: true,
            pack_added: false,
            ..Default::default()
        });
        let conv = st
            .current
            .as_ref()
            .map(|c| c.id.clone())
            .unwrap_or_default();
        view::apply(&ui, &st);
        for (i, hue) in [(0u64, 0u8), (1, 1), (2, 2), (3, 3), (4, 4)] {
            let px = sticker_pixels(hue);
            view::apply_preview(
                &ui,
                view::Preview {
                    conversation: "stickers/p1".into(),
                    seq: i,
                    width: 96,
                    height: 96,
                    pixels: px.clone(),
                },
            );
            if i == 2 {
                view::apply_preview(
                    &ui,
                    view::Preview {
                        conversation: conv.clone(),
                        seq: 98,
                        width: 96,
                        height: 96,
                        pixels: px,
                    },
                );
            }
        }
        shot("44-sticker-phone", phone);
        ui.set_sheet(Sheet::Stickers);
        shot("45-sticker-picker-phone", phone);
        ui.set_sheet(Sheet::None);

        // Voice notes: a waveform and a length.
        let mut vn = data.clone();
        let wave = |seed: u32| -> Vec<u8> {
            (0..64u32)
                .map(|i| {
                    let x = (i * 37 + seed * 11) % 97;
                    (40 + (x * 2) % 200) as u8
                })
                .collect()
        };
        vn.messages.push(Msg {
            outgoing: false,
            time: "14:08".into(),
            status: 3,
            seq: 97,
            file: "voice-note.evn".into(),
            voice: true,
            voice_ms: 14_000,
            waveform: wave(1),
            ..Default::default()
        });
        vn.messages.push(Msg {
            outgoing: true,
            time: "14:09".into(),
            status: 1,
            seq: 96,
            file: "voice-note.evn".into(),
            voice: true,
            voice_ms: 6_000,
            waveform: wave(5),
            ..Default::default()
        });
        view::apply(&ui, &vn);
        shot("46-voice-notes-phone", phone);
        let mut ty = data.clone();
        ty.typing = true;
        ty.typing_setting = true;
        view::apply(&ui, &ty);
        shot("47-typing-phone", phone);
        ui.set_sheet(Sheet::Settings);
        shot("48-typing-setting-phone", phone);
        ui.set_sheet(Sheet::None);
        // Changing the recovery words, and a contact who did.
        view::apply(&ui, &data);
        ui.set_sheet(Sheet::ChangeWords);
        shot("49-change-words-phone", phone);
        ui.set_sheet(Sheet::None);
        let mut mv = data.clone();
        mv.moved = 1;
        if let Some(c) = mv.current.as_mut() {
            c.verified = false;
            c.met = false;
        }
        view::apply(&ui, &mv);
        shot("50-contact-moved-phone", phone);
        view::apply(&ui, &data);

        // An animated picture: its poster with its length, then the player.
        let (cw, ch) = (240u32, 160u32);
        let frame = |k: u32| -> Vec<u8> {
            let mut px = Vec::with_capacity((cw * ch * 4) as usize);
            for y in 0..ch {
                for x in 0..cw {
                    let cx = 40.0 + k as f32 * 20.0;
                    let (dx, dy) = (x as f32 - cx, y as f32 - 80.0);
                    let ball = dx * dx + dy * dy < 22.0 * 22.0;
                    let c = if ball {
                        (242, 178, 48)
                    } else {
                        (29 + (y / 8) as u8, 86 + (y / 6) as u8, 70 + (y / 8) as u8)
                    };
                    px.extend_from_slice(&[c.0, c.1, c.2, 255]);
                }
            }
            px
        };
        let mut clip = data.clone();
        clip.messages.push(Msg {
            outgoing: false,
            time: "14:10".into(),
            seq: 950,
            file: "party.clip".into(),
            image: true,
            clip_ms: 2400,
            ..Default::default()
        });
        view::apply(&ui, &clip);
        let cid = data
            .current
            .as_ref()
            .map(|c| c.id.clone())
            .unwrap_or_default();
        view::apply_preview(
            &ui,
            view::Preview {
                conversation: cid,
                seq: 950,
                width: cw,
                height: ch,
                pixels: frame(0),
            },
        );
        shot("51-clip-phone", phone);
        view::apply_clip(
            &ui,
            view::ClipFrames {
                width: cw,
                height: ch,
                interval_ms: 66,
                frames: (0..9).map(frame).collect(),
            },
        );
        ui.set_player_index(4);
        ui.set_sheet(Sheet::Player);
        shot("52-player-phone", phone);
        ui.set_sheet(Sheet::None);
        view::apply(&ui, &data);
        ui.set_sheet(Sheet::Poll);
        ui.set_poll_question("Where should we meet?".into());
        ui.set_poll_a("Café on Main St".into());
        shot("31-poll-sheet-phone", phone);
        ui.set_poll_question("".into());
        ui.set_poll_a("".into());
        ui.set_sheet(Sheet::None);
        let mut members = group.clone();
        members.group_admin = true;
        members.members = group.contacts[1..4].to_vec();
        members.addable = vec![Pick {
            id: "m1".into(),
            name: "Mara Lindqvist".into(),
            tint: 3,
            selected: true,
        }];
        view::apply(&ui, &members);
        ui.set_sheet(Sheet::Members);
        shot("24-members-phone", phone);
        let mut waiting = data.clone();
        waiting.joining = vec!["Book club".into()];
        waiting.current = None;
        view::apply(&ui, &waiting);
        ui.set_sheet(Sheet::None);
        ui.set_current_id("".into());
        shot("29-joining-phone", phone);
        ui.set_sheet(Sheet::None);
        view::apply(&ui, &data);
        ui.set_group_name("Book club".into());
        ui.set_sheet(Sheet::NewGroup);
        shot("15-new-group", desktop);
        let mut linking = data.clone();
        linking.link_choices = vec![
            "harbor ivory kettle".into(),
            "glide ember noble".into(),
            "cedar orbit brisk".into(),
            "quartz amount lunar".into(),
        ];
        view::apply(&ui, &linking);
        ui.set_sheet(Sheet::Devices);
        shot("16-devices-link", desktop);
        view::apply(&ui, &data);
        shot("16-devices-phone", phone);
        ui.set_confirm_remove("b2".into());
        shot("17-devices-remove-phone", phone);
        ui.set_confirm_remove("".into());
        view::apply(&ui, &data);
        ui.set_sheet(Sheet::Settings);
        shot("11-privacy", desktop);
        shot("11-privacy-phone", phone);
        let mut alert = data.clone();
        alert.recovery_alert = "3 Oct 14:02".into();
        alert.current = None;
        view::apply(&ui, &alert);
        ui.set_sheet(Sheet::None);
        ui.set_current_id("".into());
        shot("19-recovery-alert-phone", phone);
        let mut split = alert.clone();
        split.recovery_alert = String::new();
        split.kt_split = "enclave.example".into();
        view::apply(&ui, &split);
        shot("28-kt-split-phone", phone);
        let mut clock = split.clone();
        clock.kt_split = String::new();
        clock.clock_skew = "3 hours behind".into();
        view::apply(&ui, &clock);
        shot("29-clock-skew-phone", phone);
        let mut linked = clock.clone();
        linked.clock_skew = String::new();
        linked.new_device = "a new device, 30 Sep 14:02".into();
        view::apply(&ui, &linked);
        shot("53-new-device-phone", phone);

        // Recovery with friends: choosing, holding, restoring.
        let mut friends = data.clone();
        friends.friends = vec![
            Pick {
                id: "a1".into(),
                name: "Sam Okafor".into(),
                tint: 0,
                selected: true,
            },
            Pick {
                id: "a2".into(),
                name: "Priya Raman".into(),
                tint: 1,
                selected: true,
            },
            Pick {
                id: "a3".into(),
                name: "Lucía Fernández".into(),
                tint: 2,
                selected: true,
            },
            Pick {
                id: "a4".into(),
                name: "Tomasz".into(),
                tint: 3,
                selected: false,
            },
        ];
        view::apply(&ui, &friends);
        ui.set_sheet(Sheet::Friends);
        shot("32-friends-phone", phone);
        let mut holder = data.clone();
        holder.holds_share = true;
        view::apply(&ui, &holder);
        ui.set_sheet(Sheet::None);
        shot("33-holds-share", desktop);
        holder.shown_share = "academic acid acrobat romp academic hunting clay dream luck fumes bishop order ancestor lunar beard evoke aluminum cinema legs roster spider laser alarm spirit parcel bulb sidewalk".into();
        view::apply(&ui, &holder);
        ui.set_sheet(Sheet::Share);
        shot("34-show-share-phone", phone);
        ui.set_sheet(Sheet::None);
        view::apply(&ui, &Snapshot::default());
        ui.set_screen(Screen::Restore);
        ui.set_restore_s1(
            "academic acid acrobat romp academic hunting clay dream luck fumes".into(),
        );
        ui.set_restore_file("/home/robin/Downloads/Enclave backup 2026-09-12.enclave".into());
        shot("35-restore-phone", phone);
        ui.set_restore_s1("".into());
        ui.set_restore_file("".into());
        view::apply(&ui, &data);
        let mut meet = data.clone();
        meet.meet_code = "enclave:meet#AQCDAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4A".into();
        view::apply(&ui, &meet);
        ui.set_sheet(Sheet::Meet);
        shot("20-meet-code-phone", phone);
        meet.meet_words = "harbor ivory kettle".into();
        meet.meet_name = "Sam Okafor".into();
        view::apply(&ui, &meet);
        shot("20-meet-words-phone", phone);
        meet.meet_words.clear();
        meet.meet_done = "Sam Okafor".into();
        view::apply(&ui, &meet);
        shot("20-meet-done-phone", phone);
        // A selected message with its actions, and the timer sheet.
        view::apply(&ui, &data);
        ui.set_sheet(Sheet::None);
        if let Some(m) = data.messages.iter().rev().find(|m| m.outgoing) {
            ui.set_selected_seq(m.seq.to_string().into());
        }
        shot("21-message-actions", desktop);
        ui.set_selected_seq("".into());
        let mut timed = data.clone();
        timed.timer = 86_400;
        view::apply(&ui, &timed);
        ui.set_sheet(Sheet::Timer);
        shot("22-timer-phone", phone);
        let mut found = data.clone();
        found.current = None;
        found.search = vec![Row {
            id: "s1".into(),
            name: "Sam Okafor".into(),
            preview: "…Tomorrow works. Same café?".into(),
            time: "14:02".into(),
            state: 2,
            tint: 0,
            ..Default::default()
        }];
        view::apply(&ui, &found);
        ui.set_sheet(Sheet::None);
        ui.set_current_id("".into());
        ui.set_search_query("café".into());
        shot("23-search-phone", phone);
        ui.set_search_query("".into());
        view::apply(&ui, &data);
        view::apply(&ui, &data);
        ui.set_sheet(Sheet::Settings);
        ui.set_sheet(Sheet::Recovery);
        shot("12-recovery", desktop);
        shot("12-recovery-phone", phone);
        ui.set_sheet(Sheet::None);
        ui.set_current_id("".into());
        shot("13-list-phone", phone);
    }
    eprintln!("screenshots written to {}", out.display());
    Ok(())
}
