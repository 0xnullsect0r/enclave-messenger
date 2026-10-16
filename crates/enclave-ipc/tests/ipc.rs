//! Round trips, hostile input, framing and the token check.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_ipc::frame::{self, TOKEN_LEN};
use enclave_ipc::{Cmd, Device, Effect, FileHash, Msg, Out, Pick, Row, Snapshot};

fn snapshot() -> Snapshot {
    let row = Row {
        id: "ab".into(),
        name: "Sam Okafor".into(),
        preview: "See you — tomorrow ☕".into(),
        time: "14:02".into(),
        unread: 2,
        state: 2,
        verified: true,
        met: true,
        tint: 5,
        kind: 0,
        members: 0,
        pinned: true,
        muted: true,
        archived: false,
        blocked: true,
        admin: true,
        art: 0x0123_4567,
        about: "Out walking".into(),
        has_photo: true,
    };
    Snapshot {
        my_name: "Robin".into(),
        my_about: "Hi".into(),
        my_photo: true,
        link_previews: true,
        gif_search: true,
        stories: vec![enclave_ipc::StoryRow {
            key: "ab/cd".into(),
            who: "c01".into(),
            name: "Sam".into(),
            text: "At the lake".into(),
            ago: "3 h".into(),
            picture: true,
            viewed: false,
            reached: 4,
            waiting: 2,
        }],
        story_audience: vec![enclave_ipc::Pick {
            id: "c01".into(),
            name: "Sam".into(),
            tint: 2,
            selected: true,
        }],
        my_link: "enclave:add#xyz".into(),
        contacts: vec![row.clone(), Row::default()],
        requests: vec![row.clone()],
        archived: vec![Row {
            archived: true,
            ..Row::default()
        }],
        current: Some(row),
        messages: vec![Msg {
            text: "hello".into(),
            outgoing: true,
            time: "14:03".into(),
            status: 1,
            sender: String::new(),
            seq: u64::MAX - 3,
            can_edit: true,
            deleted: false,
            file: "photo.jpg".into(),
            image: true,
            poll_options: vec!["Friday".into(), "Saturday".into()],
            poll_counts: vec![1, 3],
            poll_mine: 2,
            poll_state: 1,
            poll_ours: true,
            pinned: true,
            contact_name: "Jo".into(),
            contact_known: false,
            location: "52.520008, 13.404954".into(),
            location_label: "Meet here".into(),
            sticker: true,
            pack_added: false,
            voice: true,
            voice_ms: 4200,
            waveform: vec![10; 64],
            clip_ms: 2400,
            transcript: "see you at noon".into(),
            quoted: true,
            quote_seq: 2,
            quote_who: "You".into(),
            quote_text: "lunch?".into(),
            forwarded: true,
            mentions_me: true,
            poll_anonymous: true,
            poll_voters: 3,
            my_reaction: "👍".into(),
            view_once: true,
            view_once_ready: true,
            link_title: "A page".into(),
            link_description: "About it".into(),
            link_site: "example.org".into(),
            link_image: true,
        }],
        code_groups: vec!["12345".into(); 12],
        code_words: vec!["abandon".into(), "zoo".into()],
        code_words_english: true,
        status: "ok".into(),
        recovery_words: vec!["abandon".into(); 24],
        recovery_saved: true,
        words_language: "fr".into(),
        privacy: 1,
        finishing: true,
        gap: true,
        on_record: true,
        closed: false,
        add_error: String::new(),
        busy: true,
        pick: vec![Pick {
            id: "cd".into(),
            name: "Priya".into(),
            tint: 1,
            selected: true,
        }],
        devices: vec![Device {
            id: "00ff".into(),
            label: "This device".into(),
            detail: "Added 2 Sep 2026".into(),
            removable: false,
            history_action: "Send history now".into(),
        }],
        link_choices: vec!["a b c".into(); 4],
        link_status: "s".into(),
        can_link: true,
        my_username: "@robin@enclave.example".into(),
        usernames: true,
        username_error: "e".into(),
        can_join: true,
        join_code: "enclave:link#q".into(),
        join_words: "x y z".into(),
        recovery_alert: "3 Oct 14:02".into(),
        recovery_hold: "9 Oct 08:00".into(),
        recovery_stopped: true,
        meet_code: "enclave:meet#abc".into(),
        meet_words: "harbor ivory kettle".into(),
        meet_name: "Sam".into(),
        meet_error: String::new(),
        meet_done: String::new(),
        timer: 3600,
        search: vec![Row::default()],
        username_problem: "@robin@enclave.example".into(),
        kt_split: "enclave.example".into(),
        clock_skew: "3 hours behind".into(),
        update_release: "v1.2.3".into(),
        update_required: 1,
        build_check: "matches".into(),
        call: enclave_ipc::CallView {
            state: 4,
            conversation: "c1".into(),
            name: "Ben".into(),
            video: false,
            muted: true,
            camera: true,
            video_width: 320,
            video_height: 240,
            connected_at: 1_790_000_000,
            words: "apple river".into(),
            error: String::new(),
            direct_asked: true,
            direct: true,
            group: true,
            hand: true,
            cameras_full: true,
            screen: true,
            peers: vec![enclave_ipc::CallPeer {
                id: 7,
                name: "Priya".into(),
                hand: true,
                reaction: "👏".into(),
            }],
            live_groups: vec!["g01".into()],
            link: "enclave:call#AQ".into(),
            knocks: vec![enclave_ipc::CallPeer {
                id: 3,
                name: "Ana".into(),
                ..Default::default()
            }],
        },
        typing_who: "Ana".into(),
        announcement_only: true,
        folders: vec!["Work".into(), "Family".into()],
        folder: "Work".into(),
        current_folders: vec!["Work".into()],
        sandbox_weak: true,
        transcription: 1,
        transcription_percent: 42,
        transcription_error: "no route".into(),
        new_device: "a new device, 30 Sep 14:02".into(),
        joining: vec!["Book club".into()],
        restore_error: "wrong words".into(),
        friends: vec![enclave_ipc::Pick {
            id: "f1".into(),
            name: "Ben".into(),
            tint: 2,
            selected: true,
        }],
        share_holders: vec!["Ben".into(), "Cy".into()],
        share_threshold: 2,
        holds_share: true,
        share_release: "enclave:share#AQ".into(),
        share_release_words: "abandon ability able".into(),
        share_request: "enclave:release#AQ".into(),
        share_request_words: "abandon ability able".into(),
        pins: vec!["Meet at the station".into()],
        pin_seqs: vec!["4".into()],
        sticker_packs: vec![enclave_ipc::StickerPackRow {
            id: "p1".into(),
            title: "Cats".into(),
            count: 3,
        }],
        members: vec![Row::default(); 2],
        group_admin: true,
        addable: vec![Pick::default()],
        locked: true,
        unlock_error: "no".into(),
        can_lock: true,
        invites: 2,
        typing_setting: true,
        receipts_setting: true,
        typing: true,
        can_change_words: true,
        words_pending: true,
        removed: true,
        has_root_pin: true,
        securing: true,
        previews: true,
        pin_error: "That PIN isn't right.".into(),
        moved: 2,
        held_moves: vec!["Cy".into()],
        route: 1,
        tor_blocked: true,
        bridges: "builtin".into(),
        bridges_error: String::new(),
        bridges_restart: true,
        pin_lock: true,
        app_lock: true,
        lock_timeout: 300,
        server_backup: true,
        server_backup_at: "9 Oct".into(),
        backup_check: "ok".into(),
        servers: vec![enclave_ipc::ServerRow {
            id: "aa".into(),
            domain: "b.example".into(),
            operator: "B".into(),
            family: "b".into(),
        }],
        home: "aa".into(),
        moving: true,
        can_move: true,
        group_host: "bb".into(),
        group_next: "aa".into(),
        group_votes: vec!["aa:1".into()],
        group_admins: 3,
        group_vote: "aa".into(),
        file_keys: true,
        screen_security: true,
        biometric: "Touch ID".into(),
        biometric_on: true,
    }
}

fn cmds() -> Vec<Cmd> {
    vec![
        Cmd::Create("Robin".into(), "correct horse".into()),
        Cmd::Unlock("correct horse".into()),
        Cmd::Lock,
        Cmd::SetPassphrase(String::new()),
        Cmd::NewInvite(1),
        Cmd::CancelInvites,
        Cmd::NewGroupInvite("g01".into(), 5, false),
        Cmd::CreatePoll(
            "g01".into(),
            "When?".into(),
            vec!["Fri".into(), "Sat".into()],
            true,
        ),
        Cmd::Vote("g01".into(), 7, 1),
        Cmd::ClosePoll("g01".into(), 7),
        Cmd::SaveBackup(false),
        Cmd::Restore(vec!["a b c".into()], vec![1, 2, 3]),
        Cmd::GiveShares(vec!["ab".into(), "cd".into()], 2),
        Cmd::RevealShare(String::new()),
        Cmd::Pin("id".into(), 3, true),
        Cmd::ConvPrefs("id".into(), true, false, true),
        Cmd::Block("id".into(), true),
        Cmd::ShareContact("a".into(), "b".into()),
        Cmd::AddShared("a".into(), 4),
        Cmd::ShareLocation("a".into(), "52.5".into(), "13.4".into(), "Here".into()),
        Cmd::Report("a".into(), 1, true, false, true),
        Cmd::CreatePack("Cats".into(), vec![vec![1, 2], vec![3]]),
        Cmd::SendSticker("a".into(), "p".into(), 2),
        Cmd::AddPack("a".into(), 5),
        Cmd::LoadStickers,
        Cmd::TypingSetting(true),
        Cmd::Typing("c1".into(), false),
        Cmd::ChangeWords,
        Cmd::BackupRoute(true),
        Cmd::BackupRoute(false),
        Cmd::SetBridges("obfs4 192.0.2.1:443 AA cert=x iat-mode=0".into()),
        Cmd::SetOnRecord(true),
        Cmd::WordsLanguage("ja".into()),
        Cmd::CodeWordsEnglish(true),
        Cmd::ReleaseShare("enclave:release#AQ".into()),
        Cmd::AskShares,
        Cmd::DeleteAccount,
        Cmd::EraseDevice,
        Cmd::SetRootPin("482913".into()),
        Cmd::UnlockRoot("482913".into()),
        Cmd::SecureAccount,
        Cmd::SetPreviews(true),
        Cmd::SetAppLock("2468".into()),
        Cmd::SetLockTimeout(60),
        Cmd::ServerBackup(true),
        Cmd::CheckBackup("words".into(), vec![1, 2]),
        Cmd::RestoreFromServer(vec!["words".into()]),
        Cmd::PickServer("aa".into()),
        Cmd::MoveHome("aa".into()),
        Cmd::VoteGroupHost("aa".into()),
        Cmd::SetScreenSecurity(false),
        Cmd::UnlockBiometric(0x1234),
        Cmd::SetBiometric(true),
        Cmd::LanServing("aa".into(), vec!["10.0.0.2:4000".into()]),
        Cmd::LanChunks("aa".into(), vec![vec![1, 2], vec![3]], true),
        Cmd::LanFailed("aa".into()),
        Cmd::Visible(false),
        Cmd::PushToken(1, "https://push.example/x".into()),
        Cmd::Wake,
        Cmd::Reattach,
        Cmd::VerifyBuild(vec![FileHash {
            name: "enclave@x86_64-unknown-linux-gnu".into(),
            length: 7,
            sha256: vec![1; 32],
            sha3_512: vec![2; 64],
        }]),
        Cmd::CheckUpdates,
        Cmd::StartCall("c1".into(), true, true),
        Cmd::AnswerCall,
        Cmd::AnswerCallDirect,
        Cmd::DeclineCall,
        Cmd::EndCall,
        Cmd::CallMute(true),
        Cmd::CallMic(vec![-3; 960]),
        Cmd::CallCamera(false),
        Cmd::CallFrame(2, 2, vec![9; 16]),
        Cmd::StartGroupCall("g01".into(), true),
        Cmd::JoinGroupCall("g01".into()),
        Cmd::CallHand(true),
        Cmd::CallReact("👏".into()),
        Cmd::CreateCallLink(true),
        Cmd::AdmitToCall(3),
        Cmd::RefuseFromCall(4),
        Cmd::CallScreen(true),
        Cmd::PlayVoice("ab".into(), 3),
        Cmd::TranscriptionModel(true),
        Cmd::ReceiptsSetting(false),
        Cmd::SetAnnouncementOnly(true),
        Cmd::NewFolder("Work".into()),
        Cmd::DeleteFolder("Work".into()),
        Cmd::InFolder("Work".into(), true),
        Cmd::ShowFolder(String::new()),
        Cmd::OpenLink("enclave:add#AAAA".into()),
        Cmd::SendReply("ab".into(), "yes".into(), 3),
        Cmd::Forward("ab".into(), 3, "g01".into()),
        Cmd::Stage(vec![1; 1000]),
        Cmd::SendStaged("ab".into(), "big.bin".into(), String::new()),
        Cmd::OpenFile("ab".into(), 4),
        Cmd::SendViewOnce("ab".into(), "now.jpg".into(), "".into()),
        Cmd::OpenViewOnce("ab".into(), 5),
        Cmd::AllFiles,
        Cmd::RemovePack("0011".into()),
        Cmd::SetName("Robin".into()),
        Cmd::SetAbout("Out walking".into()),
        Cmd::SetPhoto(vec![1; 300]),
        Cmd::PreviewPack("ab".into(), 6),
        Cmd::LinkPreviewsSetting(true),
        Cmd::GifSearchSetting(false),
        Cmd::GifSearch("cats".into()),
        Cmd::SendGif("g01".into(), 3),
        Cmd::PostStory("At the lake".into(), "lake.jpg".into(), vec![1, 2, 3]),
        Cmd::DeleteStory("ab/cd".into()),
        Cmd::OpenStory("ab/cd".into()),
        Cmd::StoryHidden("c01".into(), true),
        Cmd::Transcribe("ab".into(), 3),
        Cmd::SaveBackup(true),
        Cmd::SetEmergencyPin("1357".into()),
        Cmd::SetGroupAdmin("g".into(), "m".into(), true),
        Cmd::SetOnRecord(false),
        Cmd::Select(String::new()),
        Cmd::Send("id".into(), "text ✓".into()),
        Cmd::Accept("a".into()),
        Cmd::Decline("b".into()),
        Cmd::Add("enclave:add#x".into(), "hi".into()),
        Cmd::Check("c".into()),
        Cmd::Privacy(1),
        Cmd::WordsSaved,
        Cmd::TogglePick("d".into()),
        Cmd::CreateGroup("Book club".into()),
        Cmd::LinkScan("enclave:link#y".into()),
        Cmd::LinkPick(3),
        Cmd::ClaimUsername("robin".into()),
        Cmd::RemoveDevice("00ff".into()),
        Cmd::StartJoin,
        Cmd::CancelJoin,
        Cmd::RevealWords(true),
        Cmd::SendHistory("00ff".into()),
        Cmd::StopRecovery,
        Cmd::ApproveRecovery,
        Cmd::Meet(true),
        Cmd::MeetScan("enclave:meet#x".into()),
        Cmd::MeetConfirm,
        Cmd::React("ab".into(), 3, "👍".into()),
        Cmd::Edit("ab".into(), 4, "fixed".into()),
        Cmd::Delete("ab".into(), 5),
        Cmd::Timer("ab".into(), 86_400),
        Cmd::SendFile("ab".into(), "a.txt".into(), vec![7; 1000], "look".into()),
        Cmd::SaveFile("ab".into(), 6),
        Cmd::Search("café".into()),
        Cmd::AddMembers("g1".into()),
        Cmd::RemoveMember("g1".into(), "ab".into()),
        Cmd::LeaveGroup("g1".into()),
    ]
}

#[test]
fn round_trips() {
    let s = snapshot();
    assert_eq!(Snapshot::decode(&s.encode()).unwrap(), s);
    assert_eq!(
        Snapshot::decode(&Snapshot::default().encode()).unwrap(),
        Snapshot::default()
    );
    for c in cmds() {
        assert_eq!(Cmd::decode(&c.encode()).unwrap(), c);
    }
    for o in [
        Out::Snapshot(Box::new(s)),
        Out::Effect(Effect::ContactAdded),
        Out::Effect(Effect::GroupCreated),
        Out::Effect(Effect::UsernameClaimed),
        Out::Effect(Effect::RemovalDone),
        Out::Effect(Effect::FileSent),
        Out::Effect(Effect::LeftGroup),
        Out::Effect(Effect::PassphraseChanged),
        Out::File("a.txt".into(), vec![1, 2, 3]),
        Out::Invite("enclave:add#AAAA".into()),
        Out::LanChunks("aa".into(), vec![vec![1; 10], vec![2; 3]], false),
        Out::LanStop("aa".into()),
        Out::LanFetch("aa".into(), vec!["10.0.0.2:4000".into()], 7),
        Out::UpdateBundle(b"ENCLUPD1".to_vec()),
        Out::CallAudio(vec![7; 960]),
        Out::CallVideo(2, 1, vec![3; 8]),
        Out::CallTile(9, 1, 2, vec![4; 8]),
        Out::VoiceAudio("ab:3".into(), true, vec![5; 960]),
        Out::OpenLink("enclave:join#AAAA".into()),
        Out::FilePart("big.bin".into(), vec![7; 4096], true),
        Out::OpenNext,
        Out::PackPreview("Cats".into(), 12),
        Out::Gifs(vec!["A cat".into(), "Two cats".into()]),
        Out::Gallery(vec![enclave_ipc::GalleryRow {
            conversation: "g01".into(),
            name: "Trip".into(),
            seq: 4,
            file: "beach.jpg".into(),
            picture: true,
            outgoing: false,
            time: "14:02".into(),
        }]),
        Out::Notify(enclave_ipc::Notice {
            conversation: "ab".into(),
            title: "Priya".into(),
            body: "Chapter 4?".into(),
        }),
        Out::Preview(enclave_ipc::Preview {
            conversation: "ab".into(),
            seq: 3,
            width: 2,
            height: 1,
            pixels: vec![1; 8],
        }),
        Out::Clip(enclave_ipc::ClipFrames {
            width: 2,
            height: 1,
            interval_ms: 66,
            frames: vec![vec![1; 8], vec![2; 8]],
        }),
    ] {
        assert_eq!(Out::decode(&o.encode()).unwrap(), o);
    }
}

#[test]
fn hostile_input_is_refused_not_panicked_on() {
    let good = Out::Snapshot(Box::new(snapshot())).encode();
    // Every truncation and every trailing byte fails.
    for n in 0..good.len() {
        assert!(Out::decode(&good[..n]).is_err(), "prefix {n}");
    }
    assert!(Out::decode(&[good.clone(), vec![0]].concat()).is_err());
    // Byte flips never panic.
    let mut x = 0x9E37_79B9u32;
    for _ in 0..20_000 {
        let mut b = good.clone();
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        let i = x as usize % b.len();
        b[i] ^= (x >> 8) as u8 | 1;
        let _ = Out::decode(&b);
    }
    // A huge claimed count is refused before allocating.
    let mut w = vec![1u8];
    w.extend_from_slice(&0u32.to_be_bytes());
    w.extend_from_slice(&0u32.to_be_bytes());
    w.extend_from_slice(&u32::MAX.to_be_bytes());
    assert!(Out::decode(&w).is_err());
    for c in cmds() {
        let e = c.encode();
        for n in 0..e.len() {
            assert!(Cmd::decode(&e[..n]).is_err());
        }
    }
    assert!(Cmd::decode(&[250]).is_err());
}

#[tokio::test]
async fn framing_and_token() {
    let token = [7u8; TOKEN_LEN];
    assert_eq!(
        frame::token_from_hex(&frame::token_hex(&token)),
        Some(token)
    );
    assert_eq!(frame::token_from_hex("zz"), None);

    let (mut a, mut b) = tokio::io::duplex(1 << 20);
    frame::present_token(&mut a, &token).await.unwrap();
    frame::check_token(&mut b, &token).await.unwrap();
    frame::present_token(&mut a, &[8; TOKEN_LEN]).await.unwrap();
    assert!(frame::check_token(&mut b, &token).await.is_err());

    let body = Cmd::Send("x".into(), "y".repeat(10_000)).encode();
    frame::write_frame(&mut a, &body).await.unwrap();
    assert_eq!(frame::read_frame(&mut b).await.unwrap(), body);
    // An oversize length prefix is refused without reading the body.
    use tokio::io::AsyncWriteExt;
    a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
    assert!(frame::read_frame(&mut b).await.is_err());
}

#[test]
fn net_messages_round_trip_and_refuse_garbage() {
    use enclave_ipc::net::{NetReply, NetRequest};
    for r in [
        NetRequest::Exchange {
            id: 7,
            server: [3; 16],
            bytes: vec![9; 16_384],
        },
        NetRequest::ServerKey {
            id: u32::MAX,
            server: [4; 16],
        },
        NetRequest::SetRoute {
            server: [5; 16],
            route: "nym:abc.def@ghi".into(),
        },
        NetRequest::Oneway {
            id: 9,
            server: [6; 16],
            bytes: vec![1; 16_384],
        },
        NetRequest::RequirePrivate { on: true },
        NetRequest::Fetch {
            id: 10,
            method: "POST".into(),
            url: "https://gate.example/credgate/v1/tokens".into(),
            body: vec![2; 500],
        },
        NetRequest::BuyTickets {
            id: 11,
            gate: "https://gate.example".into(),
            token: vec![3; 146],
        },
        NetRequest::Connect {
            id: 12,
            tickets: vec![vec![4; 3000], vec![5; 10]],
        },
        NetRequest::Connect {
            id: 13,
            tickets: vec![],
        },
        NetRequest::TicketsSpent { id: 14 },
        NetRequest::UseFallback { on: true },
        NetRequest::UseFallback { on: false },
        NetRequest::TorStatus { id: 15 },
        NetRequest::UdpOpen {
            id: 16,
            remote: "203.0.113.7:51820".into(),
        },
        NetRequest::UdpSend {
            socket: 3,
            bytes: vec![9; 160],
        },
        NetRequest::UdpClose { socket: 3 },
        NetRequest::SetPacing {
            pacing: vec![0, 0, 11, 184, 1, 0, 0, 58, 152, 0, 0, 117, 48],
        },
    ] {
        let e = r.encode();
        assert_eq!(NetRequest::decode(&e).unwrap(), r);
        for n in 0..e.len().min(64) {
            assert!(NetRequest::decode(&e[..n]).is_err());
        }
    }
    for r in [
        NetReply {
            id: 1,
            result: Ok(vec![1; 100]),
        },
        NetReply {
            id: 2,
            result: Err("unreachable".into()),
        },
    ] {
        assert_eq!(NetReply::decode(&r.encode()).unwrap(), r);
    }
    assert!(NetReply::decode(&[0, 0, 0, 1, 9]).is_err());
}

#[test]
fn media_messages_round_trip_and_check_sizes() {
    use enclave_ipc::media::{MediaOp, MediaOut, MediaReply, MediaRequest};
    for r in [
        MediaRequest {
            id: 1,
            op: MediaOp::Sanitize,
            bytes: vec![0xff, 0xd8, 0xff],
        },
        MediaRequest {
            id: 2,
            op: MediaOp::Thumbnail(560),
            bytes: vec![7; 1000],
        },
        MediaRequest {
            id: 9,
            op: MediaOp::Shrink(512),
            bytes: vec![1, 2],
        },
        MediaRequest {
            id: 10,
            op: MediaOp::Clip,
            bytes: b"GIF89a".to_vec(),
        },
        MediaRequest {
            id: 11,
            op: MediaOp::ClipPoster(560),
            bytes: vec![0; 10],
        },
        MediaRequest {
            id: 12,
            op: MediaOp::ClipFrames(360),
            bytes: vec![0; 10],
        },
        MediaRequest {
            id: 13,
            op: MediaOp::CallOpen(4),
            bytes: Vec::new(),
        },
        MediaRequest {
            id: 14,
            op: MediaOp::CallEncode(4),
            bytes: vec![0; 1920],
        },
        MediaRequest {
            id: 15,
            op: MediaOp::CallDecode(4, enclave_ipc::media::CallDecode::Recover),
            bytes: vec![1; 80],
        },
        MediaRequest {
            id: 16,
            op: MediaOp::CallDecode(4, enclave_ipc::media::CallDecode::Lost),
            bytes: Vec::new(),
        },
        MediaRequest {
            id: 17,
            op: MediaOp::CallClose(4),
            bytes: Vec::new(),
        },
        MediaRequest {
            id: 18,
            op: MediaOp::CallMix(4),
            bytes: vec![1, 0, 0, 0, 7, 0, 0, 2, 9, 9],
        },
        MediaRequest {
            id: 19,
            op: MediaOp::VideoDecodeFrom(4, 7),
            bytes: vec![3; 40],
        },
        MediaRequest {
            id: 20,
            op: MediaOp::VideoScreen(4, 0, true),
            bytes: Vec::new(),
        },
        MediaRequest {
            id: 21,
            op: MediaOp::VoicePiece(500),
            bytes: vec![1; 10],
        },
        MediaRequest {
            id: 22,
            op: MediaOp::VoiceOgg,
            bytes: vec![1; 10],
        },
        MediaRequest {
            id: 23,
            op: MediaOp::PageMeta,
            bytes: vec![0, 1, b'x', b'<'],
        },
        MediaRequest {
            id: 24,
            op: MediaOp::GifHits,
            bytes: b"{}".to_vec(),
        },
        MediaRequest {
            id: 25,
            op: MediaOp::GifPoster(120),
            bytes: b"GIF89a".to_vec(),
        },
    ] {
        assert_eq!(MediaRequest::decode(&r.encode()).unwrap(), r);
    }
    for r in [
        MediaReply {
            id: 1,
            result: Ok(MediaOut::Sanitized {
                png: true,
                width: 3,
                height: 4,
                bytes: vec![1, 2, 3],
            }),
        },
        MediaReply {
            id: 2,
            result: Ok(MediaOut::Rgba {
                width: 2,
                height: 2,
                pixels: vec![9; 16],
            }),
        },
        MediaReply {
            id: 3,
            result: Err("damaged".into()),
        },
        MediaReply {
            id: 5,
            result: Ok(MediaOut::Clip {
                width: 2,
                height: 2,
                duration_ms: 600,
                bytes: vec![3; 9],
                frames: vec![vec![1; 16], vec![2; 16]],
            }),
        },
        MediaReply {
            id: 6,
            result: Ok(MediaOut::Raw(vec![4; 80])),
        },
    ] {
        assert_eq!(MediaReply::decode(&r.encode()).unwrap(), r);
    }
    // Pixels that don't match the stated size are refused.
    let lying = MediaReply {
        id: 4,
        result: Ok(MediaOut::Rgba {
            width: 100,
            height: 100,
            pixels: vec![0; 16],
        }),
    };
    assert!(MediaReply::decode(&lying.encode()).is_err());
    let lying_clip = MediaReply {
        id: 6,
        result: Ok(MediaOut::Clip {
            width: 4,
            height: 4,
            duration_ms: 1,
            bytes: Vec::new(),
            frames: vec![vec![0; 64], vec![0; 63]],
        }),
    };
    assert!(
        MediaReply::decode(&lying_clip.encode()).is_err(),
        "every frame checked"
    );
    let bad_clip = Out::Clip(enclave_ipc::ClipFrames {
        width: 2,
        height: 2,
        interval_ms: 1,
        frames: vec![vec![0; 15]],
    });
    assert!(Out::decode(&bad_clip.encode()).is_err());
    let bad_preview = Out::Preview(enclave_ipc::Preview {
        conversation: "ab".into(),
        seq: 1,
        width: 50,
        height: 50,
        pixels: vec![0; 4],
    });
    assert!(Out::decode(&bad_preview.encode()).is_err());
    // Sizes whose product overflows are refused, not a panic.
    let huge = Out::Preview(enclave_ipc::Preview {
        conversation: "ab".into(),
        seq: 1,
        width: u32::MAX,
        height: u32::MAX,
        pixels: vec![0; 4],
    });
    assert!(Out::decode(&huge.encode()).is_err());
    let huge = MediaReply {
        id: 5,
        result: Ok(MediaOut::Rgba {
            width: u32::MAX,
            height: u32::MAX,
            pixels: vec![0; 4],
        }),
    };
    assert!(MediaReply::decode(&huge.encode()).is_err());
}
