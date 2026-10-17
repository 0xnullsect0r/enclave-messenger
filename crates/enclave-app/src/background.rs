//! Running on with the window closed (PC-48, `docs/09-transport.md` §6.3).
//!
//! Where the desktop has a status area, closing the window hides it: the
//! vault switches to the Background profile (one Poisson tick every two
//! minutes on average) and messages and notifications keep arriving. The
//! status icon opens the window again or quits; starting Enclave again
//! also opens the window (the second copy hands [`SHOW`] to the first).
//! Without a status area, closing the window quits, as before.

use crate::ui::AppWindow;
use enclave_ipc::Cmd;
use enclave_platform::tray::{Icon, Labels, Tray, TrayEvent};
use slint::ComponentHandle;
use std::cell::RefCell;
use std::rc::Rc;
use tokio::sync::mpsc::UnboundedSender;

/// What a second copy of the app hands the first to bring its window back.
pub const SHOW: &str = "enclave:show";

/// The app icon at 32 px, for the status area.
const ICON_PNG: &[u8] = include_bytes!("../../../packaging/icons/png/enclave-32.png");

fn icon() -> Option<Icon> {
    let decoder = png::Decoder::new(std::io::Cursor::new(ICON_PNG));
    let mut reader = decoder.read_info().ok()?;
    let mut buf = vec![0; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).ok()?;
    let rgba = match info.color_type {
        png::ColorType::Rgba => buf[..info.buffer_size()].to_vec(),
        png::ColorType::Rgb => buf[..info.buffer_size()]
            .chunks_exact(3)
            .flat_map(|p| [p[0], p[1], p[2], 255])
            .collect(),
        _ => return None,
    };
    Some(Icon {
        width: info.width,
        height: info.height,
        rgba,
    })
}

/// Bring the window back and tell the vault it is seen again.
pub fn show(ui: &AppWindow, tx: &UnboundedSender<Cmd>) {
    let _ = ui.show();
    let _ = tx.send(Cmd::Visible(true));
}

/// Set up closing to the status area. Keep what it returns for as long as
/// the app runs (dropping it removes the icon).
pub fn start(ui: &AppWindow, tx: UnboundedSender<Cmd>) -> Rc<RefCell<Option<Tray>>> {
    let tray: Rc<RefCell<Option<Tray>>> = Rc::default();
    let w = ui.as_weak();
    let t = tx.clone();
    let labels = Labels {
        tooltip: "Enclave".to_string(),
        open: crate::i18n::tr("Open Enclave"),
        quit: crate::i18n::tr("Quit Enclave"),
    };
    let shown = icon().and_then(|i| {
        enclave_platform::tray::show(&i, &labels, move |e| {
            let (w, t) = (w.clone(), t.clone());
            let _ = slint::invoke_from_event_loop(move || match e {
                TrayEvent::Open => {
                    if let Some(ui) = w.upgrade() {
                        show(&ui, &t);
                    }
                }
                TrayEvent::Quit => {
                    let _ = slint::quit_event_loop();
                }
            });
        })
    });
    *tray.borrow_mut() = shown;
    let has_tray = Rc::clone(&tray);
    ui.window().on_close_requested(move || {
        if has_tray.borrow().is_some() {
            // Hidden, still running: the Background profile from now.
            let _ = tx.send(Cmd::Visible(false));
        } else {
            let _ = slint::quit_event_loop();
        }
        slint::CloseRequestResponse::HideWindow
    });
    tray
}
