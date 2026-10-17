//! The notification-area icon: `Shell_NotifyIconW` on a message-only
//! window, which runs its own message loop on its own thread. A click
//! opens the window; a right click shows "Open Enclave" and "Quit".

use super::{Icon, Labels, TrayEvent, fire};
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreateIcon, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyIcon,
    DestroyMenu, DestroyWindow, DispatchMessageW, GetCursorPos, GetMessageW, HICON, HWND_MESSAGE,
    MF_STRING, MSG, PostMessageW, PostQuitMessage, RegisterClassW, SetForegroundWindow,
    TPM_NONOTIFY, TPM_RETURNCMD, TrackPopupMenu, TranslateMessage, WM_APP, WM_CLOSE, WM_DESTROY,
    WM_LBUTTONUP, WM_RBUTTONUP, WNDCLASSW,
};

const CALLBACK: u32 = WM_APP + 1;
const OPEN: usize = 1;
const QUIT: usize = 2;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The menu's labels, set once per process before the window exists.
fn labels() -> &'static OnceLock<(Vec<u16>, Vec<u16>)> {
    static L: OnceLock<(Vec<u16>, Vec<u16>)> = OnceLock::new();
    &L
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if msg == CALLBACK {
        match (lparam & 0xffff) as u32 {
            WM_LBUTTONUP => fire(TrayEvent::Open),
            WM_RBUTTONUP => {
                if let Some((open, quit)) = labels().get() {
                    // SAFETY: a popup menu owned here and destroyed below;
                    // the label buffers live for the process.
                    unsafe {
                        let menu = CreatePopupMenu();
                        if !menu.is_null() {
                            AppendMenuW(menu, MF_STRING, OPEN, open.as_ptr());
                            AppendMenuW(menu, MF_STRING, QUIT, quit.as_ptr());
                            let mut pt = POINT { x: 0, y: 0 };
                            GetCursorPos(&mut pt);
                            // The menu closes when the person clicks away
                            // only if the window is in the foreground.
                            SetForegroundWindow(hwnd);
                            let chosen = TrackPopupMenu(
                                menu,
                                TPM_RETURNCMD | TPM_NONOTIFY,
                                pt.x,
                                pt.y,
                                0,
                                hwnd,
                                std::ptr::null(),
                            );
                            DestroyMenu(menu);
                            match chosen as usize {
                                OPEN => fire(TrayEvent::Open),
                                QUIT => fire(TrayEvent::Quit),
                                _ => {}
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        return 0;
    }
    if msg == WM_DESTROY {
        // SAFETY: ends this thread's message loop.
        unsafe { PostQuitMessage(0) };
        return 0;
    }
    // SAFETY: the default handling of every other message.
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

/// The icon while shown: its window (a handle as an integer, so the type
/// is `Send`), closed on drop.
pub(super) struct Inner {
    hwnd: isize,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // SAFETY: the window belongs to the tray thread; WM_CLOSE makes it
        // remove the icon and destroy the window there.
        unsafe { PostMessageW(self.hwnd as HWND, WM_CLOSE, 0, 0) };
    }
}

/// An `HICON` from RGBA: Windows wants BGRA rows and an AND mask.
fn make_icon(icon: &Icon) -> HICON {
    let bgra: Vec<u8> = icon
        .rgba
        .chunks_exact(4)
        .flat_map(|p| [p[2], p[1], p[0], p[3]])
        .collect();
    let mask = vec![0u8; (icon.width.div_ceil(32) * 4 * icon.height) as usize];
    // SAFETY: both buffers are the sizes CreateIcon reads for a 32-bit
    // `width × height` icon.
    unsafe {
        CreateIcon(
            GetModuleHandleW(std::ptr::null()),
            icon.width as i32,
            icon.height as i32,
            1,
            32,
            mask.as_ptr(),
            bgra.as_ptr(),
        )
    }
}

pub(super) fn show(icon: &Icon, l: &Labels) -> Option<Inner> {
    let _ = labels().set((wide(&l.open), wide(&l.quit)));
    let icon = icon.clone();
    let tooltip = l.tooltip.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("enclave-tray".into())
        .spawn(move || {
            // SAFETY: the window class, the window, the icon and the
            // notification data all live on this thread, which runs the
            // window's message loop until WM_CLOSE destroys it.
            unsafe {
                let class = wide("EnclaveTray");
                let hinst = GetModuleHandleW(std::ptr::null());
                let wc = WNDCLASSW {
                    style: 0,
                    lpfnWndProc: Some(wndproc),
                    cbClsExtra: 0,
                    cbWndExtra: 0,
                    hInstance: hinst,
                    hIcon: std::ptr::null_mut(),
                    hCursor: std::ptr::null_mut(),
                    hbrBackground: std::ptr::null_mut(),
                    lpszMenuName: std::ptr::null(),
                    lpszClassName: class.as_ptr(),
                };
                RegisterClassW(&wc);
                let hwnd = CreateWindowExW(
                    0,
                    class.as_ptr(),
                    class.as_ptr(),
                    0,
                    0,
                    0,
                    0,
                    0,
                    HWND_MESSAGE,
                    std::ptr::null_mut(),
                    hinst,
                    std::ptr::null(),
                );
                if hwnd.is_null() {
                    let _ = tx.send(None);
                    return;
                }
                let hicon = make_icon(&icon);
                let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
                nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
                nid.hWnd = hwnd;
                nid.uID = 1;
                nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
                nid.uCallbackMessage = CALLBACK;
                nid.hIcon = hicon;
                for (d, s) in nid.szTip.iter_mut().zip(tooltip.encode_utf16().take(127)) {
                    *d = s;
                }
                if Shell_NotifyIconW(NIM_ADD, &nid) == 0 {
                    DestroyWindow(hwnd);
                    let _ = tx.send(None);
                    return;
                }
                let _ = tx.send(Some(hwnd as isize));
                let mut msg: MSG = std::mem::zeroed();
                while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                    if msg.message == WM_CLOSE && msg.hwnd == hwnd {
                        Shell_NotifyIconW(NIM_DELETE, &nid);
                        DestroyWindow(hwnd);
                        continue;
                    }
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                Shell_NotifyIconW(NIM_DELETE, &nid);
                DestroyIcon(hicon);
            }
        })
        .ok()?;
    rx.recv().ok().flatten().map(|hwnd| Inner { hwnd })
}
