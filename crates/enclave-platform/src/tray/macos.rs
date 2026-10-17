//! The menu-bar item: an `NSStatusItem` whose menu has "Open Enclave" and
//! "Quit", each sent to a small target object. AppKit is main-thread only,
//! so [`show`] must run on the main thread (Slint's).

use super::{Icon, Labels, TrayEvent, fire};
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject};
use objc2::{MainThreadMarker, MainThreadOnly, define_class, msg_send, sel};
use objc2_app_kit::{NSMenu, NSMenuItem, NSStatusBar, NSStatusItem, NSVariableStatusItemLength};
use objc2_foundation::NSString;

define_class!(
    // SAFETY: NSObject has no subclassing requirements, and the target
    // implements no Drop.
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "EnclaveTrayTarget"]
    struct Target;

    impl Target {
        #[unsafe(method(openEnclave:))]
        fn open_enclave(&self, _sender: Option<&AnyObject>) {
            fire(TrayEvent::Open);
        }

        #[unsafe(method(quitEnclave:))]
        fn quit_enclave(&self, _sender: Option<&AnyObject>) {
            fire(TrayEvent::Quit);
        }
    }
);

impl Target {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(());
        // SAFETY: NSObject's designated initializer.
        unsafe { msg_send![super(this), init] }
    }
}

/// The item while shown (removed from the menu bar on drop).
pub(super) struct Inner {
    item: Retained<NSStatusItem>,
    _menu: Retained<NSMenu>,
    _target: Retained<Target>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        NSStatusBar::systemStatusBar().removeStatusItem(&self.item);
    }
}

fn menu_item(
    mtm: MainThreadMarker,
    title: &str,
    action: objc2::runtime::Sel,
    target: &Target,
) -> Retained<NSMenuItem> {
    // SAFETY: the selector is one `Target` implements, with the action
    // signature (one object argument).
    let item = unsafe {
        NSMenuItem::initWithTitle_action_keyEquivalent(
            NSMenuItem::alloc(mtm),
            &NSString::from_str(title),
            Some(action),
            &NSString::new(),
        )
    };
    // SAFETY: the target outlives the item (both are kept in `Inner`).
    unsafe { item.setTarget(Some(target)) };
    item
}

pub(super) fn show(_icon: &Icon, labels: &Labels) -> Option<Inner> {
    let mtm = MainThreadMarker::new()?;
    let target = Target::new(mtm);
    let menu = NSMenu::new(mtm);
    menu.addItem(&menu_item(mtm, &labels.open, sel!(openEnclave:), &target));
    menu.addItem(&menu_item(mtm, &labels.quit, sel!(quitEnclave:), &target));
    let item = NSStatusBar::systemStatusBar().statusItemWithLength(NSVariableStatusItemLength);
    if let Some(button) = item.button(mtm) {
        // A template symbol, so it follows the menu bar's light or dark
        // look like the system's own items.
        let label = NSString::from_str(&labels.tooltip);
        if let Some(image) =
            objc2_app_kit::NSImage::imageWithSystemSymbolName_accessibilityDescription(
                &NSString::from_str("bubble.left.and.bubble.right"),
                Some(&label),
            )
        {
            image.setTemplate(true);
            button.setImage(Some(&image));
        }
        button.setToolTip(Some(&label));
    }
    item.setMenu(Some(&menu));
    Some(Inner {
        item,
        _menu: menu,
        _target: target,
    })
}
