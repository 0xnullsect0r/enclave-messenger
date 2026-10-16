//! macOS: links opened with the app (`enclave:` URLs, `docs/03-identity.md`
//! §4.2) arrive as an Apple event (`kInternetEventClass`/`kAEGetURL`), to
//! the running app or to the one LaunchServices starts for them, never as
//! arguments. This hands each one's text to the app.

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject};
use objc2::{AnyThread, define_class, msg_send, sel};
use objc2_foundation::NSString;
use std::sync::OnceLock;

type Handler = Box<dyn Fn(String) + Send + Sync>;
static HANDLER: OnceLock<Handler> = OnceLock::new();

/// `kInternetEventClass` and `kAEGetURL`, both `'GURL'`.
const GURL: u32 = u32::from_be_bytes(*b"GURL");
/// `keyDirectObject`: the URL.
const DIRECT: u32 = u32::from_be_bytes(*b"----");

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "EnclaveUrlEvents"]
    struct UrlEvents;

    impl UrlEvents {
        #[unsafe(method(handleGetURLEvent:withReplyEvent:))]
        fn get_url(&self, event: &AnyObject, _reply: &AnyObject) {
            // SAFETY: `event` is an NSAppleEventDescriptor; both messages
            // exist on it and return objects or nil.
            let text: Option<Retained<NSString>> = unsafe {
                let d: Option<Retained<AnyObject>> =
                    msg_send![event, paramDescriptorForKeyword: DIRECT];
                match d {
                    Some(d) => msg_send![&*d, stringValue],
                    None => None,
                }
            };
            if let (Some(t), Some(f)) = (text, HANDLER.get()) {
                f(t.to_string());
            }
        }
    }
);

/// Send every link opened with the app to `f` (once per process; a later
/// call is ignored). Call it before the event loop runs, so the link that
/// started the app isn't missed.
pub fn on_open_url(f: impl Fn(String) + Send + Sync + 'static) {
    if HANDLER.set(Box::new(f)).is_err() {
        return;
    }
    // SAFETY: a plain NSObject subclass, initialised with `init`; the
    // manager keeps a weak reference, so the object is kept for the
    // process. The selector matches `get_url`'s signature.
    unsafe {
        let events: Retained<UrlEvents> = msg_send![UrlEvents::alloc(), init];
        let Some(mgr): Option<Retained<AnyObject>> =
            msg_send![objc2::class!(NSAppleEventManager), sharedAppleEventManager]
        else {
            return;
        };
        let _: () = msg_send![
            &*mgr,
            setEventHandler: &*events,
            andSelector: sel!(handleGetURLEvent:withReplyEvent:),
            forEventClass: GURL,
            andEventID: GURL
        ];
        std::mem::forget(events);
    }
}
