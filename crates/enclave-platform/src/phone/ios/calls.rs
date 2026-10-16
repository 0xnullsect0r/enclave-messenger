//! CallKit and PushKit (`docs/11-calls.md` §2, `docs/10-push.md` §5,
//! PC-02).
//!
//! A call's offer wakes the app by a PushKit VoIP push, which iOS requires
//! to be reported to CallKit at once: the system's incoming-call screen
//! shows "Enclave" until the vault has the offer and names the caller.
//! Calls are kept out of the phone's recents. The answer, hang-up and
//! mute buttons of the system's screens come back as [`super::super::Event`]s.
//! A push whose offer never comes (the call was over first) stops ringing
//! after 30 s. The `report_*` functions may be called from any thread;
//! CallKit's objects live on the main one.

use super::super::{Event, emit};
use block2::{DynBlock, RcBlock};
use objc2::rc::Retained;
use objc2::runtime::{NSObject, NSObjectProtocol, ProtocolObject};
use objc2::{AllocAnyThread, define_class};
use objc2_call_kit::{
    CXAnswerCallAction, CXCallController, CXCallEndedReason, CXCallUpdate, CXEndCallAction,
    CXHandle, CXHandleType, CXProvider, CXProviderConfiguration, CXProviderDelegate,
    CXSetMutedCallAction, CXStartCallAction, CXTransaction,
};
use objc2_foundation::{NSError, NSNumber, NSSet, NSString, NSUUID};
use objc2_push_kit::{
    PKPushCredentials, PKPushPayload, PKPushRegistry, PKPushRegistryDelegate, PKPushType,
    PKPushTypeVoIP,
};
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// The call CallKit knows about, and whether we placed it.
struct Current {
    uuid: Retained<NSUUID>,
    outgoing: bool,
    /// The vault named the caller (not just a push's placeholder).
    named: bool,
    /// Which report this was (for the placeholder's timeout).
    serial: u64,
}

static SERIAL: AtomicU64 = AtomicU64::new(1);

/// How long a push's call screen waits for the vault's offer.
const PLACEHOLDER: Duration = Duration::from_secs(30);

thread_local! {
    static PROVIDER: RefCell<Option<Retained<CXProvider>>> = const { RefCell::new(None) };
    static REGISTRY: RefCell<Option<Retained<PKPushRegistry>>> = const { RefCell::new(None) };
    static DELEGATE: RefCell<Option<Retained<CallDelegate>>> = const { RefCell::new(None) };
    static CURRENT: RefCell<Option<Current>> = const { RefCell::new(None) };
}

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "EnclaveCallDelegate"]
    struct CallDelegate;

    unsafe impl NSObjectProtocol for CallDelegate {}

    unsafe impl CXProviderDelegate for CallDelegate {
        #[unsafe(method(providerDidReset:))]
        fn did_reset(&self, _: &CXProvider) {
            CURRENT.with(|c| c.borrow_mut().take());
            emit(Event::CallEnded);
        }

        #[unsafe(method(provider:performAnswerCallAction:))]
        fn answer(&self, _: &CXProvider, action: &CXAnswerCallAction) {
            voice_audio();
            emit(Event::CallAnswered);
            // SAFETY: an action CallKit handed us, fulfilled once.
            unsafe { action.fulfill() };
        }

        #[unsafe(method(provider:performEndCallAction:))]
        fn end(&self, _: &CXProvider, action: &CXEndCallAction) {
            CURRENT.with(|c| c.borrow_mut().take());
            emit(Event::CallEnded);
            // SAFETY: as above.
            unsafe { action.fulfill() };
        }

        #[unsafe(method(provider:performSetMutedCallAction:))]
        fn mute(&self, _: &CXProvider, action: &CXSetMutedCallAction) {
            // SAFETY: as above.
            unsafe {
                emit(Event::CallMuted(action.isMuted()));
                action.fulfill();
            }
        }

        #[unsafe(method(provider:performStartCallAction:))]
        fn start(&self, _: &CXProvider, action: &CXStartCallAction) {
            voice_audio();
            // SAFETY: as above.
            unsafe { action.fulfill() };
        }
    }

    unsafe impl PKPushRegistryDelegate for CallDelegate {
        #[unsafe(method(pushRegistry:didUpdatePushCredentials:forType:))]
        fn credentials(&self, _: &PKPushRegistry, credentials: &PKPushCredentials, _: &PKPushType) {
            // SAFETY: credentials PushKit handed us.
            let token = unsafe { credentials.token() };
            let hex: String = token.to_vec().iter().map(|b| format!("{b:02x}")).collect();
            emit(Event::PushToken(4, hex));
        }

        #[unsafe(method(pushRegistry:didReceiveIncomingPushWithPayload:forType:withCompletionHandler:))]
        fn incoming(
            &self,
            _: &PKPushRegistry,
            _: &PKPushPayload,
            _: &PKPushType,
            done: &DynBlock<dyn Fn()>,
        ) {
            // Reported before anything else (iOS ends apps that don't); the
            // vault names the caller once it has the offer.
            incoming_now("Enclave", false, false);
            emit(Event::Wake);
            done.call(());
            let serial = CURRENT.with(|c| c.borrow().as_ref().map_or(0, |c| c.serial));
            if let Ok(when) = dispatch2::DispatchTime::try_from(PLACEHOLDER) {
                let _ = dispatch2::DispatchQueue::main().after(when, move || {
                    let stale = CURRENT.with(|c| {
                        c.borrow()
                            .as_ref()
                            .is_some_and(|c| c.serial == serial && !c.named)
                    });
                    if stale {
                        ended_now(CXCallEndedReason::Unanswered);
                    }
                });
            }
        }
    }
);

/// Set up CallKit and ask PushKit for a VoIP token. On the main thread.
pub(crate) fn init() {
    // SAFETY: plain CallKit and PushKit calls on the main thread with
    // valid arguments; the provider, registry and delegate are kept for
    // the app's life (both hold their delegate weakly).
    unsafe {
        let config = CXProviderConfiguration::new();
        config.setSupportsVideo(true);
        config.setMaximumCallGroups(1);
        config.setMaximumCallsPerCallGroup(1);
        // Nothing about calls in the phone's own call history.
        config.setIncludesCallsInRecents(false);
        let generic = NSNumber::new_isize(CXHandleType::Generic.0);
        config.setSupportedHandleTypes(&NSSet::from_slice(&[&*generic]));
        let provider = CXProvider::initWithConfiguration(CXProvider::alloc(), &config);
        let delegate = CallDelegate::alloc().set_ivars(());
        let delegate: Retained<CallDelegate> = objc2::msg_send![super(delegate), init];
        provider.setDelegate_queue(Some(ProtocolObject::from_ref(&*delegate)), None);
        let registry = PKPushRegistry::initWithQueue(PKPushRegistry::alloc(), None);
        registry.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        registry.setDesiredPushTypes(Some(&NSSet::from_slice(&[PKPushTypeVoIP])));
        PROVIDER.with(|p| *p.borrow_mut() = Some(provider));
        REGISTRY.with(|r| *r.borrow_mut() = Some(registry));
        DELEGATE.with(|d| *d.borrow_mut() = Some(delegate));
    }
}

fn update(name: &str, video: bool) -> Retained<CXCallUpdate> {
    // SAFETY: a fresh update object, filled in.
    unsafe {
        let u = CXCallUpdate::new();
        u.setLocalizedCallerName(Some(&NSString::from_str(name)));
        u.setHasVideo(video);
        u.setSupportsHolding(false);
        u.setSupportsGrouping(false);
        u.setSupportsUngrouping(false);
        u.setSupportsDTMF(false);
        u
    }
}

/// The audio session for a call (CallKit activates it): voice processing,
/// Bluetooth headsets. Set before CallKit activates it, as Apple asks.
fn voice_audio() {
    use objc2_avf_audio::{
        AVAudioSession, AVAudioSessionCategoryOptions, AVAudioSessionCategoryPlayAndRecord,
        AVAudioSessionModeVoiceChat,
    };
    // SAFETY: the shared session, set with the system's own constants.
    unsafe {
        let (Some(category), Some(mode)) = (
            AVAudioSessionCategoryPlayAndRecord,
            AVAudioSessionModeVoiceChat,
        ) else {
            return;
        };
        let _ = AVAudioSession::sharedInstance().setCategory_mode_options_error(
            category,
            mode,
            AVAudioSessionCategoryOptions::AllowBluetoothHFP,
        );
    }
}

fn on_main(f: impl FnOnce() + Send + 'static) {
    dispatch2::DispatchQueue::main().exec_async(f);
}

/// An incoming call: show the system's call screen, or name the caller on
/// the one a VoIP push already showed.
pub(crate) fn report_incoming(name: &str, video: bool) {
    let name = name.to_string();
    on_main(move || incoming_now(&name, video, true));
}

/// We are calling: tell CallKit, so the call gets the system's audio
/// handling and shows on the lock screen.
pub(crate) fn report_outgoing(name: &str, video: bool) {
    let name = name.to_string();
    on_main(move || outgoing_now(&name, video));
}

/// The call connected.
pub(crate) fn report_connected() {
    on_main(connected_now);
}

/// The call ended (here, or the other side hung up).
pub(crate) fn report_ended() {
    on_main(|| ended_now(CXCallEndedReason::RemoteEnded));
}

fn incoming_now(name: &str, video: bool, named: bool) {
    PROVIDER.with(|p| {
        let Some(provider) = p.borrow().clone() else {
            return;
        };
        let known = CURRENT.with(|c| c.borrow().as_ref().map(|c| c.uuid.clone()));
        // SAFETY: CallKit calls on the main thread with valid objects.
        unsafe {
            match known {
                Some(uuid) => {
                    provider.reportCallWithUUID_updated(&uuid, &update(name, video));
                    if named {
                        CURRENT.with(|c| {
                            if let Some(c) = c.borrow_mut().as_mut() {
                                c.named = true;
                            }
                        });
                    }
                }
                None => {
                    let uuid = NSUUID::new();
                    let (who, kind) = (
                        name.to_string(),
                        if video {
                            "Incoming video call"
                        } else {
                            "Incoming call"
                        },
                    );
                    let done = RcBlock::new(move |e: *mut NSError| {
                        // Refused (Do Not Disturb, a call in progress, or
                        // CallKit not allowed where the phone is, PC-03):
                        // no call screen to update; a notification says
                        // it rings instead.
                        if !e.is_null() {
                            CURRENT.with(|c| c.borrow_mut().take());
                            super::notify(kind, &who);
                        }
                    });
                    provider.reportNewIncomingCallWithUUID_update_completion(
                        &uuid,
                        &update(name, video),
                        &done,
                    );
                    CURRENT.with(|c| {
                        *c.borrow_mut() = Some(Current {
                            uuid,
                            outgoing: false,
                            named,
                            serial: SERIAL.fetch_add(1, Ordering::Relaxed),
                        });
                    });
                }
            }
        }
    });
}

fn outgoing_now(name: &str, video: bool) {
    if CURRENT.with(|c| c.borrow().is_some()) {
        return;
    }
    // SAFETY: CallKit calls on the main thread with valid objects.
    unsafe {
        let uuid = NSUUID::new();
        let handle = CXHandle::initWithType_value(
            CXHandle::alloc(),
            CXHandleType::Generic,
            &NSString::from_str(name),
        );
        let action =
            CXStartCallAction::initWithCallUUID_handle(CXStartCallAction::alloc(), &uuid, &handle);
        action.setVideo(video);
        let tx = CXTransaction::initWithAction(CXTransaction::alloc(), &action);
        let done = RcBlock::new(|_: *mut NSError| {});
        CXCallController::new().requestTransaction_completion(&tx, &done);
        CURRENT.with(|c| {
            *c.borrow_mut() = Some(Current {
                uuid,
                outgoing: true,
                named: true,
                serial: SERIAL.fetch_add(1, Ordering::Relaxed),
            });
        });
    }
}

fn connected_now() {
    PROVIDER.with(|p| {
        let (Some(provider), Some((uuid, true))) = (
            p.borrow().clone(),
            CURRENT.with(|c| c.borrow().as_ref().map(|c| (c.uuid.clone(), c.outgoing))),
        ) else {
            return;
        };
        // SAFETY: a call CallKit knows, on the main thread.
        unsafe { provider.reportOutgoingCallWithUUID_connectedAtDate(&uuid, None) };
    });
}

fn ended_now(reason: CXCallEndedReason) {
    let Some(current) = CURRENT.with(|c| c.borrow_mut().take()) else {
        return;
    };
    PROVIDER.with(|p| {
        if let Some(provider) = p.borrow().as_ref() {
            // SAFETY: a call CallKit knows, on the main thread.
            unsafe {
                provider.reportCallWithUUID_endedAtDate_reason(&current.uuid, None, reason);
            }
        }
    });
}
