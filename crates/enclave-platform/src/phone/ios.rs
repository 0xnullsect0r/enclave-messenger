//! iOS: UIKit and friends through objc2. Everything here runs on the main
//! thread (the app's UI thread on iOS) except the camera's frames, which
//! arrive on a queue of their own.

use super::{Camera, Pick};
use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject, Bool, NSObject, NSObjectProtocol, ProtocolObject, Sel};
use objc2::{
    AnyThread, DefinedClass, MainThreadMarker, MainThreadOnly, define_class, msg_send, sel,
};
use objc2_av_foundation::{
    AVAuthorizationStatus, AVCaptureConnection, AVCaptureDevice, AVCaptureDeviceInput,
    AVCaptureDevicePosition, AVCaptureDeviceTypeBuiltInWideAngleCamera, AVCaptureOutput,
    AVCaptureSession, AVCaptureVideoDataOutput, AVCaptureVideoDataOutputSampleBufferDelegate,
    AVMediaTypeAudio, AVMediaTypeVideo,
};
use objc2_core_media::CMSampleBuffer;
use objc2_core_video::{
    CVPixelBufferGetBaseAddressOfPlane, CVPixelBufferGetBytesPerRowOfPlane,
    CVPixelBufferGetHeightOfPlane, CVPixelBufferGetWidthOfPlane, CVPixelBufferLockBaseAddress,
    CVPixelBufferLockFlags, CVPixelBufferUnlockBaseAddress,
};
use objc2_foundation::{
    NSArray, NSData, NSDate, NSDictionary, NSNotification, NSNotificationCenter, NSNumber,
    NSOperationQueue, NSString, NSURL,
};
use objc2_ui_kit::{
    UIApplication, UIApplicationDidBecomeActiveNotification,
    UIApplicationKeyboardExtensionPointIdentifier, UIApplicationState,
    UIApplicationWillResignActiveNotification, UIBlurEffect, UIBlurEffectStyle,
    UIDocumentPickerDelegate, UIDocumentPickerViewController, UIPasteboard,
    UIPasteboardOptionExpirationDate, UIPasteboardOptionLocalOnly, UIScreen,
    UIScreenCapturedDidChangeNotification, UIView, UIViewAutoresizing, UIVisualEffectView,
    UIWindow,
};
use objc2_uniform_type_identifiers::{UTType, UTTypeData, UTTypeImage, UTTypeItem};
use objc2_user_notifications::{
    UNAuthorizationOptions, UNMutableNotificationContent, UNNotificationRequest,
    UNUserNotificationCenter,
};
use std::cell::RefCell;
use std::path::PathBuf;
use std::ptr::NonNull;
use std::sync::Mutex;
use std::time::{Duration, Instant};

type Picked = Box<dyn FnOnce(Vec<PathBuf>) + Send>;
type Saved = Box<dyn FnOnce(Result<String, String>) + Send>;
type Frames = Box<dyn FnMut(Camera) + Send>;

/// The tag of the cover laid over the window (screen security).
const COVER: isize = 0x0E1C_1A7E;
/// How long a copied text stays on the clipboard.
const CLIPBOARD: f64 = 60.0;

thread_local! {
    /// Observers and delegates kept alive (UIKit holds them weakly).
    static KEEP: RefCell<Vec<Retained<AnyObject>>> = const { RefCell::new(Vec::new()) };
    static SESSION: RefCell<Option<Retained<AVCaptureSession>>> = const { RefCell::new(None) };
}

static CAMERA: Mutex<Option<Frames>> = Mutex::new(None);
/// The camera is for a video call (front, colour), not a scan.
static CALL_CAMERA: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// The front camera's buffers, shown upright on a phone held upright.
const FRONT_ROTATION: u16 = 270;
/// Screen security, on until the profile's setting says otherwise.
static SECURE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

fn secure() -> bool {
    SECURE.load(std::sync::atomic::Ordering::Relaxed)
}

fn mtm() -> Option<MainThreadMarker> {
    MainThreadMarker::new()
}

#[allow(deprecated)]
fn key_window(mtm: MainThreadMarker) -> Option<Retained<UIWindow>> {
    UIApplication::sharedApplication(mtm).keyWindow()
}

/// Lay a blur over the window, or take it away.
fn cover(mtm: MainThreadMarker, on: bool) {
    let Some(window) = key_window(mtm) else {
        return;
    };
    let view: &UIView = &window;
    if let Some(old) = view.viewWithTag(COVER) {
        old.removeFromSuperview();
    }
    if !on {
        return;
    }
    let effect = UIBlurEffect::effectWithStyle(UIBlurEffectStyle::SystemMaterial, mtm);
    let blur = UIVisualEffectView::initWithEffect(UIVisualEffectView::alloc(mtm), Some(&effect));
    blur.setFrame(view.bounds());
    blur.setAutoresizingMask(
        UIViewAutoresizing::FlexibleWidth | UIViewAutoresizing::FlexibleHeight,
    );
    blur.setTag(COVER);
    view.addSubview(&blur);
}

fn captured(mtm: MainThreadMarker) -> bool {
    #[allow(deprecated)]
    UIScreen::mainScreen(mtm).isCaptured()
}

fn observe(name: &'static NSString, f: impl Fn() + 'static) {
    let block = RcBlock::new(move |_: NonNull<NSNotification>| f());
    let center = NSNotificationCenter::defaultCenter();
    // SAFETY: the block only touches UIKit on the main queue it is
    // delivered on, and the observer token is kept for the app's life.
    let token = unsafe {
        center.addObserverForName_object_queue_usingBlock(
            Some(name),
            None,
            Some(&NSOperationQueue::mainQueue()),
            &block,
        )
    };
    KEEP.with(|k| k.borrow_mut().push(Retained::<AnyObject>::from(token)));
}

/// The app delegate's answer to `application:shouldAllowExtensionPointIdentifier:`:
/// no third-party keyboards, which could log what is typed.
extern "C-unwind" fn should_allow(_: &AnyObject, _: Sel, _: &AnyObject, point: &NSString) -> Bool {
    // SAFETY: a constant UIKit defines.
    let keyboard = unsafe { UIApplicationKeyboardExtensionPointIdentifier };
    Bool::new(!point.isEqualToString(keyboard))
}

/// Add `imp` to `class` as `sel`, unless it answers it already.
///
/// # Safety
/// `imp` must have the signature `types` describes.
unsafe fn add_method(class: &AnyClass, sel: Sel, imp: objc2::runtime::Imp, types: &std::ffi::CStr) {
    if class.instance_method(sel).is_none() {
        // SAFETY: the caller's promise; the class is a live class.
        unsafe {
            objc2::ffi::class_addMethod(
                (class as *const AnyClass).cast_mut(),
                sel,
                imp,
                types.as_ptr(),
            );
        }
    }
}

/// APNs gave this device a token: hand it on in hex.
extern "C-unwind" fn registered(_: &AnyObject, _: Sel, _: &AnyObject, token: &NSData) {
    let hex: String = token.to_vec().iter().map(|b| format!("{b:02x}")).collect();
    super::emit(super::Event::PushToken(2, hex));
}

/// A push arrived while the app runs: fetch now.
extern "C-unwind" fn received(
    _: &AnyObject,
    _: Sel,
    _: &AnyObject,
    _: &AnyObject,
    done: &block2::DynBlock<dyn Fn(usize)>,
) {
    super::emit(super::Event::Wake);
    // UIBackgroundFetchResultNoData: the fetch runs on the vault's own time.
    done.call((1,));
}

/// Screen security and the keyboard rule. On the main thread, once the app
/// runs (its delegate exists).
pub fn init() {
    let Some(mtm) = mtm() else {
        return;
    };
    // The app switcher's snapshot and the screen while recorded or
    // mirrored show a blur, not the conversation (docs/14-storage.md §5).
    // SAFETY: constants UIKit defines.
    let (resign, active, capture) = unsafe {
        (
            UIApplicationWillResignActiveNotification,
            UIApplicationDidBecomeActiveNotification,
            UIScreenCapturedDidChangeNotification,
        )
    };
    observe(resign, move || {
        cover(mtm, secure());
        super::emit(super::Event::Visible(false));
    });
    observe(active, move || {
        cover(mtm, secure() && captured(mtm));
        super::emit(super::Event::Visible(true));
    });
    observe(capture, move || cover(mtm, secure() && captured(mtm)));
    cover(mtm, secure() && captured(mtm));

    // SAFETY: reading the delegate object to find its class.
    let delegate = unsafe { UIApplication::sharedApplication(mtm).delegate() };
    if let Some(d) = delegate {
        let obj: &AnyObject = d.as_ref();
        let class: &AnyClass = obj.class();
        // SAFETY: each function matches its selector's signature, and the
        // type encoding says so.
        unsafe {
            add_method(
                class,
                sel!(application:shouldAllowExtensionPointIdentifier:),
                std::mem::transmute::<
                    extern "C-unwind" fn(&AnyObject, Sel, &AnyObject, &NSString) -> Bool,
                    objc2::runtime::Imp,
                >(should_allow),
                c"B@:@@",
            );
            add_method(
                class,
                sel!(application:didRegisterForRemoteNotificationsWithDeviceToken:),
                std::mem::transmute::<
                    extern "C-unwind" fn(&AnyObject, Sel, &AnyObject, &NSData),
                    objc2::runtime::Imp,
                >(registered),
                c"v@:@@",
            );
            add_method(
                class,
                sel!(application:didReceiveRemoteNotification:fetchCompletionHandler:),
                std::mem::transmute::<
                    extern "C-unwind" fn(
                        &AnyObject,
                        Sel,
                        &AnyObject,
                        &AnyObject,
                        &block2::DynBlock<dyn Fn(usize)>,
                    ),
                    objc2::runtime::Imp,
                >(received),
                c"v@:@@@?",
            );
        }
    }
    // APNs: the token comes back to `registered` (Maximum privacy never
    // registers it with a server; the vault refuses there).
    UIApplication::sharedApplication(mtm).registerForRemoteNotifications();

    let center = UNUserNotificationCenter::currentNotificationCenter();
    let done = RcBlock::new(|_: Bool, _: *mut objc2_foundation::NSError| {});
    center.requestAuthorizationWithOptions_completionHandler(
        UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound,
        &done,
    );
}

/// What a document picker answers.
enum Answer {
    Pick(Picked),
    Save(Saved),
}

struct PickerIvars {
    answer: RefCell<Option<Answer>>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "EnclavePickerDelegate"]
    #[ivars = PickerIvars]
    struct PickerDelegate;

    unsafe impl NSObjectProtocol for PickerDelegate {}

    unsafe impl UIDocumentPickerDelegate for PickerDelegate {
        #[unsafe(method(documentPicker:didPickDocumentsAtURLs:))]
        fn did_pick(&self, _: &UIDocumentPickerViewController, urls: &NSArray<NSURL>) {
            let paths: Vec<PathBuf> = urls
                .iter()
                .filter_map(|u| u.path().map(|p| PathBuf::from(p.to_string())))
                .collect();
            self.answer(paths);
        }

        #[unsafe(method(documentPickerWasCancelled:))]
        fn cancelled(&self, _: &UIDocumentPickerViewController) {
            self.answer(Vec::new());
        }
    }
);

impl PickerDelegate {
    fn new(mtm: MainThreadMarker, answer: Answer) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(PickerIvars {
            answer: RefCell::new(Some(answer)),
        });
        // SAFETY: NSObject's init on a freshly allocated object.
        unsafe { msg_send![super(this), init] }
    }

    fn answer(&self, paths: Vec<PathBuf>) {
        let taken = self.ivars().answer.borrow_mut().take();
        match taken {
            Some(Answer::Pick(done)) => done(paths),
            Some(Answer::Save(done)) => match paths.first() {
                Some(p) => done(Ok(p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default())),
                None => done(Err(String::new())),
            },
            None => {}
        }
        let me: *const Self = self;
        KEEP.with(|k| {
            k.borrow_mut()
                .retain(|o| !std::ptr::eq(Retained::as_ptr(o).cast(), me))
        });
    }
}

fn present(
    mtm: MainThreadMarker,
    picker: &UIDocumentPickerViewController,
    answer: Answer,
) -> Result<(), Answer> {
    let Some(root) = key_window(mtm).and_then(|w| w.rootViewController()) else {
        return Err(answer);
    };
    let delegate = PickerDelegate::new(mtm, answer);
    picker.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
    KEEP.with(|k| {
        k.borrow_mut()
            .push(Retained::into_super(Retained::into_super(delegate)))
    });
    root.presentViewController_animated_completion(picker, true, None);
    Ok(())
}

pub(super) fn pick(kind: Pick, done: Picked) {
    let Some(mtm) = mtm() else {
        return done(Vec::new());
    };
    // SAFETY: constants the framework defines.
    let ty: &UTType = unsafe {
        match kind {
            Pick::Backup => UTTypeData,
            Pick::Pictures => UTTypeImage,
            Pick::File => UTTypeItem,
        }
    };
    let types = NSArray::from_slice(&[ty]);
    let picker = UIDocumentPickerViewController::initForOpeningContentTypes_asCopy(
        UIDocumentPickerViewController::alloc(mtm),
        &types,
        true,
    );
    picker.setAllowsMultipleSelection(kind == Pick::Pictures);
    if let Err(Answer::Pick(done)) = present(mtm, &picker, Answer::Pick(done)) {
        done(Vec::new());
    }
}

pub(super) fn save(name: &str, bytes: Vec<u8>, done: Saved) {
    let Some(mtm) = mtm() else {
        return done(Err("the file can't be saved here".into()));
    };
    let safe: String = name
        .chars()
        .map(|c| if c == '/' || c == '\\' { '_' } else { c })
        .collect();
    let safe = if safe.is_empty() || safe.starts_with('.') {
        "file".into()
    } else {
        safe
    };
    let dir = std::env::temp_dir().join("export");
    let path = dir.join(&safe);
    if let Err(e) = std::fs::create_dir_all(&dir).and_then(|()| std::fs::write(&path, &bytes)) {
        return done(Err(e.to_string()));
    }
    let url = NSURL::fileURLWithPath(&NSString::from_str(&path.to_string_lossy()));
    let urls = NSArray::from_retained_slice(&[url]);
    let picker = UIDocumentPickerViewController::initForExportingURLs_asCopy(
        UIDocumentPickerViewController::alloc(mtm),
        &urls,
        true,
    );
    if let Err(Answer::Save(done)) = present(mtm, &picker, Answer::Save(done)) {
        done(Err("the file can't be saved here".into()));
    }
}

pub(super) fn notify(title: &str, body: &str) {
    let Some(mtm) = mtm() else {
        return;
    };
    if UIApplication::sharedApplication(mtm).applicationState() == UIApplicationState::Active {
        return;
    }
    let content = UNMutableNotificationContent::new();
    content.setTitle(&NSString::from_str(title));
    content.setBody(&NSString::from_str(body));
    let request = UNNotificationRequest::requestWithIdentifier_content_trigger(
        &NSString::from_str("enclave-message"),
        &content,
        None,
    );
    UNUserNotificationCenter::currentNotificationCenter()
        .addNotificationRequest_withCompletionHandler(&request, None);
}

pub(super) fn copy(text: &str) -> bool {
    let board = UIPasteboard::generalPasteboard();
    let key = NSString::from_str("public.utf8-plain-text");
    let value = NSString::from_str(text);
    let item: Retained<NSDictionary<NSString, AnyObject>> =
        NSDictionary::from_slices(&[&*key], &[value.as_ref()]);
    let items = NSArray::from_retained_slice(&[item]);
    let local = NSNumber::new_bool(true);
    let until = NSDate::dateWithTimeIntervalSinceNow(CLIPBOARD);
    // SAFETY: constants UIKit defines.
    let (k_local, k_until) = unsafe {
        (
            UIPasteboardOptionLocalOnly,
            UIPasteboardOptionExpirationDate,
        )
    };
    let options: Retained<NSDictionary<NSString, AnyObject>> =
        NSDictionary::from_slices(&[k_local, k_until], &[local.as_ref(), until.as_ref()]);
    // SAFETY: the items are plain-text dictionaries, the options the two
    // documented keys with their documented value types.
    unsafe { board.setItems_options(&items, &options) };
    true
}

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "EnclaveCameraDelegate"]
    #[ivars = Mutex<Instant>]
    struct CameraDelegate;

    unsafe impl NSObjectProtocol for CameraDelegate {}

    unsafe impl AVCaptureVideoDataOutputSampleBufferDelegate for CameraDelegate {
        #[unsafe(method(captureOutput:didOutputSampleBuffer:fromConnection:))]
        unsafe fn frame(&self, _: &AVCaptureOutput, buffer: &CMSampleBuffer, _: &AVCaptureConnection) {
            {
                let Ok(mut last) = self.ivars().lock() else {
                    return;
                };
                let call = CALL_CAMERA.load(std::sync::atomic::Ordering::SeqCst);
                if last.elapsed() < Duration::from_millis(if call { 66 } else { 120 }) {
                    return;
                }
                *last = Instant::now();
            }
            if CALL_CAMERA.load(std::sync::atomic::Ordering::SeqCst) {
                // SAFETY: as below, for both planes.
                if let Some((w, h, i420)) = unsafe { buffer.image_buffer().and_then(|i| i420(&i)) }
                    && let (Ok(w), Ok(h)) = (u32::try_from(w), u32::try_from(h))
                    && let Ok(mut c) = CAMERA.lock()
                    && let Some(report) = c.as_mut()
                {
                    report(Camera::Color(w, h, FRONT_ROTATION, i420));
                }
                return;
            }
            // SAFETY: the buffer is valid for this call.
            let Some(image) = (unsafe { buffer.image_buffer() }) else {
                return;
            };
            // SAFETY: locked read-only around the plane reads; the plane
            // is `height` rows of `stride` bytes.
            let grey = unsafe {
                if CVPixelBufferLockBaseAddress(&image, CVPixelBufferLockFlags::ReadOnly) != 0 {
                    return;
                }
                let w = CVPixelBufferGetWidthOfPlane(&image, 0);
                let h = CVPixelBufferGetHeightOfPlane(&image, 0);
                let stride = CVPixelBufferGetBytesPerRowOfPlane(&image, 0);
                let base = CVPixelBufferGetBaseAddressOfPlane(&image, 0).cast::<u8>();
                let out = if base.is_null() || stride < w {
                    None
                } else {
                    let mut out = Vec::with_capacity(w * h);
                    for row in 0..h {
                        out.extend_from_slice(std::slice::from_raw_parts(base.add(row * stride), w));
                    }
                    Some((w, h, out))
                };
                CVPixelBufferUnlockBaseAddress(&image, CVPixelBufferLockFlags::ReadOnly);
                out
            };
            if let Some((w, h, grey)) = grey
                && let (Ok(w), Ok(h)) = (u32::try_from(w), u32::try_from(h))
                && let Ok(mut c) = CAMERA.lock()
                && let Some(report) = c.as_mut()
            {
                report(Camera::Frame(w, h, grey));
            }
        }
    }
);

/// I420 from a bi-planar 4:2:0 pixel buffer (Y, then Cb and Cr
/// interleaved).
///
/// # Safety
///
/// `image` must be a valid pixel buffer for the duration of the call.
unsafe fn i420(image: &objc2_core_video::CVBuffer) -> Option<(usize, usize, Vec<u8>)> {
    // SAFETY: locked read-only around the plane reads; each plane is
    // `height` rows of `stride` bytes.
    unsafe {
        if CVPixelBufferLockBaseAddress(image, CVPixelBufferLockFlags::ReadOnly) != 0 {
            return None;
        }
        let w = CVPixelBufferGetWidthOfPlane(image, 0);
        let h = CVPixelBufferGetHeightOfPlane(image, 0);
        let ys = CVPixelBufferGetBytesPerRowOfPlane(image, 0);
        let cs = CVPixelBufferGetBytesPerRowOfPlane(image, 1);
        let yb = CVPixelBufferGetBaseAddressOfPlane(image, 0).cast::<u8>();
        let cb = CVPixelBufferGetBaseAddressOfPlane(image, 1).cast::<u8>();
        let (cw, ch) = (w.div_ceil(2), h.div_ceil(2));
        let out = if yb.is_null() || cb.is_null() || ys < w || cs < 2 * cw {
            None
        } else {
            let mut out = Vec::with_capacity(w * h + 2 * cw * ch);
            for row in 0..h {
                out.extend_from_slice(std::slice::from_raw_parts(yb.add(row * ys), w));
            }
            let mut v = Vec::with_capacity(cw * ch);
            for row in 0..ch {
                let line = std::slice::from_raw_parts(cb.add(row * cs), 2 * cw);
                for pair in line.chunks_exact(2) {
                    out.push(pair[0]);
                    v.push(pair[1]);
                }
            }
            out.extend_from_slice(&v);
            Some((w, h, out))
        };
        CVPixelBufferUnlockBaseAddress(image, CVPixelBufferLockFlags::ReadOnly);
        out
    }
}

/// A session to start on the camera's queue (AVFoundation's documented
/// way: `startRunning` blocks, so not on the main thread).
struct Running(Retained<AVCaptureSession>);

// SAFETY: AVCaptureSession may be started from any thread; this one is
// moved to the camera queue and used only there.
unsafe impl Send for Running {}

fn camera_failed(why: &str) {
    if let Ok(mut c) = CAMERA.lock()
        && let Some(report) = c.as_mut()
    {
        report(Camera::Failed(why.into()));
    }
}

fn open_camera() {
    // SAFETY: a constant AVFoundation defines.
    let Some(video) = (unsafe { AVMediaTypeVideo }) else {
        return camera_failed("No camera was found.");
    };
    // SAFETY: plain AVFoundation calls with valid arguments.
    unsafe {
        let front = if CALL_CAMERA.load(std::sync::atomic::Ordering::SeqCst) {
            AVCaptureDevice::defaultDeviceWithDeviceType_mediaType_position(
                AVCaptureDeviceTypeBuiltInWideAngleCamera,
                Some(video),
                AVCaptureDevicePosition::Front,
            )
        } else {
            None
        };
        let Some(device) = front.or_else(|| AVCaptureDevice::defaultDeviceWithMediaType(video))
        else {
            return camera_failed("No camera was found.");
        };
        let Ok(input) = AVCaptureDeviceInput::deviceInputWithDevice_error(&device) else {
            return camera_failed("The camera is busy or can't be opened.");
        };
        let session = AVCaptureSession::new();
        let output = AVCaptureVideoDataOutput::new();
        let format =
            NSNumber::new_u32(objc2_core_video::kCVPixelFormatType_420YpCbCr8BiPlanarFullRange);
        // CFString and NSString are the same object (toll-free bridged).
        let key: &NSString =
            &*std::ptr::from_ref(objc2_core_video::kCVPixelBufferPixelFormatTypeKey)
                .cast::<NSString>();
        let settings: Retained<NSDictionary<NSString, AnyObject>> =
            NSDictionary::from_slices(&[key], &[format.as_ref()]);
        output.setVideoSettings(Some(&settings));
        output.setAlwaysDiscardsLateVideoFrames(true);
        let delegate = CameraDelegate::alloc().set_ivars(Mutex::new(Instant::now()));
        let delegate: Retained<CameraDelegate> = msg_send![super(delegate), init];
        let queue = dispatch2::DispatchQueue::new("enclave.camera", None);
        output.setSampleBufferDelegate_queue(
            Some(ProtocolObject::from_ref(&*delegate)),
            Some(&queue),
        );
        KEEP.with(|k| {
            k.borrow_mut()
                .push(Retained::into_super(Retained::into_super(delegate)))
        });
        if !session.canAddInput(&input) || !session.canAddOutput(&output) {
            return camera_failed("The camera can't be started.");
        }
        session.addInput(&input);
        session.addOutput(&output);
        let running = Running(session.clone());
        queue.exec_async(move || {
            let r = running;
            r.0.startRunning();
        });
        SESSION.with(|s| *s.borrow_mut() = Some(session));
    }
}

pub(super) fn start_call_camera(report: Frames) {
    CALL_CAMERA.store(true, std::sync::atomic::Ordering::SeqCst);
    start(report);
}

pub(super) fn start_camera(report: Frames) {
    CALL_CAMERA.store(false, std::sync::atomic::Ordering::SeqCst);
    start(report);
}

fn start(report: Frames) {
    if let Ok(mut c) = CAMERA.lock() {
        *c = Some(report);
    }
    // SAFETY: a constant AVFoundation defines.
    let Some(video) = (unsafe { AVMediaTypeVideo }) else {
        return camera_failed("No camera was found.");
    };
    // SAFETY: a plain class method.
    match unsafe { AVCaptureDevice::authorizationStatusForMediaType(video) } {
        AVAuthorizationStatus::Authorized => open_camera(),
        AVAuthorizationStatus::NotDetermined => {
            let answer = RcBlock::new(|granted: Bool| {
                if granted.as_bool() {
                    dispatch2::DispatchQueue::main().exec_async(open_camera);
                } else {
                    camera_failed(
                        "Enclave may not use the camera. Allow it in Settings → Enclave.",
                    );
                }
            });
            // SAFETY: a plain class method; the block lives as long as
            // AVFoundation needs it.
            unsafe { AVCaptureDevice::requestAccessForMediaType_completionHandler(video, &answer) };
        }
        _ => camera_failed("Enclave may not use the camera. Allow it in Settings → Enclave."),
    }
}

pub(super) fn ask_microphone() {
    // SAFETY: a constant AVFoundation defines.
    let Some(audio) = (unsafe { AVMediaTypeAudio }) else {
        return;
    };
    // SAFETY: a plain class method.
    if unsafe { AVCaptureDevice::authorizationStatusForMediaType(audio) }
        == AVAuthorizationStatus::NotDetermined
    {
        let answer = RcBlock::new(|_granted: Bool| {});
        // SAFETY: a plain class method; the block lives as long as
        // AVFoundation needs it.
        unsafe { AVCaptureDevice::requestAccessForMediaType_completionHandler(audio, &answer) };
    }
}

pub(super) fn stop_camera() {
    SESSION.with(|s| {
        if let Some(session) = s.borrow_mut().take() {
            // SAFETY: stopping a session we started.
            unsafe { session.stopRunning() };
        }
    });
    if let Ok(mut c) = CAMERA.lock() {
        *c = None;
    }
}

pub(super) fn set_screen_security(on: bool) {
    SECURE.store(on, std::sync::atomic::Ordering::Relaxed);
    if let Some(mtm) = mtm() {
        cover(mtm, on && captured(mtm));
    }
}

pub(super) fn delivery() -> (u8, u8) {
    (super::delivery::APPLE, 1 << super::delivery::APPLE)
}

pub(super) fn set_delivery(_: u8) {}

/// Dynamic Type: the content size category the person chose, as a scale.
pub(super) fn text_scale() -> f32 {
    let Some(mtm) = MainThreadMarker::new() else {
        return 1.0;
    };
    let app = UIApplication::sharedApplication(mtm);
    // SAFETY: preferredContentSizeCategory is a UIApplication property
    // returning an NSString (a UIContentSizeCategory constant), read on
    // the main thread.
    let category: Retained<NSString> =
        unsafe { objc2::msg_send![&app, preferredContentSizeCategory] };
    match category.to_string().as_str() {
        "UICTContentSizeCategoryXS"
        | "UICTContentSizeCategoryS"
        | "UICTContentSizeCategoryM"
        | "UICTContentSizeCategoryL" => 1.0,
        "UICTContentSizeCategoryXL" => 1.12,
        "UICTContentSizeCategoryXXL" => 1.24,
        "UICTContentSizeCategoryXXXL" => 1.35,
        "UICTContentSizeCategoryAccessibilityM" => 1.65,
        "UICTContentSizeCategoryAccessibilityL" => 1.94,
        c if c.starts_with("UICTContentSizeCategoryAccessibility") => 2.0,
        _ => 1.0,
    }
}

#[link(name = "UIKit", kind = "framework")]
unsafe extern "C" {
    fn UIAccessibilityIsReduceMotionEnabled() -> objc2::runtime::Bool;
}

/// Settings → Accessibility → Motion → Reduce Motion.
pub(super) fn reduce_motion() -> bool {
    // SAFETY: a UIKit function with no arguments that only reads a setting.
    unsafe { UIAccessibilityIsReduceMotionEnabled() }.as_bool()
}
