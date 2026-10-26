//! Enclave on Android and iOS (milestones A1 and I1).
//!
//! A phone app is one process (iOS starts no programs at all), so the
//! desktop's helper programs are linked in and run as threads of it
//! (`enclave_platform::process`): netd for the network, tord for Tor,
//! nymd for the mixnet client and mediad for pictures, each on the same
//! pipes and protocol as its program. Tor and the Nym client share the
//! process thanks to one SQLite for both (`third_party/libsqlite3-sys-030`).
//! The vault runs on a thread of its own; the operating system's app
//! sandbox stands in for the desktop's per-process confinement.

use std::path::PathBuf;

/// Run the app on the profile in `profile` until its window closes, with
/// `extra` arguments for it (`--smoke-exit` in checks).
pub fn start(profile: PathBuf, extra: Vec<String>) -> Result<(), slint::PlatformError> {
    prepare();
    let mut args = args(&profile);
    args.extend(extra);
    enclave_app::shell::run(args)
}

/// Start the vault on `profile` with no window (Android's background
/// service, for a push or to stay connected). A window opened later
/// attaches to the same vault.
#[cfg(any(target_os = "android", target_os = "ios"))]
pub fn start_headless(profile: PathBuf) {
    prepare();
    enclave_crash::install(&profile.join(enclave_crash::DIR), "app");
    match enclave_vault::Mode::from_args(&args(&profile)) {
        Ok(mode) => enclave_app::vault::phone::run(mode),
        Err(e) => eprintln!("enclave: {e}"),
    }
}

fn args(profile: &std::path::Path) -> Vec<String> {
    vec![
        "enclave".into(),
        "--single-process".into(),
        "--profile".into(),
        profile.to_string_lossy().into_owned(),
    ]
}

/// The helpers, Tor's variables and (Android) the helper processes, once
/// per process (the service and each new window both come here).
fn prepare() {
    register_helpers();
    #[cfg(target_os = "android")]
    {
        static REMOTE: std::sync::Once = std::sync::Once::new();
        REMOTE.call_once(|| {
            enclave_platform::process::set_remote(enclave_platform::phone::android::helper_process)
        });
    }
    tor_once();
}

/// The helpers linked into the app, runnable as threads or in a helper
/// process.
fn register_helpers() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        enclave_platform::process::register("enclave-netd", enclave_netd::main_with);
        enclave_platform::process::register("enclave-tord", enclave_tord::daemon::main_with);
        enclave_platform::process::register("enclave-nymd", enclave_nymd::main_with);
        #[cfg(enclave_mediad_wasm)]
        enclave_platform::process::register("enclave-mediad", sandboxed_mediad);
        #[cfg(not(enclave_mediad_wasm))]
        enclave_platform::process::register("enclave-mediad", enclave_mediad::main_with);
        enclave_tord::managed::set_in_process(lyrebird::start);
    });
}

/// iOS: mediad as WebAssembly in the interpreter sandbox
/// (`enclave-wasmbox`, `docs/15-client.md` §1.3), on the pipes the vault
/// gave this thread. Other people's pictures, clips and voice notes are
/// parsed only there.
#[cfg(enclave_mediad_wasm)]
fn sandboxed_mediad(_args: Vec<String>) -> std::process::ExitCode {
    static MODULE: &[u8] = include_bytes!(env!("ENCLAVE_MEDIAD_WASM_PATH"));
    let Ok(io) = enclave_platform::process::stdio() else {
        return std::process::ExitCode::FAILURE;
    };
    match enclave_wasmbox::run(MODULE, io.input, io.output) {
        Ok(0) => std::process::ExitCode::SUCCESS,
        Ok(_) => std::process::ExitCode::FAILURE,
        Err(e) => {
            eprintln!("enclave-mediad (sandbox): {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn tor_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(tor_variables);
}

/// Snowflake and WebTunnel (`docs/09-transport.md` §7): lyrebird's clients
/// in this process, as a library built by `ci/tor/lyrebird.sh archive`. On
/// iOS it is linked in (`liblyrebird.a`, when the build had it); on Android
/// loaded from the APK (`liblyrebird.so`). Without it those bridges can't
/// be used; obfs4 runs in enclave-tord itself either way.
mod lyrebird {
    use std::ffi::{CString, c_char, c_int};
    use std::path::Path;

    type Start = unsafe extern "C" fn(*const c_char, *const c_char) -> c_int;

    #[cfg(enclave_lyrebird)]
    #[allow(unsafe_code)]
    unsafe extern "C" {
        fn enclave_pt_start(state: *const c_char, name: *const c_char) -> c_int;
    }

    #[cfg(enclave_lyrebird)]
    fn entry() -> Option<Start> {
        Some(enclave_pt_start)
    }

    #[cfg(all(target_os = "android", not(enclave_lyrebird)))]
    #[allow(unsafe_code)]
    fn entry() -> Option<Start> {
        static LIB: std::sync::OnceLock<Option<libloading::Library>> = std::sync::OnceLock::new();
        // SAFETY: liblyrebird.so is ours (ci/tor/lyrebird-lib); loading
        // it starts the Go runtime and runs no other initialisers.
        let lib = LIB
            .get_or_init(|| unsafe { libloading::Library::new("liblyrebird.so").ok() })
            .as_ref()?;
        // SAFETY: the symbol has this signature (enclave_pt.go), and the
        // library stays loaded for the life of the process.
        unsafe { lib.get::<Start>(b"enclave_pt_start\0").ok().map(|s| *s) }
    }

    #[cfg(all(not(target_os = "android"), not(enclave_lyrebird)))]
    fn entry() -> Option<Start> {
        None
    }

    /// Start transport `name` with its state in `state`: its SOCKS5 port.
    pub fn start(state: &Path, name: &str) -> Option<u16> {
        let f = entry()?;
        let state = CString::new(state.to_string_lossy().as_bytes()).ok()?;
        let name = CString::new(name).ok()?;
        // SAFETY: both are NUL-terminated strings that outlive the call;
        // the function copies what it keeps.
        #[allow(unsafe_code)]
        let port = unsafe { f(state.as_ptr(), name.as_ptr()) };
        u16::try_from(port).ok().filter(|p| *p != 0)
    }
}

/// Tor's loopback port and secret for this run, and the proxy variables
/// that send the mixnet client's HTTP (nym-api, ticketbooks) through it.
/// On the desktop netd gives these to nymd's process; here they are the
/// app's own, set once ([`prepare`]), before any thread of ours reads them.
fn tor_variables() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or(0);
    let Ok(secret) =
        enclave_crypto::rng::HedgedRng::new().and_then(|mut r| r.array::<32>("netd/tor-secret"))
    else {
        return;
    };
    let secret: String = secret.iter().map(|b| format!("{b:02x}")).collect();
    let proxy = format!("socks5h://{}:{secret}@127.0.0.1:{port}", enclave_tord::USER);
    let mut vars = vec![
        ("ENCLAVE_TOR_SOCKS", format!("127.0.0.1:{port}")),
        ("ENCLAVE_TOR_SECRET", secret),
    ];
    for v in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        vars.push((v, proxy.clone()));
    }
    for (k, v) in vars {
        // SAFETY: called first thing when the app starts, before it has
        // started any thread that reads the environment.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var(k, v);
        }
    }
    for v in ["NO_PROXY", "no_proxy"] {
        // SAFETY: as above.
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var(v);
        }
    }
}

/// Android's entry point: the activity's internal storage holds the
/// profile.
#[cfg(target_os = "android")]
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
fn android_main(app: slint::android::AndroidApp) {
    stderr_to_logcat();
    enclave_platform::phone::android::attach_activity();
    let profile = app
        .internal_data_path()
        .unwrap_or_else(|| PathBuf::from("/data/local/tmp"))
        .join("profile");
    if let Err(e) = slint::android::init(app) {
        eprintln!("enclave: {e}");
        return;
    }
    if let Err(e) = start(profile, Vec::new()) {
        eprintln!("enclave: {e}");
    }
}

/// Java's `Native.start(service, profile)`: the background service starts
/// the vault with no window.
#[cfg(target_os = "android")]
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
extern "system" fn Java_com_aricummings_enclave_Native_start(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    service: jni::objects::JObject<'_>,
    profile: jni::objects::JString<'_>,
) {
    stderr_to_logcat();
    enclave_platform::phone::android::attach_service(&env, &service);
    let Ok(profile) = env.get_string(&profile).map(String::from) else {
        return;
    };
    start_headless(PathBuf::from(profile));
}

/// Java's `Native.event(kind, data)`: in front or not, a push token, a
/// wake, the activity gone.
#[cfg(target_os = "android")]
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
extern "system" fn Java_com_aricummings_enclave_Native_event(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    kind: jni::sys::jint,
    data: jni::objects::JString<'_>,
) {
    let data: String = env.get_string(&data).map(String::from).unwrap_or_default();
    enclave_platform::phone::android::event(kind, &data);
}

/// Java's `Native.helper(name, args, fd)`, in a helper process of the
/// app's (`HelperService`): run that helper on the socket the app handed
/// over. netd (in `:net`) brings Tor and the mixnet client with it as
/// threads; mediad runs in the `isolatedProcess` `:media`, with no network
/// and no files.
#[cfg(target_os = "android")]
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
extern "system" fn Java_com_aricummings_enclave_Native_helper(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    name: jni::objects::JString<'_>,
    args: jni::objects::JObjectArray<'_>,
    fd: jni::sys::jint,
) {
    register_helpers();
    let Ok(name) = env.get_string(&name).map(String::from) else {
        return;
    };
    let n = env.get_array_length(&args).unwrap_or(0);
    let args: Vec<String> = (0..n)
        .filter_map(|i| {
            let o = env.get_object_array_element(&args, i).ok()?;
            env.get_string(&jni::objects::JString::from(o))
                .ok()
                .map(String::from)
        })
        .collect();
    if name == "enclave-netd" {
        tor_once();
    }
    if let Err(e) = enclave_platform::phone::android::serve_helper(&name, args, fd) {
        eprintln!("enclave: {name}: {e}");
    }
}

/// Android sends an app's standard error nowhere: this sends it to the
/// system log under the tag "enclave", so a panic (and every `eprintln!`,
/// which never carries message content) can be read with `adb logcat`.
/// Apps can't read each other's logs.
#[cfg(target_os = "android")]
#[allow(unsafe_code)]
fn stderr_to_logcat() {
    use std::io::BufRead;
    use std::os::fd::FromRawFd;
    #[link(name = "log")]
    unsafe extern "C" {
        fn __android_log_write(
            prio: i32,
            tag: *const std::ffi::c_char,
            text: *const std::ffi::c_char,
        ) -> i32;
    }
    /// `ANDROID_LOG_WARN`.
    const WARN: i32 = 5;
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let mut fds = [0i32; 2];
        // SAFETY: `pipe` fills the two descriptors of a new pipe.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return;
        }
        // SAFETY: points descriptor 2 at the pipe's write end; both are
        // open descriptors of this process.
        if unsafe { libc::dup2(fds[1], 2) } < 0 {
            return;
        }
        // SAFETY: the read end is this file's alone from here on.
        let read = unsafe { std::fs::File::from_raw_fd(fds[0]) };
        let _ = std::thread::Builder::new()
            .name("enclave-stderr".into())
            .spawn(move || {
                for line in std::io::BufReader::new(read).lines().map_while(Result::ok) {
                    // Also for the window's "Copy log" (no terminal here).
                    enclave_platform::log::keep(&line);
                    if let Ok(text) = std::ffi::CString::new(line) {
                        // SAFETY: both are NUL-terminated strings that
                        // outlive the call.
                        unsafe { __android_log_write(WARN, c"enclave".as_ptr(), text.as_ptr()) };
                    }
                }
            });
    });
}
