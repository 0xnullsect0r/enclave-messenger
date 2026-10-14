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
    enclave_platform::process::register("enclave-netd", enclave_netd::main_with);
    enclave_platform::process::register("enclave-tord", enclave_tord::daemon::main_with);
    enclave_platform::process::register("enclave-nymd", enclave_nymd::main_with);
    enclave_platform::process::register("enclave-mediad", enclave_mediad::main_with);
    tor_variables();
    let mut args = vec![
        "enclave".into(),
        "--single-process".into(),
        "--profile".into(),
        profile.to_string_lossy().into_owned(),
    ];
    args.extend(extra);
    enclave_app::shell::run(args)
}

/// Tor's loopback port and secret for this run, and the proxy variables
/// that send the mixnet client's HTTP (nym-api, ticketbooks) through it.
/// On the desktop netd gives these to nymd's process; here they are the
/// app's own, set once, before any thread of ours reads them.
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
