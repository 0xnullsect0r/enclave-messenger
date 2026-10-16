//! Updating Enclave, and checking the build that runs (`docs/19-ops.md`
//! §1.3–§1.5).
//!
//! The vault learns of releases from the home server over the mixnet and
//! hands the window the checked bundle ([`enclave_ipc::Out::UpdateBundle`]).
//! Where Enclave installs its own updates (Windows `.msi`, macOS `.dmg`, an
//! AppImage), "Update" downloads the release file over HTTPS, checks it
//! before anything else: its length and both hashes are in the targets two
//! maintainers signed, and Sigsum's log holds it with the witnesses'
//! cosignatures ([`enclave_update::Client::check`]). Only then does it
//! install. A package manager's install (`.deb`, `.rpm`, Flatpak, the AUR)
//! is updated by that package manager, so the app says so instead.
//!
//! "Verify this build" hashes the programs that run ([`build_hashes`]) and
//! the vault checks them against the release.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The bundle the vault last handed over.
static BUNDLE: Mutex<Option<Vec<u8>>> = Mutex::new(None);

/// Keep the vault's newest checked bundle.
pub fn set_bundle(b: Vec<u8>) {
    if let Ok(mut g) = BUNDLE.lock() {
        *g = Some(b);
    }
}

/// Where release files are downloaded from (`/download/<tag>/<file>`).
const RELEASES: &str = "https://github.com/0xnullsect0r/enclave-messenger/releases/download";

/// The programs of a desktop install, as release targets name them.
const PROGRAMS: [&str; 6] = [
    "enclave",
    "enclave-vault",
    "enclave-netd",
    "enclave-mediad",
    "enclave-tord",
    "enclave-nymd",
];

/// How this copy of Enclave was installed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Install {
    /// The Windows installer (`.msi`), for this architecture.
    Msi(&'static str),
    /// The Windows package (`.msix`), for this architecture.
    Msix(&'static str),
    /// The macOS app, replaced from the `.dmg`; the bundle's path.
    Dmg(PathBuf),
    /// An AppImage at this path, replaced in place.
    AppImage(PathBuf),
    /// Updated by something else (a package manager or app store).
    Managed(&'static str),
}

/// How this copy was installed.
pub fn install() -> Install {
    if cfg!(windows) {
        let packaged =
            std::env::current_exe().is_ok_and(|e| e.to_string_lossy().contains("\\WindowsApps\\"));
        return if packaged {
            Install::Msix(arch())
        } else {
            Install::Msi(arch())
        };
    }
    if cfg!(target_os = "macos") {
        // …/Enclave.app/Contents/MacOS/enclave
        if let Some(app) = std::env::current_exe()
            .ok()
            .and_then(|e| e.ancestors().nth(3).map(Path::to_path_buf))
            .filter(|a| a.extension().is_some_and(|x| x == "app"))
        {
            return Install::Dmg(app);
        }
        return Install::Managed(
            "This copy of Enclave isn't an installed app. Download the newest release from the Enclave website.",
        );
    }
    if let Some(p) = std::env::var_os("APPIMAGE") {
        return Install::AppImage(PathBuf::from(p));
    }
    if std::env::var_os("FLATPAK_ID").is_some() {
        return Install::Managed(
            "Enclave updates through Flathub: open your software center, or run flatpak update.",
        );
    }
    Install::Managed("Update Enclave with your system's package manager or software center.")
}

fn arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    }
}

/// The release file for `install` at `version` (`1.2.3`).
pub fn asset(install: &Install, version: &str) -> Option<String> {
    match install {
        Install::Msi(a) => Some(format!("Enclave-{version}-{a}.msi")),
        Install::Msix(a) => Some(format!("Enclave-{version}-{a}.msix")),
        Install::Dmg(_) => Some(format!("Enclave-{version}-macos.dmg")),
        Install::AppImage(_) => Some(format!("Enclave-{version}-{}.AppImage", arch())),
        Install::Managed(_) => None,
    }
}

/// Check `file` (named `name`) against the bundle the vault handed over,
/// for release `tag`.
pub fn check(tag: &str, name: &str, file: &[u8], now: u64) -> Result<(), String> {
    let Some(root) = enclave_vault::built::UPDATE_ROOT else {
        return Err("this build has no release keys to check updates with".into());
    };
    let bundle = BUNDLE
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .ok_or("no release information yet")?;
    let bundle = enclave_update::Bundle::decode(&bundle).map_err(|e| e.to_string())?;
    let mut client = enclave_update::Client::new(root, [0; 3]).map_err(|e| e.to_string())?;
    let release = bundle.apply(&mut client, now).map_err(|e| e.to_string())?;
    if release.release != tag {
        return Err(format!(
            "the release information is for {}, not {tag}",
            release.release
        ));
    }
    let proof = bundle
        .proof(name)
        .ok_or_else(|| format!("{name} has no Sigsum proof"))?;
    client
        .check(&release, name, file, proof)
        .map_err(|e| e.to_string())
}

/// Download, check and install release `tag`. `progress` hears what is
/// happening; on success the installer (or the new copy) has been started
/// and the app should quit.
pub fn update(tag: &str, progress: impl Fn(String) + Send + 'static) -> Result<(), String> {
    let install = install();
    let version = tag.trim_start_matches('v');
    let Some(name) = asset(&install, version) else {
        if let Install::Managed(how) = install {
            return Err(how.into());
        }
        return Err("this install can't update itself".into());
    };
    progress(format!("Downloading {name}…"));
    let url = format!("{RELEASES}/{tag}/{name}");
    let file = download(&url, &progress)?;
    progress("Checking the download…".into());
    check(tag, &name, &file, now())?;
    progress("Installing…".into());
    let dir = std::env::temp_dir().join(format!("enclave-update-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(&name);
    std::fs::write(&path, &file).map_err(|e| format!("{}: {e}", path.display()))?;
    install_file(&install, &path)
}

fn install_file(install: &Install, path: &Path) -> Result<(), String> {
    match install {
        Install::Msi(_) => {
            // The installer replaces the running copy once the app quits.
            std::process::Command::new("msiexec")
                .arg("/i")
                .arg(path)
                .arg("/passive")
                .spawn()
                .map(drop)
                .map_err(|e| format!("msiexec: {e}"))
        }
        Install::Msix(_) => {
            // Windows replaces the package once the app has closed.
            std::process::Command::new("powershell")
                .args(["-NoProfile", "-Command"])
                .arg(format!(
                    "Add-AppxPackage -Path '{}' -AllowUnsigned -ForceApplicationShutdown",
                    path.display()
                ))
                .spawn()
                .map(drop)
                .map_err(|e| format!("Add-AppxPackage: {e}"))
        }
        Install::Dmg(app) => replace_app(path, app),
        Install::AppImage(target) => {
            let next = target.with_extension("AppImage.new");
            std::fs::copy(path, &next).map_err(|e| format!("{}: {e}", next.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&next, std::fs::Permissions::from_mode(0o755))
                    .map_err(|e| e.to_string())?;
            }
            std::fs::rename(&next, target).map_err(|e| format!("{}: {e}", target.display()))?;
            std::process::Command::new(target)
                .spawn()
                .map(drop)
                .map_err(|e| e.to_string())
        }
        Install::Managed(how) => Err((*how).into()),
    }
}

/// Put the `.dmg`'s app in place of `app` and start it.
fn replace_app(dmg: &Path, app: &Path) -> Result<(), String> {
    let mount = dmg.with_extension("mount");
    let run = |cmd: &mut std::process::Command| -> Result<(), String> {
        let out = cmd.output().map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    };
    run(std::process::Command::new("hdiutil")
        .args(["attach", "-nobrowse", "-readonly", "-mountpoint"])
        .arg(&mount)
        .arg(dmg))?;
    let result = (|| {
        let new_app = std::fs::read_dir(&mount)
            .map_err(|e| e.to_string())?
            .flatten()
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|x| x == "app"))
            .ok_or("the disk image has no app")?;
        let staged = app.with_extension("app.new");
        let _ = std::fs::remove_dir_all(&staged);
        run(std::process::Command::new("ditto")
            .arg(&new_app)
            .arg(&staged))?;
        let old = app.with_extension("app.old");
        let _ = std::fs::remove_dir_all(&old);
        std::fs::rename(app, &old).map_err(|e| format!("{}: {e}", app.display()))?;
        if let Err(e) = std::fs::rename(&staged, app) {
            let _ = std::fs::rename(&old, app);
            return Err(format!("{}: {e}", app.display()));
        }
        let _ = std::fs::remove_dir_all(&old);
        Ok(())
    })();
    let _ = run(std::process::Command::new("hdiutil")
        .arg("detach")
        .arg(&mount));
    result?;
    run(std::process::Command::new("open").arg("-n").arg(app))
}

/// GET `url` over HTTPS (following redirects), reporting progress.
fn download(url: &str, progress: &dyn Fn(String)) -> Result<Vec<u8>, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(fetch(url, progress))
}

/// Largest release file fetched.
const MAX_FILE: usize = 512 << 20;

async fn fetch(url: &str, progress: &dyn Fn(String)) -> Result<Vec<u8>, String> {
    use http_body_util::BodyExt as _;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        enclave_tls::compat_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .enable_http1()
        .build();
    let client: hyper_util::client::legacy::Client<_, http_body_util::Empty<bytes::Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(connector);
    let mut uri: hyper::Uri = url.parse().map_err(|e| format!("{url}: {e}"))?;
    for _ in 0..6 {
        let req = hyper::Request::get(uri.clone())
            .header(hyper::header::USER_AGENT, "enclave")
            .body(http_body_util::Empty::new())
            .map_err(|e| e.to_string())?;
        let resp = client
            .request(req)
            .await
            .map_err(|e| format!("{uri}: {e}"))?;
        if resp.status().is_redirection() {
            let next = resp
                .headers()
                .get(hyper::header::LOCATION)
                .and_then(|l| l.to_str().ok())
                .and_then(|l| l.parse::<hyper::Uri>().ok())
                .filter(|u| u.scheme_str() == Some("https"))
                .ok_or("a redirect away from HTTPS")?;
            uri = next;
            continue;
        }
        if !resp.status().is_success() {
            return Err(format!("{uri}: {}", resp.status()));
        }
        let total = resp
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|l| l.to_str().ok())
            .and_then(|l| l.parse::<usize>().ok());
        let mut body = resp.into_body();
        let mut out = Vec::new();
        let mut shown = 0;
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| e.to_string())?;
            if let Some(d) = frame.data_ref() {
                out.extend_from_slice(d);
                if out.len() > MAX_FILE {
                    return Err("the download is too large".into());
                }
                if let Some(t) = total.filter(|t| *t > 0) {
                    let pct = out.len() * 100 / t;
                    if pct >= shown + 5 {
                        shown = pct;
                        progress(format!("Downloading… {pct}%"));
                    }
                }
            }
        }
        return Ok(out);
    }
    Err("too many redirects".into())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The running programs' names and hashes ("Verify this build"): each
/// program of the install that is next to this one.
pub fn build_hashes() -> Vec<enclave_ipc::FileHash> {
    let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf))
    else {
        return Vec::new();
    };
    let target = env!("ENCLAVE_RELEASE_TARGET");
    let mut out = Vec::new();
    for p in PROGRAMS {
        let file = format!("{p}{}", std::env::consts::EXE_SUFFIX);
        let Ok(bytes) = std::fs::read(dir.join(&file)) else {
            continue;
        };
        let t = enclave_update::Target::of(&format!("{file}@{target}"), &bytes);
        out.push(enclave_ipc::FileHash {
            name: t.name,
            length: t.length,
            sha256: t.sha256.to_vec(),
            sha3_512: t.sha3_512.to_vec(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_files_are_named_as_the_release_names_them() {
        assert_eq!(
            asset(&Install::Msi("x86_64"), "1.2.3").as_deref(),
            Some("Enclave-1.2.3-x86_64.msi")
        );
        assert_eq!(
            asset(
                &Install::Dmg(PathBuf::from("/Applications/Enclave.app")),
                "1.2.3"
            )
            .as_deref(),
            Some("Enclave-1.2.3-macos.dmg")
        );
        assert_eq!(asset(&Install::Managed("apt"), "1.2.3"), None);
    }

    #[test]
    fn programs_next_to_this_one_are_hashed() {
        // The test binary's folder has no Enclave programs by these names
        // unless built; whatever is found is named program@target.
        for h in build_hashes() {
            assert!(h.name.contains('@'));
            assert_eq!(h.sha256.len(), 32);
            assert_eq!(h.sha3_512.len(), 64);
        }
    }
}
