//! Release builds, their archives and installers (`release.yml`).
//!
//! * `dist [--target T]`: build every program a desktop install ships, as
//!   `repro` builds them (paths remapped, `SOURCE_DATE_EPOCH`), from both
//!   workspaces and lyrebird's Go source, gather them with the notices
//!   (and on Linux the desktop entry, AppStream metadata and icons) in
//!   `target/T/release/dist/`, and pack `target/dist/enclave-V-T.tar.gz`
//!   (`.zip` on Windows). `T` defaults to this machine; on macOS
//!   `universal2-apple-darwin` builds both architectures and joins them.
//! * `packager --target T --formats F`: the Windows installers (`wix`,
//!   `nsis`) and the AppImage (`appimage`) through cargo-packager, from
//!   what `dist` gathered, named `Enclave-V-ARCH.msi`, `-setup.exe` and
//!   `.AppImage`. `ENCLAVE_WIN_SIGN_CMD` (a command with `%1` for
//!   the file) signs the Windows programs and installers when set.
//! * `bundle-macos [--target T]`: `Enclave.app`, signed inside out with the
//!   hardened runtime and `packaging/macos` entitlements (ad hoc without
//!   `APPLE_SIGN_IDENTITY`), a `.dmg`, and with App Store Connect API keys
//!   (`ASC_KEY_PATH`, `ASC_KEY_ID`, `ASC_ISSUER_ID`) notarized and stapled.
//! * `checksums DIR`: `SHA256SUMS` and `SHA3-512SUMS` for the files in `DIR`.
//! * `version [TAG]`: print the version; with a tag (`vX.Y.Z[-pre]`), check
//!   it names the workspace version and the AppStream metadata's newest
//!   release. `version --android-code [V]`: Android's `versionCode`.
//!
//! The version in file names and packages is `ENCLAVE_VERSION` when set
//! (the release tag without its `v`), else the workspace's.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use crate::root;

/// What a desktop install ships, next to each other (the window starts the
/// vault, which starts netd and mediad; netd starts tord and nymd; tord
/// starts lyrebird).
pub const PROGRAMS: [&str; 7] = [
    "enclave",
    "enclave-vault",
    "enclave-netd",
    "enclave-mediad",
    "enclave-tord",
    "enclave-nymd",
    "lyrebird",
];

/// The main workspace's packages behind the first five.
const PACKAGES: [&str; 5] = [
    "enclave-app",
    "enclave-vault",
    "enclave-netd",
    "enclave-mediad",
    "enclave-tord",
];

const APP_ID: &str = "com.aricummings.Enclave";
const UNIVERSAL: &str = "universal2-apple-darwin";

fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn run(cmd: &mut Command) -> Result<(), String> {
    eprintln!("dist: {cmd:?}");
    let status = cmd.status().map_err(|e| format!("{cmd:?}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{cmd:?}: {status}"))
    }
}

fn output(cmd: &mut Command) -> Result<String, String> {
    let out = cmd.output().map_err(|e| format!("{cmd:?}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{cmd:?}: {}", out.status));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn exit(r: Result<(), String>) -> ExitCode {
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The workspace version (`[workspace.package] version`).
pub fn workspace_version() -> Result<String, String> {
    let text = fs::read_to_string(root().join("Cargo.toml")).map_err(|e| e.to_string())?;
    let mut in_package = false;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            in_package = l == "[workspace.package]";
        } else if in_package && let Some(v) = l.strip_prefix("version") {
            let v = v.trim().trim_start_matches('=').trim().trim_matches('"');
            return Ok(v.to_string());
        }
    }
    Err("no [workspace.package] version".into())
}

/// The version for file names and packages.
pub fn version() -> Result<String, String> {
    match std::env::var("ENCLAVE_VERSION") {
        Ok(v) if !v.is_empty() => Ok(v.trim_start_matches('v').to_string()),
        _ => workspace_version(),
    }
}

/// `X.Y.Z` of a version (installers that take numbers only).
pub fn numeric(v: &str) -> &str {
    v.split(['-', '+']).next().unwrap_or(v)
}

fn host() -> Result<String, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let rustc = Path::new(&cargo).with_file_name("rustc");
    let rustc = if rustc.exists() {
        rustc
    } else {
        PathBuf::from("rustc")
    };
    let vv = output(Command::new(rustc).arg("-vV"))?;
    vv.lines()
        .find_map(|l| l.strip_prefix("host: "))
        .map(str::to_string)
        .ok_or_else(|| "rustc -vV has no host".into())
}

fn target_arg(args: &[String]) -> Result<String, String> {
    match opt(args, "--target") {
        Some(t) => Ok(t),
        None => host(),
    }
}

fn exe(target: &str, name: &str) -> String {
    if target.contains("windows") {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

/// Where cargo puts `target`'s release build.
fn release_dir(target: &str) -> PathBuf {
    root().join("target").join(target).join("release")
}

/// The gathered install for `target`.
pub fn dist_dir(target: &str) -> PathBuf {
    release_dir(target).join("dist")
}

fn source_date_epoch() -> String {
    std::env::var("SOURCE_DATE_EPOCH").unwrap_or_else(|_| {
        output(
            Command::new("git")
                .current_dir(root())
                .args(["log", "-1", "--format=%ct"]),
        )
        .unwrap_or_else(|_| "1700000000".into())
    })
}

/// Build the programs for one real target into `target/T/release`.
fn build(target: &str) -> Result<(), String> {
    let root = root();
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let cargo_home = std::env::var("CARGO_HOME").unwrap_or_else(|_| {
        std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map(|h| format!("{h}/.cargo"))
            .unwrap_or_default()
    });
    let mut flags = format!(
        "--remap-path-prefix={cargo_home}=/cargo --remap-path-prefix={}=/src",
        root.display()
    );
    // Windows: the C runtime linked in, so the programs start on a system
    // without the Visual C++ redistributable.
    if target.contains("windows-msvc") {
        flags.push_str(" -C target-feature=+crt-static");
    }
    let epoch = source_date_epoch();
    let env = |c: &mut Command| {
        c.env("RUSTFLAGS", &flags)
            .env("CARGO_INCREMENTAL", "0")
            .env("SOURCE_DATE_EPOCH", &epoch);
        if target.contains("apple") {
            // macOS 12: what lyrebird's Go toolchain (1.26) supports.
            c.env("MACOSX_DEPLOYMENT_TARGET", "12.0");
        }
    };
    let mut c = Command::new(&cargo);
    c.current_dir(&root)
        .args(["build", "--release", "--locked", "--target", target]);
    for p in PACKAGES {
        c.args(["-p", p]);
    }
    env(&mut c);
    run(&mut c)?;
    let mut c = Command::new(&cargo);
    c.current_dir(root.join("nym")).args([
        "build",
        "--release",
        "--locked",
        "--target",
        target,
        "-p",
        "enclave-nymd",
    ]);
    env(&mut c);
    run(&mut c)?;
    let nymd = exe(target, "enclave-nymd");
    let from = root
        .join("nym/target")
        .join(target)
        .join("release")
        .join(&nymd);
    fs::create_dir_all(release_dir(target)).map_err(|e| e.to_string())?;
    fs::copy(&from, release_dir(target).join(&nymd))
        .map_err(|e| format!("{}: {e}", from.display()))?;
    // lyrebird (Go), for Snowflake and WebTunnel bridges.
    let (goos, goarch) = go_target(target)?;
    run(Command::new(bash())
        .current_dir(&root)
        .arg("ci/tor/lyrebird.sh")
        .arg("build")
        // Relative to the root, in `/` form (the script runs in Git's bash
        // on Windows).
        .arg(format!(
            "target/{target}/release/{}",
            exe(target, "lyrebird")
        ))
        .args([goos, goarch])
        .env("SOURCE_DATE_EPOCH", &epoch))
}

fn go_target(target: &str) -> Result<(&'static str, &'static str), String> {
    let os = if target.contains("linux") {
        "linux"
    } else if target.contains("apple-darwin") {
        "darwin"
    } else if target.contains("windows") {
        "windows"
    } else {
        return Err(format!("no Go target for {target}"));
    };
    let arch = if target.starts_with("x86_64") {
        "amd64"
    } else if target.starts_with("aarch64") {
        "arm64"
    } else {
        return Err(format!("no Go architecture for {target}"));
    };
    Ok((os, arch))
}

/// Both macOS architectures, joined with `lipo`.
fn build_universal() -> Result<(), String> {
    let parts = ["aarch64-apple-darwin", "x86_64-apple-darwin"];
    for t in parts {
        build(t)?;
    }
    let out = release_dir(UNIVERSAL);
    fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    for p in PROGRAMS {
        let mut c = Command::new("lipo");
        c.arg("-create").arg("-output").arg(out.join(p));
        for t in parts {
            c.arg(release_dir(t).join(p));
        }
        run(&mut c)?;
    }
    Ok(())
}

fn copy(from: &Path, to: &Path) -> Result<(), String> {
    if let Some(d) = to.parent() {
        fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    fs::copy(from, to)
        .map(|_| ())
        .map_err(|e| format!("{} → {}: {e}", from.display(), to.display()))
}

/// Gather the install for `target` in its `dist` folder.
fn stage(target: &str) -> Result<PathBuf, String> {
    let root = root();
    let dir = dist_dir(target);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    for p in PROGRAMS {
        let name = exe(target, p);
        copy(&release_dir(target).join(&name), &dir.join(&name))?;
    }
    copy(&root.join("LICENSE"), &dir.join("LICENSE"))?;
    copy(&root.join("README.md"), &dir.join("README.md"))?;
    copy(
        &root.join("crates/enclave-app/licenses.txt"),
        &dir.join("THIRD-PARTY-NOTICES.txt"),
    )?;
    if target.contains("linux") {
        let share = dir.join("share");
        let linux = root.join("packaging/linux");
        copy(
            &linux.join(format!("{APP_ID}.desktop")),
            &share.join(format!("applications/{APP_ID}.desktop")),
        )?;
        copy(
            &linux.join(format!("{APP_ID}.metainfo.xml")),
            &share.join(format!("metainfo/{APP_ID}.metainfo.xml")),
        )?;
        let icons = root.join("packaging/icons");
        for size in [16, 24, 32, 48, 64, 128, 256, 512] {
            copy(
                &icons.join(format!("png/enclave-{size}.png")),
                &share.join(format!("icons/hicolor/{size}x{size}/apps/{APP_ID}.png")),
            )?;
        }
        copy(
            &icons.join("enclave.svg"),
            &share.join(format!("icons/hicolor/scalable/apps/{APP_ID}.svg")),
        )?;
        copy(
            &icons.join("enclave-symbolic.svg"),
            &share.join(format!("icons/hicolor/symbolic/apps/{APP_ID}-symbolic.svg")),
        )?;
    }
    Ok(dir)
}

/// Every file under `dir`, relative, sorted (so archives don't depend on
/// the order the file system lists them in).
fn files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    fn walk(base: &Path, d: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
        for e in fs::read_dir(d).map_err(|e| e.to_string())? {
            let p = e.map_err(|e| e.to_string())?.path();
            if p.is_dir() {
                walk(base, &p, out)?;
            } else if let Ok(rel) = p.strip_prefix(base) {
                out.push(rel.to_path_buf());
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out)?;
    out.sort();
    Ok(out)
}

fn is_program(rel: &Path) -> bool {
    let name = rel.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    let stem = name.trim_end_matches(".exe");
    PROGRAMS.contains(&stem)
}

fn unix_path(p: &Path) -> String {
    p.components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// A `.tar.gz` of `dir` under `top/`: fixed times, owners and modes.
fn tar_gz(dir: &Path, top: &str, out: &Path) -> Result<(), String> {
    let epoch: u64 = source_date_epoch().parse().unwrap_or(1_700_000_000);
    let file = fs::File::create(out).map_err(|e| e.to_string())?;
    let gz = flate2::GzBuilder::new()
        .mtime(0)
        .write(file, flate2::Compression::best());
    let mut tar = tar::Builder::new(gz);
    tar.mode(tar::HeaderMode::Deterministic);
    for rel in files(dir)? {
        let data = fs::read(dir.join(&rel)).map_err(|e| e.to_string())?;
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(if is_program(&rel) { 0o755 } else { 0o644 });
        h.set_mtime(epoch);
        h.set_uid(0);
        h.set_gid(0);
        h.set_entry_type(tar::EntryType::Regular);
        let path = format!("{top}/{}", unix_path(&rel));
        tar.append_data(&mut h, path, data.as_slice())
            .map_err(|e| e.to_string())?;
    }
    let gz = tar.into_inner().map_err(|e| e.to_string())?;
    gz.finish().map_err(|e| e.to_string())?;
    Ok(())
}

/// A `.zip` of `dir` under `top/` (deflate; fixed times).
fn zip(dir: &Path, top: &str, out: &Path) -> Result<(), String> {
    // 1980-01-01 00:00, the earliest DOS time: fixed, so builds compare.
    const DOS_DATE: u16 = (1 << 5) | 1;
    let mut body = Vec::new();
    let mut central = Vec::new();
    let mut count: u16 = 0;
    for rel in files(dir)? {
        let data = fs::read(dir.join(&rel)).map_err(|e| e.to_string())?;
        let name = format!("{top}/{}", unix_path(&rel));
        let crc = crc32fast::hash(&data);
        let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(&data).map_err(|e| e.to_string())?;
        let packed = enc.finish().map_err(|e| e.to_string())?;
        let size = |n: usize| u32::try_from(n).map_err(|_| format!("{name}: over 4 GiB"));
        let (csize, usize_) = (size(packed.len())?, size(data.len())?);
        let offset = size(body.len())?;
        let name_len = u16::try_from(name.len()).map_err(|_| "name too long".to_string())?;
        let common = |v: &mut Vec<u8>| {
            v.extend_from_slice(&20u16.to_le_bytes()); // version needed
            v.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 names
            v.extend_from_slice(&8u16.to_le_bytes()); // deflate
            v.extend_from_slice(&0u16.to_le_bytes()); // time
            v.extend_from_slice(&DOS_DATE.to_le_bytes());
            v.extend_from_slice(&crc.to_le_bytes());
            v.extend_from_slice(&csize.to_le_bytes());
            v.extend_from_slice(&usize_.to_le_bytes());
            v.extend_from_slice(&name_len.to_le_bytes());
            v.extend_from_slice(&0u16.to_le_bytes()); // extra
        };
        body.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        common(&mut body);
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(&packed);
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes()); // made by
        common(&mut central);
        central.extend_from_slice(&[0; 8]); // comment, disk, internal attributes
        central.extend_from_slice(&0u32.to_le_bytes()); // external attributes
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
        count = count.checked_add(1).ok_or("too many files")?;
    }
    let cd_offset = u32::try_from(body.len()).map_err(|_| "over 4 GiB".to_string())?;
    let cd_size = u32::try_from(central.len()).map_err(|_| "over 4 GiB".to_string())?;
    body.extend_from_slice(&central);
    body.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    body.extend_from_slice(&[0; 4]); // disks
    body.extend_from_slice(&count.to_le_bytes());
    body.extend_from_slice(&count.to_le_bytes());
    body.extend_from_slice(&cd_size.to_le_bytes());
    body.extend_from_slice(&cd_offset.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    fs::write(out, body).map_err(|e| e.to_string())
}

/// bash: on Windows Git's, not the `bash.exe` in System32 that starts WSL
/// (which runners don't have a distribution for).
fn bash() -> PathBuf {
    if cfg!(windows) {
        let candidates = [
            std::env::var_os("ProgramFiles").map(|p| PathBuf::from(p).join("Git/bin/bash.exe")),
            Some(PathBuf::from("C:/Program Files/Git/bin/bash.exe")),
        ];
        if let Some(git) = candidates.into_iter().flatten().find(|p| p.exists()) {
            return git;
        }
    }
    PathBuf::from("bash")
}

fn out_dir() -> Result<PathBuf, String> {
    let d = root().join("target/dist");
    fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    Ok(d)
}

pub fn dist(args: &[String]) -> ExitCode {
    exit((|| {
        let target = target_arg(args)?;
        if !args.iter().any(|a| a == "--no-build") {
            if target == UNIVERSAL {
                build_universal()?;
            } else {
                build(&target)?;
            }
        }
        let dir = stage(&target)?;
        let v = version()?;
        let top = format!("enclave-{v}-{target}");
        let out = out_dir()?;
        let file = if target.contains("windows") {
            let f = out.join(format!("{top}.zip"));
            zip(&dir, &top, &f)?;
            f
        } else {
            let f = out.join(format!("{top}.tar.gz"));
            tar_gz(&dir, &top, &f)?;
            f
        };
        eprintln!("dist: {}", file.display());
        Ok(())
    })())
}

/// cargo-packager's configuration for what `dist` gathered.
fn packager_config(target: &str, formats: &[&str]) -> Result<serde_json::Value, String> {
    let root = root();
    let v = version()?;
    let dir = dist_dir(target);
    let binaries: Vec<serde_json::Value> = PROGRAMS
        .iter()
        .map(|p| serde_json::json!({ "path": p, "main": *p == "enclave" }))
        .collect();
    let mut cfg = serde_json::json!({
        // Named here: without it cargo-packager 0.11 looks for the package
        // name by changing into the config file's path, which fails.
        "name": "enclave",
        "productName": "Enclave",
        "version": numeric(&v),
        "identifier": APP_ID,
        "description": "Private messages without a phone number",
        "homepage": "https://github.com/0xnullsect0r/enclave-messenger",
        "authors": ["The Enclave contributors"],
        "publisher": "The Enclave contributors",
        "copyright": "GPL-3.0-only. The Enclave contributors.",
        "licenseFile": root.join("LICENSE"),
        "category": "SocialNetworking",
        "binaries": binaries,
        "binariesDir": dir,
        "outDir": out_dir()?,
        "targetTriple": target,
        "formats": formats,
        "icons": [
            root.join("packaging/icons/enclave.ico"),
            root.join("packaging/icons/png/enclave-256.png"),
            root.join("packaging/icons/png/enclave-128.png"),
            root.join("packaging/icons/png/enclave-32.png"),
        ],
        "resources": [
            { "src": dir.join("THIRD-PARTY-NOTICES.txt"), "target": "THIRD-PARTY-NOTICES.txt" },
        ],
        "nsis": {
            "installMode": "currentUser",
            "installerIcon": root.join("packaging/icons/enclave.ico"),
            "compression": "lzma",
        },
        "wix": {},
        "windows": { "allowDowngrades": false },
    });
    if let Ok(cmd) = std::env::var("ENCLAVE_WIN_SIGN_CMD")
        && !cmd.is_empty()
    {
        cfg["windows"]["signCommand"] = serde_json::Value::String(cmd);
    }
    Ok(cfg)
}

pub fn packager(args: &[String]) -> ExitCode {
    exit((|| {
        let target = target_arg(args)?;
        let formats = opt(args, "--formats").ok_or("--formats wix,nsis | appimage")?;
        let formats: Vec<&str> = formats.split(',').collect();
        let cfg = packager_config(&target, &formats)?;
        let path = release_dir(&target).join("packager.json");
        fs::write(
            &path,
            serde_json::to_vec_pretty(&cfg).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let out = out_dir()?;
        let before: Vec<PathBuf> = fs::read_dir(&out)
            .map_err(|e| e.to_string())?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        run(Command::new(cargo)
            .current_dir(root())
            .args(["packager", "--release", "--config"])
            .arg(&path))?;
        // cargo-packager names files after the program and the numeric
        // version; the release names them like the others.
        let arch = target.split('-').next().unwrap_or_default();
        let v = version()?;
        for e in fs::read_dir(&out).map_err(|e| e.to_string())? {
            let p = e.map_err(|e| e.to_string())?.path();
            if before.contains(&p) {
                continue;
            }
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            let suffix = [".msi", "-setup.exe", ".AppImage"]
                .into_iter()
                .find(|s| name.ends_with(s));
            if let Some(suffix) = suffix {
                let to = out.join(format!("Enclave-{v}-{arch}{suffix}"));
                fs::rename(&p, &to).map_err(|e| e.to_string())?;
                eprintln!("packager: {}", to.display());
            }
        }
        Ok(())
    })())
}

/// The MSIX package's manifest (`docs/19-ops.md` §1.4). Unsigned, the
/// publisher carries the OID Windows looks for to let `Add-AppxPackage
/// -AllowUnsigned` install it; with a certificate, `ENCLAVE_MSIX_PUBLISHER`
/// is its subject and `ENCLAVE_WIN_SIGN_CMD` signs the package.
fn msix_manifest(version: &str, arch: &str, publisher: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
         IgnorableNamespaces="uap rescap">
  <Identity Name="{APP_ID}" Publisher="{publisher}" Version="{version}.0" ProcessorArchitecture="{arch}"/>
  <Properties>
    <DisplayName>Enclave</DisplayName>
    <PublisherDisplayName>The Enclave contributors</PublisherDisplayName>
    <Logo>Assets\StoreLogo.png</Logo>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.19041.0" MaxVersionTested="10.0.26100.0"/>
  </Dependencies>
  <Resources>
    <Resource Language="en-us"/>
  </Resources>
  <Applications>
    <Application Id="Enclave" Executable="enclave.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="Enclave" Description="Private messages without a phone number"
        BackgroundColor="transparent" Square150x150Logo="Assets\Square150x150Logo.png"
        Square44x44Logo="Assets\Square44x44Logo.png"/>
    </Application>
  </Applications>
  <Capabilities>
    <rescap:Capability Name="runFullTrust"/>
    <Capability Name="internetClient"/>
  </Capabilities>
</Package>
"#
    )
}

/// The publisher an unsigned MSIX may have.
const UNSIGNED_PUBLISHER: &str =
    "CN=The Enclave contributors, OID.2.25.311729368913984317654407730594956997722=1";

/// `cargo xtask msix --target T`: the MSIX package of what `dist`
/// gathered, `Enclave-V-ARCH.msix` (Windows, with the SDK's makeappx).
pub fn msix(args: &[String]) -> ExitCode {
    exit((|| {
        let target = target_arg(args)?;
        let v = version()?;
        let arch = target.split('-').next().unwrap_or_default();
        let msix_arch = if arch == "aarch64" { "arm64" } else { "x64" };
        let stage = release_dir(&target).join("msix");
        let _ = fs::remove_dir_all(&stage);
        fs::create_dir_all(stage.join("Assets")).map_err(|e| e.to_string())?;
        let dir = dist_dir(&target);
        for p in PROGRAMS {
            let f = format!("{p}.exe");
            fs::copy(dir.join(&f), stage.join(&f)).map_err(|e| format!("{f}: {e}"))?;
        }
        fs::copy(
            dir.join("THIRD-PARTY-NOTICES.txt"),
            stage.join("THIRD-PARTY-NOTICES.txt"),
        )
        .map_err(|e| e.to_string())?;
        let svg = fs::read(root().join("design/icon/enclave.svg")).map_err(|e| e.to_string())?;
        for (name, size) in [
            ("Square44x44Logo.png", 44),
            ("Square150x150Logo.png", 150),
            ("StoreLogo.png", 50),
        ] {
            let png = crate::icons::render(&svg, size)?;
            fs::write(stage.join("Assets").join(name), png).map_err(|e| e.to_string())?;
        }
        let publisher = std::env::var("ENCLAVE_MSIX_PUBLISHER")
            .ok()
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| UNSIGNED_PUBLISHER.into());
        // MSIX versions are four numbers; a pre-release counts as its
        // release.
        fs::write(
            stage.join("AppxManifest.xml"),
            msix_manifest(numeric(&v), msix_arch, &publisher),
        )
        .map_err(|e| e.to_string())?;
        let out = out_dir()?.join(format!("Enclave-{v}-{arch}.msix"));
        run(Command::new(makeappx()?)
            .args(["pack", "/o", "/d"])
            .arg(&stage)
            .arg("/p")
            .arg(&out))?;
        if let Ok(cmd) = std::env::var("ENCLAVE_WIN_SIGN_CMD")
            && !cmd.is_empty()
        {
            let line = cmd.replace("%1", &out.display().to_string());
            run(Command::new("cmd").args(["/C", &line]))?;
        }
        eprintln!("msix: {}", out.display());
        Ok(())
    })())
}

/// The Windows SDK's makeappx.exe (newest SDK first), or `makeappx` on the
/// PATH.
fn makeappx() -> Result<PathBuf, String> {
    let kits = PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10\bin");
    let mut found: Vec<PathBuf> = fs::read_dir(&kits)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path().join("x64").join("makeappx.exe"))
        .filter(|p| p.is_file())
        .collect();
    found.sort();
    Ok(found.pop().unwrap_or_else(|| PathBuf::from("makeappx")))
}

/// SHA-256 and SHA3-512 sums of the files in `dir`, in the format of
/// `sha256sum` (`HEX  NAME`).
pub fn checksums(args: &[String]) -> ExitCode {
    use sha2::Digest as _;
    exit((|| {
        let dir = PathBuf::from(args.first().ok_or("checksums DIR")?);
        let mut names: Vec<String> = fs::read_dir(&dir)
            .map_err(|e| e.to_string())?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| !n.ends_with("SUMS"))
            .collect();
        names.sort();
        let (mut s256, mut s3) = (String::new(), String::new());
        for n in &names {
            let data = fs::read(dir.join(n)).map_err(|e| e.to_string())?;
            let h = sha2::Sha256::digest(&data);
            let h3 = sha3::Sha3_512::digest(&data);
            s256.push_str(&format!("{}  {n}\n", hex(&h)));
            s3.push_str(&format!("{}  {n}\n", hex(&h3)));
        }
        fs::write(dir.join("SHA256SUMS"), s256).map_err(|e| e.to_string())?;
        fs::write(dir.join("SHA3-512SUMS"), s3).map_err(|e| e.to_string())?;
        eprintln!("checksums: {} files in {}", names.len(), dir.display());
        Ok(())
    })())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The newest release in the AppStream metadata.
fn metainfo_release() -> Result<String, String> {
    let p = root().join(format!("packaging/linux/{APP_ID}.metainfo.xml"));
    let text = fs::read_to_string(&p).map_err(|e| e.to_string())?;
    let at = text
        .find("<release version=\"")
        .ok_or("no <release> in the metainfo")?;
    let rest = &text[at + "<release version=\"".len()..];
    Ok(rest.split('"').next().unwrap_or_default().to_string())
}

/// Check a release tag against the workspace: `vX.Y.Z` is the workspace
/// version; `vX.Y.Z-pre` (a release candidate) its `X.Y.Z` when the
/// workspace has no pre-release part, or exactly.
pub fn check_tag(tag: &str, workspace: &str, metainfo: &str) -> Result<(), String> {
    let t = tag
        .strip_prefix('v')
        .ok_or_else(|| format!("{tag}: a release tag starts with v"))?;
    let core_ok = numeric(t) == numeric(workspace);
    let exact = t == workspace;
    let pre_on_release = t.contains('-') && !workspace.contains('-') && core_ok;
    if !(exact || pre_on_release) {
        return Err(format!(
            "{tag} doesn't name the workspace version {workspace}"
        ));
    }
    if numeric(metainfo) != numeric(workspace) {
        return Err(format!(
            "the AppStream metadata's newest release is {metainfo}, the workspace is {workspace}"
        ));
    }
    Ok(())
}

/// Android's `versionCode` for a version: X.Y.Z as XXYYZZ, then two
/// digits that put release candidates before their release (`rc.N` is N,
/// another pre-release 0, the release 99), so every later build is larger.
pub fn android_code(v: &str) -> Result<u32, String> {
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (v.split('+').next().unwrap_or(v), None),
    };
    let n: Vec<u32> = core
        .split('.')
        .map(|p| p.parse().map_err(|_| format!("{v}: not X.Y.Z")))
        .collect::<Result<_, _>>()?;
    let [x, y, z] = n[..] else {
        return Err(format!("{v}: not X.Y.Z"));
    };
    if x > 2000 || y > 99 || z > 99 {
        return Err(format!("{v}: too large for a versionCode"));
    }
    let tail = match pre {
        None => 99,
        Some(p) => p
            .strip_prefix("rc.")
            .and_then(|n| n.parse::<u32>().ok())
            .map_or(0, |n| n.min(98)),
    };
    Ok(x * 1_000_000 + y * 10_000 + z * 100 + tail)
}

pub fn version_task(args: &[String]) -> ExitCode {
    if args.first().map(String::as_str) == Some("--android-code") {
        return exit((|| {
            let v = match args.get(1) {
                Some(v) => v.trim_start_matches('v').to_string(),
                None => version()?,
            };
            println!("{}", android_code(&v)?);
            Ok(())
        })());
    }
    exit((|| {
        let w = workspace_version()?;
        if let Some(tag) = args.first() {
            check_tag(tag, &w, &metainfo_release()?)?;
        }
        println!("{w}");
        Ok(())
    })())
}

/// The bundle's `Info.plist`, with the version filled in.
fn info_plist(v: &str) -> Result<String, String> {
    let t =
        fs::read_to_string(root().join("packaging/macos/Info.plist")).map_err(|e| e.to_string())?;
    Ok(t.replace("@VERSION@", numeric(v)))
}

pub fn bundle_macos(args: &[String]) -> ExitCode {
    exit((|| {
        let target = opt(args, "--target").unwrap_or_else(|| UNIVERSAL.to_string());
        let v = version()?;
        let dir = dist_dir(&target);
        let work = release_dir(&target).join("bundle");
        let _ = fs::remove_dir_all(&work);
        let app = work.join("Enclave.app");
        let contents = app.join("Contents");
        for p in PROGRAMS {
            copy(&dir.join(p), &contents.join("MacOS").join(p))?;
        }
        let res = contents.join("Resources");
        copy(
            &root().join("packaging/icons/enclave.icns"),
            &res.join("enclave.icns"),
        )?;
        copy(
            &dir.join("THIRD-PARTY-NOTICES.txt"),
            &res.join("THIRD-PARTY-NOTICES.txt"),
        )?;
        copy(&dir.join("LICENSE"), &res.join("LICENSE"))?;
        fs::write(contents.join("Info.plist"), info_plist(&v)?).map_err(|e| e.to_string())?;
        fs::write(contents.join("PkgInfo"), "APPL????").map_err(|e| e.to_string())?;
        sign_app(&app, &work)?;
        // The disk image: the app and a link to /Applications.
        let stage = work.join("dmg");
        fs::create_dir_all(&stage).map_err(|e| e.to_string())?;
        run(Command::new("ditto")
            .arg(&app)
            .arg(stage.join("Enclave.app")))?;
        #[cfg(unix)]
        std::os::unix::fs::symlink("/Applications", stage.join("Applications"))
            .map_err(|e| e.to_string())?;
        let out = out_dir()?;
        let dmg = out.join(format!("Enclave-{v}-macos.dmg"));
        let _ = fs::remove_file(&dmg);
        run(Command::new("hdiutil")
            .args([
                "create",
                "-volname",
                "Enclave",
                "-fs",
                "HFS+",
                "-format",
                "UDZO",
                "-srcfolder",
            ])
            .arg(&stage)
            .arg(&dmg))?;
        if let Ok(id) = std::env::var("APPLE_SIGN_IDENTITY")
            && !id.is_empty()
        {
            run(Command::new("codesign")
                .args(["--force", "--timestamp", "--sign", &id])
                .arg(&dmg))?;
        }
        if let (Ok(key), Ok(key_id), Ok(issuer)) = (
            std::env::var("ASC_KEY_PATH"),
            std::env::var("ASC_KEY_ID"),
            std::env::var("ASC_ISSUER_ID"),
        ) {
            run(Command::new("xcrun")
                .args(["notarytool", "submit"])
                .arg(&dmg)
                .args([
                    "--key", &key, "--key-id", &key_id, "--issuer", &issuer, "--wait",
                ]))?;
            run(Command::new("xcrun").args(["stapler", "staple"]).arg(&dmg))?;
            run(Command::new("xcrun").args(["stapler", "staple"]).arg(&app))?;
        } else {
            eprintln!("bundle-macos: no App Store Connect key, so not notarized");
        }
        let zip = out.join(format!("Enclave-{v}-macos.app.zip"));
        let _ = fs::remove_file(&zip);
        run(Command::new("ditto")
            .args(["-c", "-k", "--sequesterRsrc", "--keepParent"])
            .arg(&app)
            .arg(&zip))?;
        eprintln!("bundle-macos: {} and {}", dmg.display(), zip.display());
        Ok(())
    })())
}

/// Sign every program, then the bundle, with the hardened runtime and each
/// one's entitlements (`packaging/macos/README.md`). Without
/// `APPLE_SIGN_IDENTITY` the signature is ad hoc, which runs on this Mac
/// only. The vault's Keychain group (`enclave-vault.entitlements`) is a
/// restricted entitlement that only a provisioning profile can allow, and a
/// profile can only be embedded in a bundle, so it is used only with
/// `ENCLAVE_MAC_KEYCHAIN_GROUP=1`, once the vault is its own helper bundle;
/// until then the vault keeps its secret in the login Keychain unwrapped.
fn sign_app(app: &Path, work: &Path) -> Result<(), String> {
    let mac = root().join("packaging/macos");
    let id = std::env::var("APPLE_SIGN_IDENTITY").unwrap_or_default();
    let real = !id.is_empty();
    let identity = if real { id.as_str() } else { "-" };
    let team = std::env::var("APPLE_TEAM_ID").unwrap_or_default();
    let group = std::env::var("ENCLAVE_MAC_KEYCHAIN_GROUP").is_ok_and(|v| v == "1");
    let vault_ent = work.join("enclave-vault.entitlements");
    let text =
        fs::read_to_string(mac.join("enclave-vault.entitlements")).map_err(|e| e.to_string())?;
    if real && team.is_empty() {
        return Err("APPLE_TEAM_ID is needed with APPLE_SIGN_IDENTITY".into());
    }
    fs::write(&vault_ent, text.replace("TEAMID", &team)).map_err(|e| e.to_string())?;
    let sign = |path: &Path, ent: Option<&Path>| -> Result<(), String> {
        let mut c = Command::new("codesign");
        c.args(["--force", "--options", "runtime", "--sign", identity]);
        if real {
            c.arg("--timestamp");
        }
        if let Some(e) = ent {
            c.arg("--entitlements").arg(e);
        }
        run(c.arg(path))
    };
    let macos = app.join("Contents/MacOS");
    for p in PROGRAMS {
        let ent = match p {
            "enclave" => continue,
            "enclave-vault" if real && group => Some(vault_ent.clone()),
            _ => Some(mac.join("helper.entitlements")),
        };
        sign(&macos.join(p), ent.as_deref())?;
    }
    let main_ent = mac.join("enclave.entitlements");
    sign(&macos.join("enclave"), Some(&main_ent))?;
    sign(app, Some(&main_ent))?;
    run(Command::new("codesign")
        .args(["--verify", "--deep", "--strict", "--verbose=2"])
        .arg(app))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_name_the_workspace_version() {
        assert!(check_tag("v1.2.3", "1.2.3", "1.2.3").is_ok());
        assert!(check_tag("v1.2.3-rc.1", "1.2.3", "1.2.3").is_ok());
        assert!(check_tag("v1.2.3-rc.1", "1.2.3-rc.1", "1.2.3").is_ok());
        assert!(check_tag("v1.2.3-rc.2", "1.2.3-rc.1", "1.2.3").is_err());
        assert!(check_tag("v1.2.4", "1.2.3", "1.2.3").is_err());
        assert!(check_tag("1.2.3", "1.2.3", "1.2.3").is_err());
        assert!(check_tag("v1.2.3", "1.2.3", "1.2.2").is_err());
        assert_eq!(numeric("0.1.0-rc.1"), "0.1.0");
    }

    #[test]
    fn android_codes_grow() {
        let codes: Vec<u32> = [
            "0.1.0-dryrun.abc",
            "0.1.0-rc.1",
            "0.1.0-rc.2",
            "0.1.0",
            "0.1.1",
            "1.0.0",
        ]
        .iter()
        .map(|v| android_code(v).unwrap())
        .collect();
        assert!(codes.windows(2).all(|w| w[0] < w[1]), "{codes:?}");
        assert_eq!(android_code("1.2.3").unwrap(), 1_020_399);
        assert!(android_code("1.2").is_err());
    }

    #[test]
    fn archives_are_the_same_twice() {
        let dir = std::env::temp_dir().join(format!("enclave-dist-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("in/share/x")).unwrap();
        fs::write(dir.join("in/enclave"), b"program").unwrap();
        fs::write(dir.join("in/share/x/a.txt"), b"text text text text").unwrap();
        for (i, out) in ["a", "b"].iter().enumerate() {
            tar_gz(&dir.join("in"), "top", &dir.join(format!("{out}.tar.gz"))).unwrap();
            zip(&dir.join("in"), "top", &dir.join(format!("{out}.zip"))).unwrap();
            let _ = i;
        }
        for ext in ["tar.gz", "zip"] {
            assert_eq!(
                fs::read(dir.join(format!("a.{ext}"))).unwrap(),
                fs::read(dir.join(format!("b.{ext}"))).unwrap()
            );
        }
        // The tar lists both files with their modes.
        let gz = flate2::read::GzDecoder::new(fs::File::open(dir.join("a.tar.gz")).unwrap());
        let mut t = tar::Archive::new(gz);
        let entries: Vec<(String, u32)> = t
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.path().unwrap().display().to_string(),
                    e.header().mode().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            entries,
            [
                ("top/enclave".into(), 0o755),
                ("top/share/x/a.txt".into(), 0o644)
            ]
        );
        let _ = fs::remove_dir_all(dir);
    }
}
