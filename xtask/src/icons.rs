//! `cargo xtask icons [--check]`: render the app icons in `design/icon/`
//! into every file the platforms take, under `packaging/icons/`, or check
//! that the committed files match what they render to.
//!
//! - `png/enclave-N.png` (16 to 1024) from `enclave.svg`: Linux hicolor,
//!   the window icon, and the sources of the two below.
//! - `enclave.ico` (16 to 256, PNG entries): Windows executables and
//!   installers.
//! - `enclave.icns` (16 to 1024, PNG entries): the macOS bundle.
//! - `store/ios-1024.png` and `store/play-512.png` from
//!   `enclave-maskable.svg` (full bleed; the stores cut the shape).
//! - `enclave.svg` and `enclave-symbolic.svg` copied as they are (Linux
//!   scalable and symbolic icons).
//! - `android/`: launcher icons for each screen density (`mipmap-*`), the
//!   shaped icon for older Androids and, from Android 8, an adaptive icon
//!   whose layer is the full-bleed one (the launcher cuts its shape).
//! - `ios/AppIcon.appiconset`: the one 1024 px icon iOS scales from (full
//!   bleed; iOS rounds the corners).

use std::path::Path;
use std::process::ExitCode;

const PNG_SIZES: [u32; 9] = [16, 24, 32, 48, 64, 128, 256, 512, 1024];
const ICO_SIZES: [u32; 6] = [16, 24, 32, 48, 64, 256];
/// ICNS entry types holding PNG data, by edge length.
const ICNS_TYPES: [(&[u8; 4], u32); 8] = [
    (b"icp4", 16),
    (b"icp5", 32),
    (b"ic11", 32),
    (b"icp6", 64),
    (b"ic07", 128),
    (b"ic08", 256),
    (b"ic09", 512),
    (b"ic10", 1024),
];

/// Android's adaptive icon: the full-bleed picture as the background layer.
const ADAPTIVE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@mipmap/ic_launcher_layer" />
    <foreground android:drawable="@android:color/transparent" />
</adaptive-icon>
"#;

/// The iOS app icon set: one universal 1024 px image.
const IOS_CONTENTS: &str = r#"{
  "images" : [
    {
      "filename" : "icon-1024.png",
      "idiom" : "universal",
      "platform" : "ios",
      "size" : "1024x1024"
    }
  ],
  "info" : {
    "author" : "xcode",
    "version" : 1
  }
}
"#;

pub(crate) fn render(svg: &[u8], size: u32) -> Result<Vec<u8>, String> {
    use resvg::{tiny_skia, usvg};
    let tree = usvg::Tree::from_data(svg, &usvg::Options::default()).map_err(|e| e.to_string())?;
    let mut pixmap = tiny_skia::Pixmap::new(size, size).ok_or("empty icon")?;
    let scale = size as f32 / tree.size().width();
    resvg::render(
        &tree,
        tiny_skia::Transform::from_scale(scale, scale),
        &mut pixmap.as_mut(),
    );
    pixmap.encode_png().map_err(|e| e.to_string())
}

/// A Windows icon: PNG images in an ICO directory.
fn ico(images: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![0, 0, 1, 0];
    out.extend_from_slice(&(images.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * images.len();
    for (size, png) in images {
        // 256 is written as 0.
        let edge = if *size >= 256 { 0 } else { *size as u8 };
        out.extend_from_slice(&[edge, edge, 0, 0]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes());
        out.extend_from_slice(&(png.len() as u32).to_le_bytes());
        out.extend_from_slice(&(offset as u32).to_le_bytes());
        offset += png.len();
    }
    for (_, png) in images {
        out.extend_from_slice(png);
    }
    out
}

/// A macOS icon: PNG entries in an ICNS container.
fn icns(images: &[(&[u8; 4], Vec<u8>)]) -> Vec<u8> {
    let body: usize = images.iter().map(|(_, p)| 8 + p.len()).sum();
    let mut out = b"icns".to_vec();
    out.extend_from_slice(&((8 + body) as u32).to_be_bytes());
    for (kind, png) in images {
        out.extend_from_slice(*kind);
        out.extend_from_slice(&((8 + png.len()) as u32).to_be_bytes());
        out.extend_from_slice(png);
    }
    out
}

/// Every output file and its bytes.
fn outputs(design: &Path) -> Result<Vec<(String, Vec<u8>)>, String> {
    let read = |name: &str| {
        std::fs::read(design.join(name)).map_err(|e| format!("design/icon/{name}: {e}"))
    };
    let main = read("enclave.svg")?;
    let maskable = read("enclave-maskable.svg")?;
    let mono = read("enclave-monochrome.svg")?;
    let mut out = Vec::new();
    let mut pngs = std::collections::BTreeMap::new();
    for size in PNG_SIZES {
        let png = render(&main, size)?;
        out.push((format!("png/enclave-{size}.png"), png.clone()));
        pngs.insert(size, png);
    }
    let get = |s: u32| pngs.get(&s).cloned().ok_or(format!("no {s} px icon"));
    out.push((
        "enclave.ico".into(),
        ico(&ICO_SIZES
            .iter()
            .map(|&s| get(s).map(|p| (s, p)))
            .collect::<Result<Vec<_>, _>>()?),
    ));
    out.push((
        "enclave.icns".into(),
        icns(
            &ICNS_TYPES
                .iter()
                .map(|&(k, s)| get(s).map(|p| (k, p)))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    ));
    out.push(("store/ios-1024.png".into(), render(&maskable, 1024)?));
    out.push(("store/play-512.png".into(), render(&maskable, 512)?));
    for (density, px) in [
        ("mdpi", 48),
        ("hdpi", 72),
        ("xhdpi", 96),
        ("xxhdpi", 144),
        ("xxxhdpi", 192),
    ] {
        out.push((
            format!("android/mipmap-{density}/ic_launcher.png"),
            render(&main, px)?,
        ));
    }
    // Adaptive icons are 108 dp, of which the launcher shows the middle 72.
    for (density, px) in [
        ("mdpi", 108),
        ("hdpi", 162),
        ("xhdpi", 216),
        ("xxhdpi", 324),
        ("xxxhdpi", 432),
    ] {
        out.push((
            format!("android/mipmap-{density}/ic_launcher_layer.png"),
            render(&maskable, px)?,
        ));
    }
    out.push((
        "android/mipmap-anydpi-v26/ic_launcher.xml".into(),
        ADAPTIVE.as_bytes().to_vec(),
    ));
    out.push((
        "ios/AppIcon.appiconset/icon-1024.png".into(),
        render(&maskable, 1024)?,
    ));
    out.push((
        "ios/AppIcon.appiconset/Contents.json".into(),
        IOS_CONTENTS.as_bytes().to_vec(),
    ));
    out.push(("enclave.svg".into(), main));
    out.push(("enclave-symbolic.svg".into(), mono));
    Ok(out)
}

pub fn icons(check: bool) -> ExitCode {
    let root = super::root();
    let dest = root.join("packaging/icons");
    let files = match outputs(&root.join("design/icon")) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("icons: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut stale = 0;
    for (name, bytes) in &files {
        let path = dest.join(name);
        if check {
            if std::fs::read(&path).ok().as_ref() != Some(bytes) {
                eprintln!("icons: packaging/icons/{name} is not what design/icon renders to");
                stale += 1;
            }
            continue;
        }
        if let Some(dir) = path.parent()
            && let Err(e) = std::fs::create_dir_all(dir)
        {
            eprintln!("icons: {}: {e}", dir.display());
            return ExitCode::FAILURE;
        }
        if let Err(e) = std::fs::write(&path, bytes) {
            eprintln!("icons: {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    }
    if stale > 0 {
        eprintln!("icons: run `cargo xtask icons` and commit the result");
        return ExitCode::FAILURE;
    }
    println!(
        "icons {}: {} files in packaging/icons",
        if check { "ok" } else { "written" },
        files.len()
    );
    ExitCode::SUCCESS
}
