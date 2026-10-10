//! Generates the design tokens and compiles the Slint UI.
#![allow(clippy::expect_used, clippy::panic)]

fn main() {
    let tokens_path = "../../design/tokens.toml";
    println!("cargo:rerun-if-changed={tokens_path}");
    let text = std::fs::read_to_string(tokens_path).expect("design/tokens.toml");
    let tokens = enclave_design::Tokens::parse(&text).expect("valid tokens");
    let failures = tokens
        .check()
        .expect("contrast pairs reference known tokens");
    assert!(failures.is_empty(), "contrast failures: {failures:#?}");
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out.join("tokens.slint"), tokens.to_slint().expect("tokens"))
        .expect("write tokens.slint");
    let config = slint_build::CompilerConfiguration::new().with_include_paths(vec![out.clone()]);
    slint_build::compile_with_config("ui/app.slint", config).expect("Slint UI compiles");
    windows_resources(&out);
}

/// On Windows the window's executable carries the app icon and its
/// version information (shown by Explorer, the taskbar and the
/// installers): a compiled resource file, written here directly (no
/// resource compiler needed), which the MSVC linker takes as an input.
fn windows_resources(out: &std::path::Path) {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if os != "windows" || env != "msvc" {
        return;
    }
    let ico_path = "../../packaging/icons/enclave.ico";
    println!("cargo:rerun-if-changed={ico_path}");
    let ico = std::fs::read(ico_path).expect("packaging/icons/enclave.ico");
    let res = res_file(&ico, env!("CARGO_PKG_VERSION"));
    let path = out.join("enclave.res");
    std::fs::write(&path, res).expect("write enclave.res");
    println!("cargo:rustc-link-arg-bin=enclave={}", path.display());
}

const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;
const RT_VERSION: u16 = 16;

/// A `.res` file: an empty entry first, then each resource with a 32-byte
/// header (type and name as numbers), its data padded to 4 bytes.
fn res_file(ico: &[u8], version: &str) -> Vec<u8> {
    let mut res = Vec::new();
    push_resource(&mut res, 0, 0, 0, &[]);
    let u16_at = |i: usize| u16::from_le_bytes([ico[i], ico[i + 1]]);
    let u32_at = |i: usize| u32::from_le_bytes([ico[i], ico[i + 1], ico[i + 2], ico[i + 3]]);
    assert!(u16_at(2) == 1, "enclave.ico is an icon file");
    let count = u16_at(4);
    // The group: the icon directory, each entry naming its image by id.
    let mut group = Vec::new();
    group.extend_from_slice(&[0, 0, 1, 0]);
    group.extend_from_slice(&count.to_le_bytes());
    for i in 0..usize::from(count) {
        let e = 6 + 16 * i;
        let (len, off) = (u32_at(e + 8), u32_at(e + 12) as usize);
        let id = u16::try_from(i + 1).expect("icon count");
        push_resource(&mut res, RT_ICON, id, 0x1010, &ico[off..off + len as usize]);
        group.extend_from_slice(&ico[e..e + 12]);
        group.extend_from_slice(&id.to_le_bytes());
    }
    push_resource(&mut res, RT_GROUP_ICON, 1, 0x1030, &group);
    push_resource(&mut res, RT_VERSION, 1, 0x0030, &version_info(version));
    res
}

fn push_resource(res: &mut Vec<u8>, kind: u16, name: u16, flags: u16, data: &[u8]) {
    let len = u32::try_from(data.len()).expect("resource size");
    res.extend_from_slice(&len.to_le_bytes());
    res.extend_from_slice(&32u32.to_le_bytes());
    for n in [kind, name] {
        res.extend_from_slice(&0xFFFFu16.to_le_bytes());
        res.extend_from_slice(&n.to_le_bytes());
    }
    res.extend_from_slice(&0u32.to_le_bytes()); // data version
    res.extend_from_slice(&flags.to_le_bytes());
    let lang: u16 = if kind == 0 { 0 } else { 0x0409 };
    res.extend_from_slice(&lang.to_le_bytes());
    res.extend_from_slice(&[0; 8]); // version, characteristics
    res.extend_from_slice(data);
    pad4(res);
}

fn pad4(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
}

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// One node of a version resource: length, value length, type, key, its
/// value and its children, each starting on 4 bytes.
fn node(key: &str, text: bool, value: &[u8], value_len: u16, children: &[Vec<u8>]) -> Vec<u8> {
    let mut v = vec![0, 0];
    v.extend_from_slice(&value_len.to_le_bytes());
    v.extend_from_slice(&u16::from(text).to_le_bytes());
    v.extend_from_slice(&utf16z(key));
    pad4(&mut v);
    v.extend_from_slice(value);
    for c in children {
        pad4(&mut v);
        v.extend_from_slice(c);
    }
    let len = u16::try_from(v.len()).expect("version resource size");
    v[..2].copy_from_slice(&len.to_le_bytes());
    v
}

fn version_info(version: &str) -> Vec<u8> {
    let core = version.split(['-', '+']).next().unwrap_or("0.0.0");
    let mut parts = core.split('.').map(|p| p.parse::<u16>().unwrap_or(0));
    let [major, minor, patch] = [(); 3].map(|()| u32::from(parts.next().unwrap_or(0)));
    let ms = (major << 16) | minor;
    let ls = patch << 16;
    let fixed: Vec<u8> = [
        0xFEEF_04BD, // signature
        0x0001_0000, // structure version
        ms,
        ls,
        ms,
        ls,
        0x3F,        // flags mask
        0,           // flags
        0x0004_0004, // VOS_NT_WINDOWS32
        1,           // VFT_APP
        0,
        0,
        0,
    ]
    .iter()
    .flat_map(|d: &u32| d.to_le_bytes())
    .collect();
    let string = |k: &str, v: &str| {
        let chars = u16::try_from(v.encode_utf16().count() + 1).expect("string length");
        node(k, true, &utf16z(v), chars, &[])
    };
    let strings = [
        string("CompanyName", "The Enclave contributors"),
        string("FileDescription", "Enclave"),
        string("FileVersion", version),
        string("InternalName", "enclave"),
        string("LegalCopyright", "GPL-3.0-only. The Enclave contributors."),
        string("OriginalFilename", "enclave.exe"),
        string("ProductName", "Enclave"),
        string("ProductVersion", version),
    ];
    let table = node("040904B0", true, &[], 0, &strings);
    let string_info = node("StringFileInfo", true, &[], 0, &[table]);
    let translation = node("Translation", false, &0x04B0_0409u32.to_le_bytes(), 4, &[]);
    let var_info = node("VarFileInfo", true, &[], 0, &[translation]);
    node(
        "VS_VERSION_INFO",
        false,
        &fixed,
        52,
        &[string_info, var_info],
    )
}
