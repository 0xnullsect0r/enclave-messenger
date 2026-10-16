//! Release builds name the foundation's public key, the server list and
//! the release root to ship with (`ENCLAVE_FOUNDATION_PUB`,
//! `ENCLAVE_SERVER_LIST`, `ENCLAVE_UPDATE_ROOT`: paths to the files
//! `enclave-admin` writes), or else the repository's copies once they exist
//! (`packaging/foundation/foundation.pub`, `packaging/foundation/server-list.bin`,
//! `packaging/update/root.bin`). Without them the build has none, and a
//! server-mode profile needs `--foundation` / `--server-list` to use one.

use std::path::{Path, PathBuf};

/// Stop the build: a release asked for files that aren't there.
fn fail(msg: &str) -> ! {
    eprintln!("enclave-vault build: {msg}");
    std::process::exit(1)
}

fn embed(var: &str, name: &str, default: &str, out: &Path, code: &mut String) {
    println!("cargo:rerun-if-env-changed={var}");
    // Unset: the file the repository keeps once it exists (the foundation
    // and the maintainers commit them; External Gates G2 and G5).
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let fallback = manifest.join("../..").join(default);
    println!("cargo:rerun-if-changed={}", fallback.display());
    let chosen = match std::env::var(var) {
        Ok(p) if !p.is_empty() => Ok(p),
        _ if fallback.is_file() => Ok(fallback.display().to_string()),
        other => other,
    };
    let value = match chosen {
        Ok(p) if !p.is_empty() => {
            println!("cargo:rerun-if-changed={p}");
            let dest = out.join(name.to_lowercase());
            if let Err(e) = std::fs::copy(&p, &dest) {
                fail(&format!("{var}={p}: {e}"));
            }
            format!("Some(include_bytes!({:?}))", dest.display().to_string())
        }
        _ => "None".to_string(),
    };
    code.push_str(&format!(
        "/// Built in from `{var}`, if set.\npub const {name}: Option<&[u8]> = {value};\n"
    ));
}

fn main() {
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_default());
    let mut code = String::new();
    embed(
        "ENCLAVE_FOUNDATION_PUB",
        "FOUNDATION_PUB",
        "packaging/foundation/foundation.pub",
        &out,
        &mut code,
    );
    embed(
        "ENCLAVE_SERVER_LIST",
        "SERVER_LIST",
        "packaging/foundation/server-list.bin",
        &out,
        &mut code,
    );
    // The release root the update channel starts from (`enclave-admin
    // release root`, signed; docs/19-ops.md §1). Without it the build
    // doesn't check for updates.
    embed(
        "ENCLAVE_UPDATE_ROOT",
        "UPDATE_ROOT",
        "packaging/update/root.bin",
        &out,
        &mut code,
    );
    if let Err(e) = std::fs::write(out.join("federation.rs"), code) {
        fail(&format!("federation.rs: {e}"));
    }
}
