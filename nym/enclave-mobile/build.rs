//! iOS:
//! - link lyrebird's clients (Snowflake, WebTunnel) when the build has them
//!   (`ENCLAVE_LYREBIRD_LIB`, the folder with `liblyrebird.a` from
//!   `ci/tor/lyrebird.sh archive`); Android loads them at run time instead;
//! - embed mediad's WebAssembly build (`ENCLAVE_MEDIAD_WASM`, from
//!   `cargo build --target wasm32-wasip1 -p enclave-mediad`) to run in the
//!   interpreter sandbox (`enclave-wasmbox`).

fn main() {
    println!("cargo::rustc-check-cfg=cfg(enclave_lyrebird)");
    println!("cargo::rustc-check-cfg=cfg(enclave_mediad_wasm)");
    println!("cargo::rerun-if-env-changed=ENCLAVE_LYREBIRD_LIB");
    println!("cargo::rerun-if-env-changed=ENCLAVE_MEDIAD_WASM");
    let ios = std::env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "ios");
    if let (true, Ok(wasm)) = (ios, std::env::var("ENCLAVE_MEDIAD_WASM")) {
        println!("cargo::rerun-if-changed={wasm}");
        println!("cargo::rustc-env=ENCLAVE_MEDIAD_WASM_PATH={wasm}");
        println!("cargo::rustc-cfg=enclave_mediad_wasm");
    }
    if let (true, Ok(dir)) = (ios, std::env::var("ENCLAVE_LYREBIRD_LIB")) {
        println!("cargo::rustc-link-search=native={dir}");
        println!("cargo::rustc-link-lib=static=lyrebird");
        // What the Go runtime needs on iOS.
        for f in ["CoreFoundation", "Security"] {
            println!("cargo::rustc-link-lib=framework={f}");
        }
        println!("cargo::rustc-link-lib=resolv");
        println!("cargo::rustc-cfg=enclave_lyrebird");
    }
}
