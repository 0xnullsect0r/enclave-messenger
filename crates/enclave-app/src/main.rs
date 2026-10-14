//! The desktop program: see [`enclave_app::shell`].
#![deny(unsafe_code)]
// A GUI program on Windows: no console window opens with it.
#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() -> Result<(), slint::PlatformError> {
    enclave_app::shell::run(std::env::args().collect())
}
