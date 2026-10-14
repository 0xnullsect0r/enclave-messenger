//! The iOS app's program: the profile in the app's Application Support
//! folder (inside its sandbox, kept out of iCloud and iTunes backups by the
//! vault), then the app ([`enclave_mobile::start`]).

fn main() {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    let profile = home
        .join("Library")
        .join("Application Support")
        .join("Enclave");
    if let Err(e) = enclave_mobile::start(profile, std::env::args().skip(1).collect()) {
        eprintln!("enclave: {e}");
    }
}
