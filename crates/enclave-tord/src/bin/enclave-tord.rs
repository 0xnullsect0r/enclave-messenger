//! `enclave-tord`: see the library ([`enclave_tord::daemon::main_with`]).

fn main() -> std::process::ExitCode {
    enclave_tord::daemon::main_with(std::env::args().skip(1).collect())
}
