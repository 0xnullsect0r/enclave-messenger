//! `enclave-nymd`: see the library ([`enclave_nymd::main_with`]).

fn main() -> std::process::ExitCode {
    enclave_nymd::main_with(std::env::args().skip(1).collect())
}
