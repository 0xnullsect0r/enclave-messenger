//! `enclave-mediad`: see the library ([`enclave_mediad::main_with`]).
#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    enclave_mediad::main_with(std::env::args().skip(1).collect())
}
