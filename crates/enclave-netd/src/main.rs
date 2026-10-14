//! `enclave-netd`: see the library ([`enclave_netd::main_with`]).

fn main() -> std::process::ExitCode {
    enclave_netd::main_with(std::env::args().skip(1).collect())
}
