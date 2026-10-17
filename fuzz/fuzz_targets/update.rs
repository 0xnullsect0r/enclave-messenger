#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    enclave_fuzz::run("update", data);
});
