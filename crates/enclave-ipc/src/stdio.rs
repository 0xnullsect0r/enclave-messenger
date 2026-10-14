//! A helper's standard input and output for tokio: the process's own, or
//! the pipes its thread was given where helpers run in the app's process
//! (`enclave_platform::process`).

/// This helper's input and output.
pub fn stdio() -> std::io::Result<(tokio::fs::File, tokio::fs::File)> {
    let s = enclave_platform::process::stdio()?;
    Ok((
        tokio::fs::File::from_std(s.input),
        tokio::fs::File::from_std(s.output),
    ))
}

/// The parent's ends of a helper started as a thread: what to write to it
/// and what to read from it.
pub fn pipes(p: enclave_platform::process::InProcess) -> (tokio::fs::File, tokio::fs::File) {
    (
        tokio::fs::File::from_std(p.stdin),
        tokio::fs::File::from_std(p.stdout),
    )
}
