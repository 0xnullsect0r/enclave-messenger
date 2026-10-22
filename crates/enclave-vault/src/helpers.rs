//! Starting the vault's helpers: netd for the network, mediad for
//! pictures. Programs next to this one on desktops; threads of the app's
//! process on Android and iOS (`enclave_platform::process`).

use crate::Mode;

/// netd (and through it Tor and the mixnet client) for `mode`'s servers,
/// and mediad. Must run inside a tokio runtime, before the vault confines
/// itself.
pub fn start(mode: &Mode) -> crate::Helpers {
    let net = start_netd(mode);
    let media = crate::media::mediad_binary()
        .and_then(|b| crate::media::Media::spawn(&b, crate::media::SPARES).ok());
    crate::Helpers {
        net,
        media,
        web: None,
    }
}

/// netd for `mode`'s servers (none outside server mode, or without netd).
pub fn start_netd(
    mode: &crate::Mode,
) -> Option<std::sync::Arc<dyn enclave_net::transport::Transport>> {
    let crate::Mode::Server {
        profile,
        home,
        others,
        nym_env,
        ..
    } = mode
    else {
        return None;
    };
    let bin = crate::netd::netd_binary()?;
    let servers: Vec<_> = home
        .iter()
        .chain(others)
        .map(|(id, r)| (*id, r.to_string()))
        .collect();
    let mut extra: Vec<String> = if *nym_env {
        vec!["--nym-env".into()]
    } else {
        Vec::new()
    };
    // Tor in front of the mixnet whenever this build ships enclave-tord
    // (`docs/09-transport.md` §1): netd starts it, keeping Tor's state in
    // the profile.
    let tord = bin.with_file_name(format!("enclave-tord{}", std::env::consts::EXE_SUFFIX));
    if tord.exists() || enclave_platform::process::registered("enclave-tord") {
        extra.push("--tor".into());
        extra.push(profile.join("tor").to_string_lossy().into_owned());
        // Bridges the user set (censorship mode).
        extra.extend(crate::netd::bridge_args(profile));
    }
    // With servers on the mixnet in the list, their routes are given once
    // the list is read: the mixnet client starts anyway, and waits for its
    // zk-nym tickets, which the vault gives it once it can read its wallet
    // (`docs/09-transport.md` §7). A list of onion services only needs
    // Tor alone (RFC 0010).
    if mode.uses_mixnet() {
        if mode.has_server_list() {
            extra.push("--mixnet".into());
        }
        extra.push("--await-tickets".into());
    }
    match crate::netd::PipeTransport::spawn(&bin, &servers, &extra) {
        Ok(t) => Some(std::sync::Arc::new(t)),
        Err(e) => {
            eprintln!("enclave-vault: netd didn't start ({e}); using the network directly");
            None
        }
    }
}
