# Release checklist

Status: living document · steps a person runs before tagging a release

Everything that can be automated runs in CI (`.github/workflows/ci.yml`);
this list is what can't, or what measures hardware rather than code. The
red-team "Manual" rows (`redteam-matrix.md`) join it with milestone Q1.

## Tor bridges

- [ ] **WebTunnel.** Get a WebTunnel bridge line from bridges.torproject.org
  (it has no built-in ones), paste it under Settings → Tor bridges on an
  installed build, restart, and check Enclave connects (CI's `tor-smoke`
  covers obfs4 and Snowflake on the live network).

## Server

- [ ] **Scale.** On a machine of the class operators are told to use, run
  `cargo run --release -p enclave-server --example scale -- --accounts 100000`
  (and `--postgres URL` for the PostgreSQL backend) and update the
  measured table in `12-servers.md` §7 if it moved by more than 20%.
