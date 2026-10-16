//! `cargo xtask shape`: the traffic-shape checks ("Shape" rows of
//! `docs/redteam-matrix.md`, `docs/20-assurance.md`). Each scenario is a
//! scripted workload run on the real scheduler or the running shaper with
//! the clock paused, measured the way an observer of the link would, and
//! judged with a statistical test:
//!
//! * two-sample Kolmogorov–Smirnov (α = 10⁻⁶) that send times don't depend
//!   on real traffic, or on which client it is;
//! * one-sample KS that Background ticks are Poisson with the profile mean;
//! * byte budgets per hour against `docs/math/cover-traffic.md`;
//! * χ² that real and cover requests look like the same random bytes.
//!
//! The measurement on a real link (a packet capture of the device's
//! connection to its Nym gateway) is `ci/federation/gen.sh shape`, in the
//! `federation-e2e-localnet` CI job.

use std::process::{Command, ExitCode};

/// A scenario: its name (an `rtNN_` name when it is one of the matrix's),
/// the test target that holds it, and what it shows.
struct Scenario {
    name: &'static str,
    target: &'static str,
    what: &'static str,
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "rt01_background_profile_constant_when_idle",
        target: "rt_shape",
        what: "idle Background: one unit + one poll per Poisson tick, 553 KB/h",
    },
    Scenario {
        name: "rt01_send_slots_independent_of_real_traffic",
        target: "rt_shape",
        what: "busy vs idle: same send times (KS) and sizes, every profile",
    },
    Scenario {
        name: "rt12_profiles_identical_across_clients",
        target: "rt_shape",
        what: "two different clients per profile: same sizes, timing, pacing",
    },
    Scenario {
        name: "tick_timing_is_independent_of_real_traffic",
        target: "shape",
        what: "scheduler: tick delays and poll order don't depend on the queue",
    },
    Scenario {
        name: "real_and_cover_requests_are_the_same_size_and_look_random",
        target: "shape",
        what: "sealed real and cover requests: same sizes, bytes uniform (χ²)",
    },
];

pub(crate) fn run() -> ExitCode {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mut failed = Vec::new();
    for s in SCENARIOS {
        eprintln!("shape: {} ({})", s.name, s.what);
        let ok = Command::new(&cargo)
            .current_dir(crate::root())
            .args([
                "test",
                "--release",
                "-q",
                "-p",
                "enclave-net",
                "--test",
                s.target,
                "--",
                "--exact",
                s.name,
            ])
            .status()
            .is_ok_and(|st| st.success());
        if !ok {
            failed.push(s.name);
        }
    }
    if failed.is_empty() {
        eprintln!("shape ok: {} scenarios", SCENARIOS.len());
        ExitCode::SUCCESS
    } else {
        eprintln!("shape FAILED: {failed:?}");
        ExitCode::FAILURE
    }
}
