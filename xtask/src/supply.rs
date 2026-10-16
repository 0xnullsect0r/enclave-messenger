//! Supply-chain checks (`docs/19-ops.md` §2, RT-14) that run as tests:
//! every crate with a build script is one `deny.toml` (and `nym/deny.toml`)
//! names, so a dependency that starts running code at build time fails CI
//! until someone looks at it and adds it, with a reason.

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;
    use std::process::Command;

    /// The crates `allow-build-scripts` names in a cargo-deny config.
    fn allowed(deny: &Path) -> BTreeSet<String> {
        let text = std::fs::read_to_string(deny).unwrap_or_default();
        let start = text.find("allow-build-scripts").unwrap_or(text.len());
        let rest = &text[start..];
        let end = rest.find(']').unwrap_or(rest.len());
        rest[..end]
            .lines()
            .filter_map(|l| {
                let l = l.trim();
                let q = l.strip_prefix('"')?;
                Some(q[..q.find('"')?].to_string())
            })
            .collect()
    }

    /// The packages of a workspace's dependency graph that have a build
    /// script (`cargo metadata`, every target and feature).
    fn with_build_scripts(manifest: &Path) -> BTreeSet<String> {
        let out = Command::new(env!("CARGO"))
            .args([
                "metadata",
                "--format-version",
                "1",
                "--all-features",
                "--locked",
                "--manifest-path",
            ])
            .arg(manifest)
            .output()
            .unwrap_or_else(|e| panic!("cargo metadata: {e}"));
        assert!(
            out.status.success(),
            "cargo metadata: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let meta: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
        let ours: BTreeSet<&str> = meta["workspace_members"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        // What is built for some target with some features (the lock file
        // also lists packages nothing enables).
        let tree = Command::new(env!("CARGO"))
            .args([
                "tree",
                "--locked",
                "--all-features",
                "--target",
                "all",
                "-e",
                "normal,build,dev",
                "--prefix",
                "none",
                "-f",
                "{p}",
                "--manifest-path",
            ])
            .arg(manifest)
            .output()
            .unwrap_or_else(|e| panic!("cargo tree: {e}"));
        let built: BTreeSet<String> = String::from_utf8_lossy(&tree.stdout)
            .lines()
            .filter_map(|l| l.split_whitespace().next().map(str::to_string))
            .collect();
        meta["packages"]
            .as_array()
            .map(|ps| {
                ps.iter()
                    .filter(|p| !ours.contains(p["id"].as_str().unwrap_or("")))
                    .filter(|p| built.contains(p["name"].as_str().unwrap_or("")))
                    .filter(|p| {
                        p["targets"].as_array().is_some_and(|ts| {
                            ts.iter().any(|t| {
                                t["kind"]
                                    .as_array()
                                    .is_some_and(|k| k.iter().any(|k| k == "custom-build"))
                            })
                        })
                    })
                    .filter_map(|p| p["name"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn rt14_build_rs_allowlist_enforced() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for (manifest, deny) in [
            (root.join("Cargo.toml"), root.join("deny.toml")),
            (root.join("nym/Cargo.toml"), root.join("nym/deny.toml")),
        ] {
            let allowed = allowed(&deny);
            assert!(
                !allowed.is_empty(),
                "{} names no build scripts",
                deny.display()
            );
            let missing: Vec<String> = with_build_scripts(&manifest)
                .into_iter()
                .filter(|p| !allowed.contains(p))
                .collect();
            assert!(
                missing.is_empty(),
                "build scripts not in {}'s allow-build-scripts: {missing:?}",
                deny.display()
            );
        }
    }
}
