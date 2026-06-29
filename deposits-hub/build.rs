use std::process::Command;

/// Emit `BUILD_TIMESTAMP` and `GIT_SHA` so the hub can report exactly which
/// commit it (and the node binary it deploys) was built from. Mirror of
/// `deposits-node/build.rs`; see that file for the why (stale-binary redeploy).
fn main() {
    let timestamp = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=BUILD_TIMESTAMP={}", timestamp);

    println!("cargo:rustc-env=GIT_SHA={}", git_sha());

    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/index");
}

/// `<short-sha>` or `<short-sha>-dirty`, falling back to `"unknown"` outside a
/// git checkout.
fn git_sha() -> String {
    let sha = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    // `--untracked-files=no`: only tracked changes mark the build dirty.
    // Scratch notes / untracked config shouldn't flip the deployed-code flag.
    let dirty = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(false);
    if dirty {
        format!("{}-dirty", sha)
    } else {
        sha
    }
}
