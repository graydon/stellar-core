fn main() {
    // On Windows (build_rust.bat), soroban submodule revisions are written to
    // .soroban-revs before invoking cargo.  Watching this file causes cargo to
    // mark the crate dirty when a submodule changes, so it re-links against
    // the updated extern rlibs (which are passed via --extern after "--" and
    // not tracked by cargo's own dependency graph).
    //
    // On Unix (Makefile.am), the rebuild is instead driven by Make
    // prerequisites and -Cmetadata in RUSTFLAGS, so the file won't exist;
    // we only register it when it's actually present.
    if std::path::Path::new(".soroban-revs").exists() {
        println!("cargo:rerun-if-changed=.soroban-revs");
    }

    // When building with the Makefile, a merged bridge file is produced that
    // splices generated lazy-XDR declarations into bridge.rs.  The Makefile
    // sets STELLAR_MERGED_BRIDGE_PATH to its absolute path; we forward it so
    // bridge.rs can `include!(env!(...))` the right file.
    if let Ok(merged) = std::env::var("STELLAR_MERGED_BRIDGE_PATH") {
        println!("cargo:rustc-env=STELLAR_BRIDGE_INCLUDE_PATH={merged}");
        println!("cargo:rerun-if-env-changed=STELLAR_MERGED_BRIDGE_PATH");
        println!("cargo:rerun-if-changed={merged}");
    } else {
        // Fallback: use the plain bridge_base.rs from the source tree.
        let src = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("src")
            .join("bridge_base.rs");
        println!(
            "cargo:rustc-env=STELLAR_BRIDGE_INCLUDE_PATH={}",
            src.display()
        );
        println!("cargo:rerun-if-changed={}", src.display());
    }
}
