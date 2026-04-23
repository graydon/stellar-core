// This file is a trampoline: it includes the actual bridge content from an
// absolute path set at build time by build.rs.  When built via the Makefile,
// STELLAR_BRIDGE_INCLUDE_PATH points to merged_bridge.rs (bridge_base.rs
// with generated lazy-XDR declarations spliced in).  Otherwise it falls back
// to bridge_base.rs directly.
include!(env!("STELLAR_BRIDGE_INCLUDE_PATH"));
