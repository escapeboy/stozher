//! The Stozher kernel binary.
//!
//! S0 scope is the specification, the vectors and `stozher-core`. This binary is a deliberate stub
//! so the workspace layout of ADR-0003 is honest from the first commit; the event store, ingest
//! API, policy distribution endpoint and native gates are S1 and S4.

fn main() {
    println!(
        "stozher-kernel {} ({})",
        env!("CARGO_PKG_VERSION"),
        stozher_core::VERSION
    );
    println!("S0: specification and reference primitives only. Ingest and gates land in S1/S4.");
}
