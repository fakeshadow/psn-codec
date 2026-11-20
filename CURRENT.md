# Current state

Version 0.2.0. Standalone bounded ticket codec with one parsing entry point, inspect.
Profiles: Rpcn21, Psn20, Psn21, Psn30. Identity values are owned Copy types.
Claims are unverified; signature verification and replay prevention are absent.
Monolithic ClaimsPolicy/assess_claims was removed in favor of composable claim helpers:
AccountId::is_zero, ServiceId::from_str_nul_padded, ServiceId::contains,
Claims::issuer_id_i32, Claims::check_time (TimeError), and is_legacy_online_id.
Public docs are README and Rustdoc. Research material is kept outside this tree.
Registry dependencies resolve through Cargo.lock; CI and local checks permit fetching.
CI explicitly selects each matrix toolchain through RUSTUP_TOOLCHAIN.
59 integration tests + 3 doctests pass with --all-features (base64 0.23.1) and
--no-default-features --features base64, and 55 + 3 pass with --no-default-features,
on both Rust 1.99.1 and Rust 1.88.0. Formatting, Clippy, Rustdoc, examples and
cargo package checks pass.
Fuzz targets are present but have not been run on this host.
