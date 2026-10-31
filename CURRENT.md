# Current state

Standalone bounded ticket codec with one parsing entry point, inspect.
Profiles: Rpcn21, Psn20, Psn21, Psn30. Identity values are owned Copy types.
Claims are unverified; signature verification and replay prevention are absent.
Public docs are README and Rustdoc. Research material is kept outside this tree.
Registry dependencies resolve through Cargo.lock; CI and local checks permit fetching.
CI explicitly selects each matrix toolchain through RUSTUP_TOOLCHAIN.
57 integration tests + 3 doctests pass with base64 0.23.1, including an empty-cache
registry download on Rust 1.88. Feature, formatting, Clippy and package checks pass.
The legacy name helper is is_legacy_online_id.
Fuzz targets are present but have not been run on this host.
