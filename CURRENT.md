# Current state

Standalone bounded ticket codec with one parsing entry point, inspect.
Profiles: Rpcn21, Psn20, Psn21, Psn30. Identity values are owned Copy types.
Claims are unverified; signature verification and replay prevention are absent.
Public docs are README and Rustdoc. Research material is kept outside this tree.
Source/package audit completed; registry publication remains disabled.
57 integration tests + 3 doctests pass; features, Rust 1.88, formatting and Clippy pass.
The 25-file package builds and passes extracted-source tests; Rustdoc warnings are denied.
The legacy name helper is is_legacy_online_id.
Fuzz targets are present but have not been run on this host.

Checkout fix: .gitattributes preserves vendor/fixture bytes and uses LF for text.
The reported vendor checksum failure was reproduced with core.autocrlf=true.
Fresh checkout with the rules passes all 37 vendor checksums and 57 integration
tests + 3 doctests using the same offline all-feature test command.
