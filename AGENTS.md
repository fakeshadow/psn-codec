# Working on this crate

Read CURRENT.md and the relevant source/tests. Keep the crate standalone and its
public parsing surface small. Preserve no_std + alloc and Rust 1.88 support.
Never represent parsed claims as authenticated. Keep raw bytes explicit and
Debug/error output redacted. Preserve applicable license notices. Keep public
docs limited to README and Rustdoc; keep research and build artifacts outside
the source tree. Run formatting, Clippy, feature tests and package checks after
changes. Update CURRENT.md with actual results.
