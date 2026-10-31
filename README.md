# psn-codec

A small Rust codec for inspecting PSN tickets. Parsing produces unverified claims;
it does not authenticate an issuer or verify signatures.

```rust
use psn_codec::ticket::{inspect, Options, Profile, TicketReport};

fn accept(raw: &[u8]) -> Option<TicketReport<'_>> {
    [Profile::Psn21, Profile::Rpcn21].into_iter().find_map(|profile| {
        inspect(raw, &Options { profile, ..Default::default() }).ok()
    })
}
```

Each caller chooses its allowed profiles. Incompatible versions return
`UnsupportedVersion`; opposite footer conventions return `ProfileMismatch`.
Strict inspection rejects malformed input. `ParseMode::Diagnostic` retains
bounded partial data; incomplete reports cannot expose complete typed claims.

Use `report.claims()?` for `account_id`, `np_id` and `service_id`.
The identity values are owned `Copy` types with private fields. Access the name
through `claims.np_id.online_id()`. Original 36-byte identity records can be
acquired with `SceNpId::try_from(slice)`; ticket-derived identities do not invent
those bytes. Constructors and conversions are documented in Rustdoc.

`ClaimsPolicy` checks exact service bytes, time and optional legacy name rules
with caller-supplied context. It supplies no signature or replay guarantee.
Raw ticket data and signing spans remain available through explicit accessors.

Default limits are 64 KiB input, 256 fields and 32 retained diagnostics.
Default `std` enables standard error traits. Disabling default features uses
`no_std` plus `alloc`. Optional `base64` enables bounded canonical decoding.
Rust 1.88 or newer is required. This crate forbids unsafe code.

```text
cargo test --all-features --locked
cargo run --example admission --all-features --locked
```

MIT licensed. Optional dependency notices are in `NOTICE`.
