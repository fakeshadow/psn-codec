//! Run with --features base64 to include bounded base64 admission.
#[allow(dead_code)]
#[path = "support/admission.rs"]
mod admission;

fn main() {
    use psn_codec::ticket::{Options, Profile, inspect};
    // The caller owns this admission policy: accept either 2.1 family on one server.
    let two_profile_allowed = [Profile::Psn21, Profile::Rpcn21];
    for (raw, expected) in [
        (
            include_bytes!("../tests/fixtures/psn21-synthetic.bin").as_slice(),
            Profile::Psn21,
        ),
        (
            include_bytes!("../tests/fixtures/rpcn21-unsigned.bin").as_slice(),
            Profile::Rpcn21,
        ),
    ] {
        let report = two_profile_allowed
            .iter()
            .find_map(|&profile| {
                inspect(
                    raw,
                    &Options {
                        profile,
                        ..Default::default()
                    },
                )
                .ok()
            })
            .expect("one of the explicitly allowed profiles must match");
        assert_eq!(report.profile(), expected);
        // Keep this profile with the session; the original bytes remain available to the caller.
        assert_eq!(report.as_bytes(), raw);
    }

    // Generic envelope coverage; each real server supplies its own allowed list.
    for raw in [
        include_bytes!("../tests/fixtures/rpcn21-unsigned.bin").as_slice(),
        include_bytes!("../tests/fixtures/psn20-synthetic.bin").as_slice(),
        include_bytes!("../tests/fixtures/psn21-synthetic.bin").as_slice(),
        include_bytes!("../tests/fixtures/psn30-synthetic.bin").as_slice(),
    ] {
        let report = admission::admit(raw, &admission::ALLOWED).unwrap();
        assert_eq!(report.as_bytes(), raw);
        let mut prefixed = (raw.len() as u16).to_be_bytes().to_vec();
        prefixed.extend_from_slice(raw);
        admission::prefixed(&prefixed, &admission::ALLOWED).unwrap();
        admission::raw_or_prefixed(raw, &admission::ALLOWED).unwrap();
        admission::raw_or_prefixed(&prefixed, &admission::ALLOWED).unwrap();
        #[cfg(feature = "base64")]
        {
            use base64::Engine;
            use psn_codec::encoding::{Base64Options, Whitespace};
            // Encoding is only to construct this example SOAP input.
            let text = base64::engine::general_purpose::STANDARD.encode(raw);
            let options = Base64Options {
                whitespace: Whitespace::AllowAscii,
                ..Default::default()
            };
            let login =
                admission::base64_identity(text.as_bytes(), &admission::ALLOWED, &options).unwrap();
            assert_eq!(login.account_id, report.claims().unwrap().account_id);
        }
    }
}
