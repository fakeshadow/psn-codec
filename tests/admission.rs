#[allow(dead_code)]
#[path = "../examples/support/admission.rs"]
mod admission;
use admission::{ALLOWED, Rejection, admit, prefixed, raw_or_prefixed};
use psn_codec::ServiceId;
use psn_codec::ticket::{Code, Options, Profile, TimeError, UnixMillis, inspect};

const RPCN: &[u8] = include_bytes!("fixtures/rpcn21-unsigned.bin");
fn vectors() -> [&'static [u8]; 4] {
    [
        RPCN,
        include_bytes!("fixtures/psn20-synthetic.bin"),
        include_bytes!("fixtures/psn21-synthetic.bin"),
        include_bytes!("fixtures/psn30-synthetic.bin"),
    ]
}
fn envelope(raw: &[u8]) -> Vec<u8> {
    let mut out = (raw.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(raw);
    out
}
fn corrupt_length(raw: &mut [u8]) {
    raw[4..8].fill(0);
}
fn no_footer() -> Vec<u8> {
    let report = inspect(RPCN, &Options::default()).unwrap();
    let mut raw = RPCN[..report.bodies()[0].field().span().end()].to_vec();
    let len = (raw.len() - 8) as u32;
    raw[4..8].copy_from_slice(&len.to_be_bytes());
    raw
}
#[test]
fn caller_explicitly_accepts_only_psn21_and_rpcn21() {
    let allowed = [Profile::Psn21, Profile::Rpcn21];
    let select = |raw: &[u8]| {
        allowed.iter().find_map(|&profile| {
            inspect(
                raw,
                &Options {
                    profile,
                    ..Default::default()
                },
            )
            .ok()
            .map(|report| report.profile())
        })
    };
    assert_eq!(
        select(include_bytes!("fixtures/psn21-synthetic.bin")),
        Some(Profile::Psn21)
    );
    assert_eq!(select(RPCN), Some(Profile::Rpcn21));
    assert_eq!(select(include_bytes!("fixtures/psn20-synthetic.bin")), None);
    assert_eq!(select(include_bytes!("fixtures/psn30-synthetic.bin")), None);
    assert_eq!(select(&no_footer()), None);
}
#[test]
fn same_caller_accepts_psn_and_rpcn_and_preserves_raw_bytes() {
    for raw in vectors().into_iter().cycle().take(8) {
        assert_eq!(admit(raw, &ALLOWED).unwrap().as_bytes(), raw);
        assert_eq!(prefixed(&envelope(raw), &ALLOWED).unwrap().as_bytes(), raw);
        assert_eq!(raw_or_prefixed(raw, &ALLOWED).unwrap().as_bytes(), raw);
        assert_eq!(
            raw_or_prefixed(&envelope(raw), &ALLOWED)
                .unwrap()
                .as_bytes(),
            raw
        );
    }
}
#[test]
fn callers_can_constrain_profiles_and_retain_all_failure_metadata() {
    assert!(matches!(admit(RPCN, &[]), Err(Rejection::NoProfiles)));
    let Err(Rejection::Profiles(failures)) = admit(RPCN, &[Profile::Psn20]) else {
        panic!("wrong profile accepted")
    };
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].1.code, Code::UnsupportedVersion);
    assert_eq!(
        failures[0].1.actual,
        Some(Profile::Rpcn21.version() as usize)
    );
    // Footer conventions now reject PSN 2.1 even with the same body shape.
    assert_eq!(admit(RPCN, &ALLOWED).unwrap().profile(), Profile::Rpcn21);
    let report = inspect(RPCN, &Options::default()).unwrap();
    let after_status = report.bodies()[0].fields()[9].span().end();
    let body_length = report.bodies()[0].field().bytes().len() as u16;
    let mut cookie = RPCN.to_vec();
    cookie.splice(after_status..after_status, [0, 8, 0, 1, 0x55]);
    cookie[10..12].copy_from_slice(&(body_length + 5).to_be_bytes());
    let payload_length = (cookie.len() - 8) as u32;
    cookie[4..8].copy_from_slice(&payload_length.to_be_bytes());
    assert!(admit(&cookie, &[Profile::Psn21]).is_err());
    assert_eq!(admit(&cookie, &ALLOWED).unwrap().profile(), Profile::Rpcn21);
    prefixed(&envelope(&cookie), &ALLOWED).unwrap();
    raw_or_prefixed(&cookie, &ALLOWED).unwrap();
    #[cfg(feature = "base64")]
    {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&cookie);
        admission::base64_identity(encoded.as_bytes(), &ALLOWED, &Default::default()).unwrap();
    }
}
#[test]
fn prefixed_rejects_short_wrong_length_and_trailing_envelopes() {
    assert!(matches!(prefixed(&[], &ALLOWED), Err(Rejection::Envelope)));
    assert!(matches!(prefixed(&[0], &ALLOWED), Err(Rejection::Envelope)));
    let mut raw = envelope(RPCN);
    raw[1] ^= 1;
    assert!(matches!(prefixed(&raw, &ALLOWED), Err(Rejection::Envelope)));
    let mut raw = envelope(RPCN);
    raw.push(0);
    assert!(matches!(prefixed(&raw, &ALLOWED), Err(Rejection::Envelope)));
}
#[test]
fn malformed_tickets_never_become_successful_admission_under_another_profile() {
    let mut wrong_length = RPCN.to_vec();
    corrupt_length(&mut wrong_length);
    let mut wrong_version = RPCN.to_vec();
    wrong_version[0] = 0x99;
    let mut wrong_tag = RPCN.to_vec();
    let report = inspect(RPCN, &Options::default()).unwrap();
    let name_start = report.bodies()[0].fields()[5].span().start();
    wrong_tag[name_start..name_start + 2].copy_from_slice(&8u16.to_be_bytes());
    for raw in [wrong_length, wrong_version, wrong_tag, no_footer()] {
        assert!(admit(&raw, &ALLOWED).is_err());
        assert!(prefixed(&envelope(&raw), &ALLOWED).is_err());
        assert!(raw_or_prefixed(&raw, &ALLOWED).is_err());
        assert!(raw_or_prefixed(&envelope(&raw), &ALLOWED).is_err());
    }
}
#[test]
fn raw_or_prefixed_raw_or_exact_prefix_does_not_accept_prefix_junk_or_partial_claims() {
    let mut raw = envelope(RPCN);
    raw[1] ^= 1;
    assert!(raw_or_prefixed(&raw, &ALLOWED).is_err());
    let mut raw = envelope(RPCN);
    raw.extend_from_slice(&[0, 0]);
    assert!(raw_or_prefixed(&raw, &ALLOWED).is_err());
    assert!(raw_or_prefixed(&envelope(&no_footer()), &ALLOWED).is_err());
}
#[test]
fn admission_enforces_service_safe_name_policy_without_logging_bad_claims() {
    let report = inspect(RPCN, &Options::default()).unwrap();
    let span = report.bodies()[0].fields()[5].payload_span().range();
    let mut raw = RPCN.to_vec();
    raw[span.clone()].fill(0);
    raw[span.start..span.start + 12].copy_from_slice(b"Never Log Me");
    // Codec permits this logical UTF-8 value; service admission rejects its alphabet.
    assert!(inspect(&raw, &Options::default()).is_ok());
    let error = admit(&raw, &ALLOWED).unwrap_err();
    assert!(matches!(error, Rejection::OnlineId));
    assert!(!format!("{error:?}").contains("Never Log Me"));
}
#[test]
fn caller_admission_checks_compose_without_another_parse() {
    let report = admit(RPCN, &ALLOWED).unwrap();
    let claims = report.claims().unwrap();
    let allowed_services = [
        ServiceId::from_str_nul_padded("UP1004-BLUS30442_00").unwrap(),
        ServiceId::from_str_nul_padded("TEST-SERVICE").unwrap(),
    ];
    assert!(allowed_services.contains(&claims.service_id));
    assert!(
        ["BLUS30442", "SERVICE"]
            .iter()
            .any(|pattern| claims.service_id.contains(pattern))
    );
    assert!(!claims.account_id.is_zero());
    assert!(claims.issuer_id_i32() >= 0);
    assert_eq!(claims.check_time(UnixMillis(1500), 0), Ok(()));
    assert_eq!(
        claims.check_time(UnixMillis(2000), 0),
        Err(TimeError::Expired)
    );
    assert_ne!(claims.service_id, ServiceId::from([0; 24]));
}
#[cfg(feature = "base64")]
#[test]
fn base64_identity_bounded_base64_admission_owns_values_after_decoding_all_profiles() {
    use base64::Engine;
    use psn_codec::encoding::{Base64Options, Whitespace};
    for raw in vectors() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
        let wrapped = format!(" \r\n{}\n\t{} ", &encoded[..8], &encoded[8..]);
        let options = Base64Options {
            whitespace: Whitespace::AllowAscii,
            ..Default::default()
        };
        let login = admission::base64_identity(wrapped.as_bytes(), &ALLOWED, &options).unwrap();
        let report = admit(raw, &ALLOWED).unwrap();
        let c = report.claims().unwrap();
        assert_eq!(login.version, report.version().unwrap());
        assert_eq!(login.account_id, c.account_id);
        assert_eq!(login.np_id, c.np_id);
        assert_eq!(login.service_id, c.service_id);
        assert!(
            admission::base64_identity(wrapped.as_bytes(), &ALLOWED, &Base64Options::default())
                .is_err()
        );
    }
}
#[cfg(feature = "base64")]
#[test]
fn base64_identity_never_promotes_bad_encoding_or_incomplete_ticket_into_identity() {
    use base64::Engine;
    use psn_codec::encoding::{Base64Error, Base64Options};
    assert!(
        admission::base64_identity(b"not a ticket!", &ALLOWED, &Base64Options::default()).is_err()
    );
    let encoded = base64::engine::general_purpose::STANDARD.encode(no_footer());
    assert!(
        admission::base64_identity(encoded.as_bytes(), &ALLOWED, &Base64Options::default())
            .is_err()
    );
    assert!(matches!(
        admission::base64_identity(
            b"AAAA",
            &ALLOWED,
            &Base64Options {
                max_encoded_bytes: 3,
                ..Default::default()
            }
        ),
        Err(Rejection::Base64(Base64Error::EncodedLimit))
    ));
    let encoded = base64::engine::general_purpose::STANDARD.encode(RPCN);
    assert!(matches!(
        admission::base64_identity(
            encoded.as_bytes(),
            &ALLOWED,
            &Base64Options {
                max_decoded_bytes: 8,
                ..Default::default()
            }
        ),
        Err(Rejection::Base64(Base64Error::DecodedLimit))
    ));
}
