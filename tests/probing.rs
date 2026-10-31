use psn_codec::ticket::*;
const PSN30: &[u8] = include_bytes!("fixtures/psn30-synthetic.bin");
const PSN21: &[u8] = include_bytes!("fixtures/psn21-synthetic.bin");
fn options(profile: Profile) -> Options {
    Options {
        profile,
        ..Default::default()
    }
}
#[test]
fn inspect_fast_fails_before_tlv_work_with_expected_and_actual_versions() {
    let mut o = options(Profile::Psn20);
    o.limits.max_fields = 0;
    o.limits.max_diagnostics = 0;
    let error = inspect(PSN30, &o).unwrap_err();
    assert_eq!(error.code, Code::UnsupportedVersion);
    assert_eq!(error.expected, Some(VERSION_20 as usize));
    assert_eq!(error.actual, Some(VERSION_30 as usize));
    assert!(error.to_string().contains("0x21000000"));
    assert!(error.to_string().contains("0x31000000"));
    assert_eq!(
        inspect(PSN30, &o).unwrap_err().code,
        Code::UnsupportedVersion
    );
}
#[test]
fn inspect_never_returns_success_for_a_malformed_matching_layout() {
    let mut v = PSN30.to_vec();
    v[13] ^= 0x40;
    assert_eq!(
        inspect(&v, &options(Profile::Psn30)).unwrap_err().code,
        Code::UnexpectedFieldType
    );
    let report = inspect(
        &v,
        &Options {
            mode: ParseMode::Diagnostic,
            ..options(Profile::Psn30)
        },
    )
    .unwrap();
    assert!(!report.is_conformant());
    assert_eq!(report.bodies().len(), 1);
}
#[test]
fn header_errors_and_resource_limits_are_distinct_from_profile_incompatibility() {
    let o = options(Profile::Psn30);
    for n in 0..8 {
        assert_eq!(
            inspect(&PSN30[..n], &o).unwrap_err().code,
            Code::TruncatedHeader
        );
    }
    let mut v = PSN30.to_vec();
    v[7] ^= 1;
    assert_eq!(
        inspect(&v, &o).unwrap_err().code,
        Code::DeclaredLengthMismatch
    );
    let mut o = o;
    o.limits.max_ticket_bytes = PSN30.len() - 1;
    assert_eq!(inspect(PSN30, &o).unwrap_err().code, Code::LimitExceeded);
}
#[test]
fn inspect_alone_collects_conformant_allowed_profiles() {
    let mut matches = Vec::new();
    let mut incompatible = 0;
    for profile in [
        Profile::Psn20,
        Profile::Psn21,
        Profile::Psn30,
        Profile::Rpcn21,
    ] {
        match inspect(PSN30, &options(profile)) {
            Ok(report) => {
                assert!(report.is_conformant());
                matches.push(report.profile());
            }
            Err(error) if error.code == Code::UnsupportedVersion => incompatible += 1,
            Err(error) => panic!("unexpected error: {error}"),
        }
    }
    assert_eq!(matches, [Profile::Psn30]);
    assert_eq!(incompatible, 3);
    // Footer conventions distinguish the otherwise overlapping 2.1 bodies.
    assert!(inspect(PSN21, &options(Profile::Psn21)).is_ok());
    assert_eq!(
        inspect(PSN21, &options(Profile::Rpcn21)).unwrap_err().code,
        Code::ProfileMismatch
    );
}
#[test]
fn callers_can_retry_same_version_layout_errors_without_tolerating_them() {
    let mut v = PSN21.to_vec();
    let report = inspect(PSN21, &options(Profile::Psn21)).unwrap();
    let at = report.bodies()[0].fields()[10].span().start();
    v.splice(at..at, [0, 8, 0, 1, 0x42]);
    let size = u16::from_be_bytes([v[10], v[11]]) + 5;
    v[10..12].copy_from_slice(&size.to_be_bytes());
    let size = (v.len() - 8) as u32;
    v[4..8].copy_from_slice(&size.to_be_bytes());
    let marker = report.footers()[0].fields()[0].payload_span().start() + 5;
    v[marker..marker + 4].copy_from_slice(b"RPCN");
    let error = inspect(&v, &options(Profile::Psn21)).unwrap_err();
    assert_eq!(error.code, Code::ProfileMismatch);
    assert!(inspect(&v, &options(Profile::Rpcn21)).is_ok());
}
#[test]
fn incompatible_versions_do_not_assume_an_eight_byte_header_or_walk_diagnostics() {
    let o = options(Profile::Psn20);
    for bytes in [
        &[0x41, 0, 0, 0][..],
        &[0x41, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0x10, 0x20][..],
    ] {
        assert_eq!(
            inspect(bytes, &o).unwrap_err().code,
            Code::UnsupportedVersion
        );
        assert_eq!(
            inspect(
                bytes,
                &Options {
                    mode: ParseMode::Diagnostic,
                    ..o
                }
            )
            .unwrap_err()
            .code,
            Code::UnsupportedVersion
        );
    }
}
