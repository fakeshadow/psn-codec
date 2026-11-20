use psn_codec::ticket::*;
fn recover<'a>(raw: &'a [u8], options: &Options) -> Result<TicketReport<'a>, Diagnostic> {
    inspect(
        raw,
        &Options {
            mode: ParseMode::Diagnostic,
            ..*options
        },
    )
}

const VECTOR: &[u8] = include_bytes!("fixtures/rpcn21-unsigned.bin");
fn options() -> Options {
    Options::default()
}
fn fix_length(bytes: &mut [u8]) {
    let n = (bytes.len() - 8) as u32;
    bytes[4..8].copy_from_slice(&n.to_be_bytes());
}
fn field_span(index: usize) -> Span {
    recover(VECTOR, &options()).unwrap().bodies()[0].fields()[index].span()
}
fn rejects(bytes: &[u8], code: Code) {
    assert!(inspect(bytes, &options()).is_err());
    match recover(bytes, &options()) {
        Ok(report) => assert!(
            report.diagnostics().iter().any(|d| d.code == code),
            "missing {code:?}"
        ),
        Err(error) => assert_eq!(error.code, code),
    }
}
#[test]
fn independent_complete_unsigned_vector() {
    let t = inspect(VECTOR, &options()).unwrap();
    let c = t.claims().unwrap();
    assert_eq!(u64::from(c.account_id), 0x0102030405060708);
    assert_eq!(c.np_id.online_id().as_str(), "Test_Player");
    assert_eq!((c.issued.0, c.expires.0), (1000, 2000));
    assert_eq!(c.issuer_id, 256);
    assert_eq!(c.domain, "un");
    assert_eq!(c.service_id.as_bytes().len(), 24);
    assert_eq!(c.serial.len(), 20);
    assert_eq!(t.as_bytes(), VECTOR);
    assert_eq!(t.signature_bytes().unwrap(), [0; 56]);
    assert_eq!(&t.rpcn_signed_bytes().unwrap()[..4], &[0x30, 0, 0, 0xa4]);
    assert_eq!(
        t.rpcn_signed_bytes().unwrap(),
        &VECTOR[t.bodies()[0].field().span().range()]
    );
}
#[test]
fn every_truncated_prefix_is_rejected_and_inspectable() {
    for n in 0..VECTOR.len() {
        assert!(inspect(&VECTOR[..n], &options()).is_err(), "prefix {n}");
        assert!(
            recover(&VECTOR[..n], &options())
                .map(|r| !r.is_conformant())
                .unwrap_or(true)
        );
    }
}
#[test]
fn exact_u32_size_and_version_bits() {
    for bytes in [[0, 1, 0, 0], [0xff; 4], [0; 4]] {
        let mut v = VECTOR.to_vec();
        v[4..8].copy_from_slice(&bytes);
        rejects(&v, Code::DeclaredLengthMismatch);
    }
    for i in 0..4 {
        let mut v = VECTOR.to_vec();
        v[i] ^= 1;
        rejects(&v, Code::UnsupportedVersion);
    }
    let mut v = VECTOR.to_vec();
    v.extend([1, 2, 3]);
    fix_length(&mut v);
    rejects(&v, Code::TruncatedField);
}
#[test]
fn every_identity_tag_and_scalar_width_is_checked() {
    for i in 0..10 {
        let span = field_span(i);
        let mut v = VECTOR.to_vec();
        v[span.start() + 1] ^= 0x40;
        rejects(&v, Code::UnexpectedFieldType);
    }
    for i in 0..10 {
        let span = field_span(i);
        let mut v = VECTOR.to_vec();
        v[span.start() + 3] -= 1;
        assert!(inspect(&v, &options()).is_err());
    }
}
#[test]
fn padding_utf8_and_wrong_type_legacy_fixture() {
    let span = field_span(5);
    let mut v = VECTOR.to_vec();
    v[span.start() + 4] = 255;
    rejects(&v, Code::InvalidText);
    let mut v = VECTOR.to_vec();
    v[span.end() - 1] = b'X';
    rejects(&v, Code::InvalidPadding);
    let mut v = VECTOR.to_vec();
    v[span.start() + 1] = 8;
    rejects(&v, Code::UnexpectedFieldType);
}
#[test]
fn duplicate_body_is_preserved_without_identity_selection() {
    let report = recover(VECTOR, &options()).unwrap();
    let span = report.bodies()[0].field().span();
    let mut v = VECTOR.to_vec();
    v.extend(&VECTOR[span.range()]);
    fix_length(&mut v);
    let report = recover(&v, &options()).unwrap();
    assert_eq!(report.bodies().len(), 2);
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|d| d.code == Code::DuplicateBody)
    );
    assert!(inspect(&v, &options()).is_err());
    let mut v = VECTOR.to_vec();
    let span = report.footers()[0].field().span();
    v.extend(&VECTOR[span.range()]);
    fix_length(&mut v);
    rejects(&v, Code::DuplicateFooter);
}
#[test]
fn malformed_tail_cannot_hide_behind_first_six_fields() {
    let mut v = VECTOR.to_vec();
    let end = field_span(9).end();
    v[end + 2..end + 4].copy_from_slice(&100u16.to_be_bytes());
    rejects(&v, Code::TruncatedField);
}
#[test]
fn resource_limits_and_zero_diagnostic_cap() {
    let mut o = options();
    o.limits.max_ticket_bytes = VECTOR.len() - 1;
    assert_eq!(recover(VECTOR, &o).unwrap_err().code, Code::LimitExceeded);
    o = options();
    o.limits.max_fields = 0;
    assert_eq!(recover(VECTOR, &o).unwrap_err().code, Code::LimitExceeded);
    o = options();
    o.limits.max_fields = 16;
    assert!(inspect(VECTOR, &o).is_ok());
    o.limits.max_fields = 15;
    assert!(inspect(VECTOR, &o).is_err());
    o = options();
    o.limits.max_diagnostics = 0;
    let mut v = VECTOR.to_vec();
    v[7] ^= 1;
    let report = recover(&v, &o).unwrap();
    assert!(report.diagnostics().is_empty());
    assert!(report.omitted_diagnostics() > 0);
    assert!(!report.is_conformant());
    assert!(inspect(&v, &o).is_err());
}
#[test]
fn unknown_sections_and_versions_remain_opaque() {
    let mut v = VECTOR.to_vec();
    v[0] = 0x31;
    assert_eq!(
        inspect(&v, &options()).unwrap_err().code,
        Code::UnsupportedVersion
    );
    v[0] = VECTOR[0];
    let r = recover(&v, &options()).unwrap();
    assert_eq!(r.bodies().len(), 1);
    assert_eq!(r.bodies()[0].fields().len(), 12);
    v[8] = 0x40;
    rejects(&v, Code::UnexpectedSection);
}
#[test]
fn optional_cookie_and_container_order() {
    let mut v = VECTOR.to_vec();
    let at = field_span(10).start();
    v.splice(at..at, [0, 8, 0, 3, 1, 2, 3]);
    let size = u16::from_be_bytes([v[10], v[11]]) + 7;
    v[10..12].copy_from_slice(&size.to_be_bytes());
    fix_length(&mut v);
    assert!(inspect(&v, &options()).is_ok());
    let mut v = VECTOR.to_vec();
    let report = recover(VECTOR, &options()).unwrap();
    let split = report.bodies()[0].field().span().end();
    v[8..].rotate_left(split - 8);
    rejects(&v, Code::UnexpectedSection);
}
#[test]
fn debug_and_errors_do_not_expose_claims() {
    let t = inspect(VECTOR, &options()).unwrap();
    let strings = [
        format!("{t:?}"),
        format!("{:?}", t.claims().unwrap()),
        format!("{:?}", t.claims().unwrap().account_id),
        format!("{:?}", t.bodies()),
    ];
    for text in strings {
        assert!(!text.contains("Test_Player"));
        assert!(!text.contains("synthetic-only"));
        assert!(!text.contains("TEST-SERVICE"));
    }
}
#[test]
fn composable_time_service_issuer_account_and_name_checks() {
    let t = inspect(VECTOR, &options()).unwrap();
    let c = t.claims().unwrap();
    let expected = psn_codec::ServiceId::from_str_nul_padded("TEST-SERVICE").unwrap();
    assert_eq!(c.service_id, expected);
    assert!(c.service_id.contains("TEST"));
    assert!(!c.service_id.contains(""));
    assert!(!c.account_id.is_zero());
    assert_eq!(c.issuer_id_i32(), 256);

    assert_eq!(c.check_time(UnixMillis(1000), 0), Ok(()));
    assert_eq!(
        c.check_time(UnixMillis(999), 0),
        Err(TimeError::NotYetValid)
    );
    assert_eq!(c.check_time(UnixMillis(2000), 0), Err(TimeError::Expired));
    assert_eq!(c.check_time(UnixMillis(2000), 1), Ok(()));
    assert_eq!(c.check_time(UnixMillis(2001), 1), Err(TimeError::Expired));
    assert_eq!(c.check_time(UnixMillis(999), 1), Ok(()));
    assert_eq!(
        c.check_time(UnixMillis(998), 1),
        Err(TimeError::NotYetValid)
    );
    assert_eq!(TimeError::Expired.to_string(), "Expired");
    #[cfg(feature = "std")]
    {
        let err: &dyn std::error::Error = &TimeError::NotYetValid;
        assert_eq!(err.to_string(), "NotYetValid");
    }

    // Zero or reversed validity windows are rejected.
    let mut bad_window = VECTOR.to_vec();
    let expires_span = field_span(3);
    bad_window[expires_span.start() + 4..expires_span.end()]
        .copy_from_slice(&1000u64.to_be_bytes());
    let equal_claims = inspect(&bad_window, &options()).unwrap().claims().unwrap();
    assert_eq!(
        equal_claims.check_time(UnixMillis(1000), 500),
        Err(TimeError::InvalidRange)
    );
    bad_window[expires_span.start() + 4..expires_span.end()].copy_from_slice(&999u64.to_be_bytes());
    let reversed_claims = inspect(&bad_window, &options()).unwrap().claims().unwrap();
    assert_eq!(
        reversed_claims.check_time(UnixMillis(999), 500),
        Err(TimeError::InvalidRange)
    );

    // High-bit issuer_id values map to negative i32 rather than large positive values.
    let issuer_span = field_span(1);
    for (raw_u32, expected_i32) in [(0x8000_0000u32, i32::MIN), (0xFFFF_FFFFu32, -1)] {
        let mut v = VECTOR.to_vec();
        v[issuer_span.start() + 4..issuer_span.end()].copy_from_slice(&raw_u32.to_be_bytes());
        let claims = inspect(&v, &options()).unwrap().claims().unwrap();
        assert_eq!(claims.issuer_id, raw_u32);
        assert_eq!(claims.issuer_id_i32(), expected_i32);
        assert!(claims.issuer_id_i32() < 0);
    }

    // Zero account_id is detectable through AccountId::is_zero.
    let account_span = field_span(4);
    let mut zero_account = VECTOR.to_vec();
    zero_account[account_span.start() + 4..account_span.end()].fill(0);
    assert!(
        inspect(&zero_account, &options())
            .unwrap()
            .claims()
            .unwrap()
            .account_id
            .is_zero()
    );

    assert!(psn_codec::identity::is_legacy_online_id("1ab"));
    assert!(!psn_codec::identity::is_legacy_online_id("ab/evil"));
}
#[test]
fn deterministic_mutation_and_arbitrary_byte_campaign() {
    let mut seed = 0x70a166e0u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for iteration in 0..50000 {
        let mut v = if iteration % 2 == 0 {
            VECTOR.to_vec()
        } else {
            (0..(next() % 1024)).map(|_| next() as u8).collect()
        };
        for _ in 0..1 + next() % 8 {
            if !v.is_empty() {
                let i = (next() as usize) % v.len();
                v[i] = next() as u8;
            }
        }
        if let Ok(report) = recover(&v, &options()) {
            for s in report.bodies().iter().chain(report.footers()) {
                for f in s.fields() {
                    assert!(f.span().start() >= s.field().payload_span().start());
                    assert!(f.span().end() <= s.field().span().end());
                    assert_eq!(f.bytes(), &v[f.payload_span().range()]);
                }
            }
            if let Ok(t) = inspect(&v, &options()) {
                assert!(report.is_conformant());
                let _ = t.claims().unwrap();
                assert_eq!(t.as_bytes(), v);
            }
        }
    }
}

#[test]
fn scalar_width_defects_with_consistent_container_sizes() {
    for index in [1, 2, 3, 4, 9] {
        let span = field_span(index);
        let mut v = VECTOR.to_vec();
        v.remove(span.end() - 1);
        let len = (span.len() - 5) as u16;
        v[span.start() + 2..span.start() + 4].copy_from_slice(&len.to_be_bytes());
        let len = u16::from_be_bytes([v[10], v[11]]) - 1;
        v[10..12].copy_from_slice(&len.to_be_bytes());
        fix_length(&mut v);
        rejects(&v, Code::InvalidWidth);
    }
}
#[test]
fn check_time_extreme_timestamps_do_not_overflow() {
    let mut v = VECTOR.to_vec();
    let span = field_span(3);
    v[span.start() + 4..span.end()].copy_from_slice(&u64::MAX.to_be_bytes());
    let t = inspect(&v, &options()).unwrap();
    let claims = t.claims().unwrap();
    assert_eq!(claims.check_time(UnixMillis(u64::MAX), 1), Ok(()));
    assert_eq!(
        claims.check_time(UnixMillis(u64::MAX), 0),
        Err(TimeError::Expired)
    );
    assert_eq!(claims.check_time(UnixMillis(0), u64::MAX), Ok(()));
}
#[test]
fn each_single_byte_value_preserves_invariants() {
    for i in 0..VECTOR.len() {
        let mut v = VECTOR.to_vec();
        for byte in 0..=255 {
            v[i] = byte;
            if let Ok(t) = inspect(&v, &options()) {
                assert!(t.is_conformant());
                let _ = t.claims().unwrap();
                assert_eq!(t.as_bytes(), v);
            }
        }
    }
}

#[test]
fn partial_diagnostic_reports_cannot_expose_complete_claims_or_signing_inputs() {
    let mut broken_type = VECTOR.to_vec();
    broken_type[field_span(5).start() + 1] = 8;
    let mut duplicate = VECTOR.to_vec();
    let span = inspect(VECTOR, &options()).unwrap().bodies()[0]
        .field()
        .span();
    duplicate.extend(&VECTOR[span.range()]);
    fix_length(&mut duplicate);
    let mut damaged_tail = VECTOR.to_vec();
    damaged_tail[field_span(10).start() + 3] = 255;
    for bytes in [
        &VECTOR[..4],
        &VECTOR[..100],
        &broken_type,
        &duplicate,
        &damaged_tail,
    ] {
        for cap in [0, 32] {
            let mut o = options();
            o.mode = ParseMode::Diagnostic;
            o.limits.max_diagnostics = cap;
            let report = inspect(bytes, &o).unwrap();
            assert!(!report.is_conformant());
            assert!(report.claims().is_err());
            assert!(report.rpcn_signed_bytes().is_err());
            assert!(report.psn_signed_bytes().is_err());
            assert!(report.signature_bytes().is_err());
            assert!(report.key_marker().is_err());
            assert!(report.entitlement_bytes().is_err());
            assert_eq!(report.as_bytes(), bytes);
        }
    }
}
#[test]
fn claims_are_borrowed_from_one_inspection_and_outlive_report_metadata() {
    let claims = {
        let report = inspect(VECTOR, &options()).unwrap();
        report.claims().unwrap()
    };
    assert_eq!(claims.np_id.online_id().as_str(), "Test_Player");
    assert_eq!(claims.serial.as_ptr(), VECTOR[16..].as_ptr());
    assert_eq!(
        claims.service_id,
        psn_codec::ServiceId::from_str_nul_padded("TEST-SERVICE").unwrap()
    );
    assert!(claims.service_id.contains("SERVICE"));
    assert_eq!(claims.check_time(UnixMillis(1500), 0), Ok(()));
}
