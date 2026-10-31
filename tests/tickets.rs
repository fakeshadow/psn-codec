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
fn injected_time_service_and_name_policy() {
    let t = inspect(VECTOR, &options()).unwrap();
    let c = t.claims().unwrap();
    let mut p = ClaimsPolicy {
        expected_service_id: c.service_id,
        now: UnixMillis(1000),
        clock_skew_ms: 0,
        require_legacy_online_id: true,
    };
    assert_eq!(assess_claims(&t.claims().unwrap(), &p), Ok(()));
    p.now = UnixMillis(999);
    assert_eq!(
        assess_claims(&t.claims().unwrap(), &p),
        Err(PolicyError::NotYetValid)
    );
    p.now = UnixMillis(2000);
    assert_eq!(
        assess_claims(&t.claims().unwrap(), &p),
        Err(PolicyError::Expired)
    );
    p.clock_skew_ms = 1;
    assert_eq!(assess_claims(&t.claims().unwrap(), &p), Ok(()));
    p.expected_service_id = psn_codec::ServiceId::from([0; 24]);
    assert_eq!(
        assess_claims(&t.claims().unwrap(), &p),
        Err(PolicyError::ServiceMismatch)
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
fn policy_extreme_timestamps_do_not_overflow() {
    let mut v = VECTOR.to_vec();
    let span = field_span(3);
    v[span.start() + 4..span.end()].copy_from_slice(&u64::MAX.to_be_bytes());
    let t = inspect(&v, &options()).unwrap();
    let p = ClaimsPolicy {
        expected_service_id: t.claims().unwrap().service_id,
        now: UnixMillis(u64::MAX),
        clock_skew_ms: 1,
        require_legacy_online_id: false,
    };
    assert_eq!(assess_claims(&t.claims().unwrap(), &p), Ok(()));
    let p = ClaimsPolicy {
        clock_skew_ms: 0,
        ..p
    };
    assert_eq!(
        assess_claims(&t.claims().unwrap(), &p),
        Err(PolicyError::Expired)
    );
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
    let policy = ClaimsPolicy {
        expected_service_id: claims.service_id,
        now: UnixMillis(1500),
        clock_skew_ms: 0,
        require_legacy_online_id: true,
    };
    assert_eq!(assess_claims(&claims, &policy), Ok(()));
}
