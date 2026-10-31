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

const PSN20: &[u8] = include_bytes!("fixtures/psn20-synthetic.bin");
const PSN21: &[u8] = include_bytes!("fixtures/psn21-synthetic.bin");
const PSN30: &[u8] = include_bytes!("fixtures/psn30-synthetic.bin");
fn options(profile: Profile) -> Options {
    Options {
        profile,
        ..Default::default()
    }
}
fn cases() -> [(Profile, &'static [u8]); 3] {
    [
        (Profile::Psn20, PSN20),
        (Profile::Psn21, PSN21),
        (Profile::Psn30, PSN30),
    ]
}
fn fix(v: &mut [u8]) {
    let n = (v.len() - 8) as u32;
    v[4..8].copy_from_slice(&n.to_be_bytes());
}
#[test]
fn independent_psn_layouts_and_signature_spans() {
    for (profile, raw) in cases() {
        let t = inspect(raw, &options(profile)).unwrap();
        let c = t.claims().unwrap();
        assert_eq!(t.profile(), profile);
        assert_eq!(t.version(), Some(profile.version()));
        assert_eq!(c.np_id.online_id().as_str(), "Synthetic_User");
        assert_eq!(u64::from(c.account_id), 123456);
        assert_eq!(c.status, 0x18000200);
        assert_eq!(c.region, b"fr\0\x02");
        assert_eq!(t.psn_signed_bytes().unwrap(), &raw[..raw.len() - 20]);
        assert_eq!(t.signature_bytes().unwrap(), [0; 20]);
        assert_eq!(t.as_bytes(), raw);
        assert_eq!(t.entitlement_bytes().unwrap(), None);
        if profile == Profile::Psn30 {
            assert_eq!(
                c.date_of_birth,
                Some(BirthDate {
                    year: 2000,
                    month: 2,
                    day: 29
                })
            );
        } else {
            assert_eq!(c.date_of_birth, None);
        }
    }
    assert_eq!(PSN20.len(), 212);
    assert_eq!(PSN21.len(), 212);
    assert_eq!(PSN30.len(), 220);
    assert!(
        !format!(
            "{:?}",
            BirthDate {
                year: 2000,
                month: 2,
                day: 29
            }
        )
        .contains("2000")
    );
}
#[test]
fn every_profile_fixture_prefix_and_wrong_profile_version() {
    for (profile, raw) in cases() {
        let o = options(profile);
        for n in 0..raw.len() {
            assert!(inspect(&raw[..n], &o).is_err(), "{profile:?}/{n}");
            assert!(
                recover(&raw[..n], &o)
                    .map(|r| !r.is_conformant())
                    .unwrap_or(true)
            );
        }
        for (other, _) in cases() {
            if other.version() != profile.version() {
                assert_eq!(
                    inspect(raw, &options(other)).unwrap_err().code,
                    Code::UnsupportedVersion
                );
            }
        }
    }
}
#[test]
fn psn21_entitlement_tail_is_explicit_opaque_and_bounded() {
    let o = options(Profile::Psn21);
    let report = recover(PSN21, &o).unwrap();
    let span = report.bodies()[0].fields()[10].span();
    let mut v = PSN21.to_vec();
    v.splice(span.range(), [0x30, 1, 0, 5, 0xff, 0x10, 0x20, 0x30, 0x40]);
    v[10..12].copy_from_slice(&169u16.to_be_bytes());
    fix(&mut v);
    let t = inspect(&v, &o).unwrap();
    assert_eq!(
        t.entitlement_bytes().unwrap(),
        Some(&[0xff, 0x10, 0x20, 0x30, 0x40][..])
    );
    assert!(inspect(&v, &options(Profile::Rpcn21)).is_err());
    v[span.start() + 3] = 255;
    assert!(inspect(&v, &o).is_err());
}
#[test]
fn date_age_status_width_and_tail_order_are_validated() {
    let o = options(Profile::Psn30);
    let r = recover(PSN30, &o).unwrap();
    for i in 9..13 {
        let span = r.bodies()[0].fields()[i].span();
        let mut v = PSN30.to_vec();
        v[span.start() + 1] ^= 0x40;
        assert!(inspect(&v, &o).is_err());
    }
    let mut v = PSN30.to_vec();
    let span = r.bodies()[0].fields()[9].span();
    v[span.start() + 3] = 3;
    assert!(inspect(&v, &o).is_err());
    // A tail outside the body must fail exact section-boundary validation.
    let mut v = PSN30.to_vec();
    v[10..12].copy_from_slice(&164u16.to_be_bytes());
    assert!(inspect(&v, &o).is_err());
}
#[test]
fn profiles_reject_opposite_family_convention_without_verifying_signature() {
    let mut v = PSN21.to_vec();
    let r = recover(PSN21, &options(Profile::Psn21)).unwrap();
    let marker = r.footers()[0].fields()[0].payload_span();
    v[marker.range()].copy_from_slice(b"RPCN");
    assert_eq!(
        inspect(&v, &options(Profile::Psn21)).unwrap_err().code,
        Code::ProfileMismatch
    );
    let t = inspect(&v, &options(Profile::Rpcn21)).unwrap();
    assert_eq!(t.profile(), Profile::Rpcn21);
    assert_eq!(t.key_marker().unwrap(), b"RPCN");
    assert_eq!(t.signature_bytes().unwrap(), [0; 20]); // remains explicitly unverified
}
#[test]
fn profile_mutation_invariants() {
    for (profile, raw) in cases() {
        let o = options(profile);
        for i in 0..raw.len() {
            let mut v = raw.to_vec();
            for byte in 0..=255 {
                v[i] = byte;
                if let Ok(t) = inspect(&v, &o) {
                    let _ = t.claims().unwrap();
                    let _ = t.psn_signed_bytes().unwrap();
                    let _ = t.entitlement_bytes().unwrap();
                    assert!(t.is_conformant());
                    assert_eq!(t.as_bytes(), v);
                }
            }
        }
    }
}
#[test]
fn budget_caps_apply_to_new_profiles_even_without_diagnostics() {
    for (profile, raw) in cases() {
        let mut o = options(profile);
        o.limits.max_diagnostics = 0;
        let mut v = raw.to_vec();
        v[7] ^= 1;
        assert!(recover(&v, &o).unwrap().diagnostics().is_empty());
        assert!(inspect(&v, &o).is_err());
        o.limits.max_ticket_bytes = raw.len() - 1;
        assert_eq!(recover(raw, &o).unwrap_err().code, Code::LimitExceeded);
    }
}
