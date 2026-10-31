use psn_codec::ticket::*;
const RPCN: &[u8] = include_bytes!("fixtures/rpcn21-unsigned.bin");
const PSN: &[u8] = include_bytes!("fixtures/psn21-synthetic.bin");
fn options(profile: Profile) -> Options {
    Options {
        profile,
        ..Default::default()
    }
}
fn marked_rpcn() -> Vec<u8> {
    let report = inspect(RPCN, &options(Profile::Rpcn21)).unwrap();
    let marker = report.footers()[0].fields()[0].payload_span().range();
    let mut raw = RPCN.to_vec();
    raw[marker].copy_from_slice(b"RPCN");
    raw
}
#[test]
fn same_version_psn_and_rpcn_profiles_are_disjoint_in_both_retry_orders() {
    let marked = marked_rpcn();
    for (raw, expected) in [
        (PSN, Profile::Psn21),
        (RPCN, Profile::Rpcn21),
        (&marked[..], Profile::Rpcn21),
    ] {
        for profiles in [
            [Profile::Psn21, Profile::Rpcn21],
            [Profile::Rpcn21, Profile::Psn21],
        ] {
            let matches: Vec<_> = profiles
                .into_iter()
                .filter_map(|profile| inspect(raw, &options(profile)).ok().map(|r| r.profile()))
                .collect();
            assert_eq!(matches, [expected]);
        }
    }
}
#[test]
fn family_mismatch_is_terminal_before_field_and_diagnostic_budgets_in_both_modes() {
    for (raw, right, wrong) in [
        (RPCN, Profile::Rpcn21, Profile::Psn21),
        (PSN, Profile::Psn21, Profile::Rpcn21),
    ] {
        let marker_at = inspect(raw, &options(right)).unwrap().footers()[0].fields()[0]
            .payload_span()
            .start();
        // Corrupt a body-child length too: the footer convention is rejected
        // without visiting the body or consuming any TLV/diagnostic budget.
        let mut corrupt = raw.to_vec();
        corrupt[14..16].fill(0xff);
        for mode in [ParseMode::Strict, ParseMode::Diagnostic] {
            let mut o = options(wrong);
            o.mode = mode;
            o.limits.max_fields = 0;
            o.limits.max_diagnostics = 0;
            for candidate in [raw, &corrupt[..]] {
                let error = inspect(candidate, &o).unwrap_err();
                assert_eq!(error.code, Code::ProfileMismatch);
                assert_eq!(error.offset, marker_at);
            }
        }
    }
}
#[test]
fn unsigned_rpcn_fallback_is_an_exact_convention_not_any_zero_key_marker() {
    let report = inspect(RPCN, &options(Profile::Rpcn21)).unwrap();
    let signature = report.footers()[0].fields()[1].payload_span().range();
    let mut changed = RPCN.to_vec();
    changed[signature.start] = 1;
    assert_eq!(
        inspect(&changed, &options(Profile::Rpcn21))
            .unwrap_err()
            .code,
        Code::ProfileMismatch
    );
    // An opaque PSN key identifier may be zero; it is not by itself an RPCN tag.
    assert!(inspect(&changed, &options(Profile::Psn21)).is_ok());
    let mut shorter = RPCN.to_vec();
    shorter.pop();
    let signature_len = signature.len() - 1;
    shorter[signature.start - 2..signature.start]
        .copy_from_slice(&(signature_len as u16).to_be_bytes());
    let footer_at = report.footers()[0].field().span().start();
    let footer_len = shorter.len() - footer_at - 4;
    shorter[footer_at + 2..footer_at + 4].copy_from_slice(&(footer_len as u16).to_be_bytes());
    let payload = shorter.len() - 8;
    shorter[4..8].copy_from_slice(&(payload as u32).to_be_bytes());
    assert_eq!(
        inspect(&shorter, &options(Profile::Rpcn21))
            .unwrap_err()
            .code,
        Code::ProfileMismatch
    );
    assert!(inspect(&shorter, &options(Profile::Psn21)).is_ok());
}
#[test]
fn malformed_footer_and_size_limits_keep_structural_resource_errors() {
    let report = inspect(PSN, &options(Profile::Psn21)).unwrap();
    let mut malformed = PSN.to_vec();
    let header = report.footers()[0].fields()[0].span().start();
    malformed[header + 1] = 7;
    assert_eq!(
        inspect(&malformed, &options(Profile::Psn21))
            .unwrap_err()
            .code,
        Code::UnexpectedFieldType
    );
    let mut o = options(Profile::Rpcn21);
    o.limits.max_ticket_bytes = PSN.len() - 1;
    assert_eq!(inspect(PSN, &o).unwrap_err().code, Code::LimitExceeded);
}
