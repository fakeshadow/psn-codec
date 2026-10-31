#![no_main]
use libfuzzer_sys::fuzz_target;
use psn_codec::ticket::*;
fuzz_target!(|data: &[u8]| {
    for profile in [
        Profile::Rpcn21,
        Profile::Psn20,
        Profile::Psn21,
        Profile::Psn30,
    ] {
        let options = Options {
            profile,
            ..Default::default()
        };
        if let Ok(report) = inspect(
            data,
            &Options {
                mode: ParseMode::Diagnostic,
                ..options
            },
        ) {
            if let Ok(ticket) = inspect(data, &options) {
                assert!(report.is_conformant());
                let _ = ticket.claims().unwrap();
                let _ = ticket.psn_signed_bytes().unwrap();
                let _ = ticket.entitlement_bytes().unwrap();
                assert_eq!(ticket.as_bytes(), data);
            }
            if !report.is_conformant() {
                assert!(report.claims().is_err());
                assert!(report.psn_signed_bytes().is_err());
            }
            for section in report.bodies().iter().chain(report.footers()) {
                for field in section.fields() {
                    assert!(field.span().start() >= section.field().payload_span().start());
                    assert!(field.span().end() <= section.field().span().end());
                }
            }
        }
    }
});
