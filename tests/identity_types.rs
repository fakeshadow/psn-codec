use psn_codec::identity::IdentityError;
use psn_codec::ticket::{Code, Options, ParseMode, inspect};
use psn_codec::{AccountId, OnlineId, SceNpId, ServiceId};
#[test]
fn public_ticket_claims_expose_owned_nested_identity_types() {
    let raw = include_bytes!("fixtures/rpcn21-unsigned.bin");
    let claims = inspect(raw, &Options::default()).unwrap().claims().unwrap();
    let account: AccountId = claims.account_id;
    let online: OnlineId = *claims.np_id.online_id();
    let service: ServiceId = claims.service_id;
    assert_eq!(u64::from(account), 0x0102030405060708);
    assert_eq!(online.as_str(), "Test_Player");
    assert!(claims.np_id.platform_bytes().is_none());
    assert_eq!(service.as_str().unwrap(), "TEST-SERVICE");
    assert_eq!(service.as_bytes().len(), 24);
}
#[test]
fn online_id_width_is_separate_from_service_registration_policy() {
    assert!(OnlineId::try_from("1234567890123456").is_ok());
    assert!(OnlineId::try_from("").is_ok());
    assert_eq!(
        OnlineId::try_from("12345678901234567").unwrap_err(),
        IdentityError::OnlineIdTooLong { actual: 17 }
    );
    assert_eq!(
        OnlineId::try_from("A\0B").unwrap_err(),
        IdentityError::InvalidPadding
    );
    assert!(!psn_codec::identity::is_legacy_online_id(
        OnlineId::try_from("A").unwrap().as_str()
    ));
}
#[test]
fn long_logical_ticket_name_is_diagnostic_only_and_never_panics_in_claims() {
    let mut raw = include_bytes!("fixtures/rpcn21-unsigned.bin").to_vec();
    raw[84..116].fill(b'A');
    assert_eq!(
        inspect(&raw, &Options::default()).unwrap_err().code,
        Code::InvalidWidth
    );
    let options = Options {
        mode: ParseMode::Diagnostic,
        ..Default::default()
    };
    let report = inspect(&raw, &options).unwrap();
    assert!(report.claims().is_err());
}
#[test]
fn sce_np_id_preserves_every_byte_and_does_not_imply_account_number() {
    let mut raw = [0xa5; 36];
    raw[..7].copy_from_slice(b"Alice\0\xff");
    let id = SceNpId::try_from(&raw[..]).unwrap();
    assert_eq!(id.online_id().as_str(), "Alice");
    assert_eq!(id.platform_bytes(), Some(&raw));
    assert_eq!(id.handle_bytes(), Some(&raw[..20]));
    assert_eq!(id.option_bytes(), Some(&[0xa5; 8][..]));
    assert_eq!(id.reserved_bytes(), Some(&[0xa5; 8][..]));
    assert_ne!(id.platform_bytes().unwrap().as_ptr(), raw.as_ptr());
    // Same logical name, different options: raw platform identities stay distinct.
    let mut other = raw;
    other[20] ^= 1;
    assert_ne!(id, SceNpId::try_from(&other[..]).unwrap());
    assert_eq!(
        id.online_id(),
        SceNpId::try_from(&other[..]).unwrap().online_id()
    );
}
#[test]
fn sce_np_id_rejects_bad_width_unterminated_and_invalid_name_encoding() {
    for len in 0..36 {
        assert!(SceNpId::try_from(&[0; 36][..len]).is_err());
    }
    assert!(SceNpId::try_from(&[0; 37][..]).is_err());
    assert_eq!(
        SceNpId::try_from(&[b'A'; 36][..]).unwrap_err(),
        IdentityError::MissingTerminator
    );
    let mut raw = [0; 36];
    raw[0] = 255;
    assert_eq!(
        SceNpId::try_from(&raw[..]).unwrap_err(),
        IdentityError::InvalidUtf8
    );
    raw[..16].fill(b'A');
    raw[16] = 0;
    assert_eq!(
        SceNpId::try_from(&raw[..])
            .unwrap()
            .online_id()
            .as_str()
            .len(),
        16
    );
}
#[test]
fn service_ids_preserve_binary_values_and_validate_text_only_on_request() {
    assert!(ServiceId::try_from(&[0; 23][..]).is_err());
    let raw = [0xff; 24];
    let id = ServiceId::from(raw);
    assert_eq!(id.as_bytes(), &raw);
    assert_eq!(id.as_str(), Err(IdentityError::InvalidUtf8));
    let mut raw = [0; 24];
    raw[0] = b'A';
    raw[23] = b'B';
    assert_eq!(
        ServiceId::from(raw).as_str(),
        Err(IdentityError::InvalidPadding)
    );
}
#[test]
fn identity_debug_formatting_is_redacted() {
    let mut raw = [0; 36];
    raw[..5].copy_from_slice(b"Alice");
    let id = SceNpId::try_from(&raw[..]).unwrap();
    let service = [b'S'; 24];
    for text in [
        format!("{:?}", OnlineId::try_from("Alice").unwrap()),
        format!("{id:?}"),
        format!("{:?}", AccountId::from(123456789)),
        format!("{:?}", ServiceId::from(service)),
    ] {
        assert!(!text.contains("Alice"));
        assert!(!text.contains("123456789"));
        assert!(!text.contains("SSSS"));
    }
}

#[test]
fn name_only_np_identity_has_no_fabricated_platform_bytes() {
    let name = OnlineId::try_from("Alice").unwrap();
    let id = SceNpId::from(name);
    assert_eq!(id.online_id(), &name);
    assert!(id.platform_bytes().is_none());
    assert!(id.handle_bytes().is_none());
    assert!(id.option_bytes().is_none());
    assert!(id.reserved_bytes().is_none());
    let mut wire = [0; 36];
    wire[..5].copy_from_slice(b"Alice");
    let complete = SceNpId::try_from(&wire[..]).unwrap();
    assert_eq!(id.online_id(), complete.online_id());
    assert_ne!(id, complete);
}
#[test]
fn identities_copy_input_and_are_independent_of_later_input_mutation() {
    fn assert_copy<T: Copy>() {}
    assert_copy::<AccountId>();
    assert_copy::<OnlineId>();
    assert_copy::<ServiceId>();
    assert_copy::<SceNpId>();
    let mut name = String::from("Alice");
    let online = OnlineId::try_from(name.as_str()).unwrap();
    name.clear();
    assert_eq!(online.as_str(), "Alice");
    let mut wire = [0xa5; 36];
    wire[..6].copy_from_slice(b"Alice\0");
    let expected = wire;
    let id = SceNpId::try_from(&wire[..]).unwrap();
    let copy = id;
    wire.fill(0);
    assert_eq!(id.platform_bytes(), Some(&expected));
    assert_eq!(copy, id);
    let mut service = [b'S'; 24];
    let id = ServiceId::try_from(&service[..]).unwrap();
    service.fill(0);
    assert_eq!(id.as_bytes(), &[b'S'; 24]);
}
#[test]
fn identity_fields_outlive_the_ticket_input_without_lifetimes() {
    let (account, np_id, service) = {
        let raw = include_bytes!("fixtures/rpcn21-unsigned.bin").to_vec();
        let report = inspect(&raw, &Options::default()).unwrap();
        let claims = report.claims().unwrap();
        (claims.account_id, claims.np_id, claims.service_id)
    };
    assert_eq!(u64::from(account), 0x0102030405060708);
    assert_eq!(np_id.online_id().as_str(), "Test_Player");
    assert!(np_id.platform_bytes().is_none());
    assert_eq!(service.as_str().unwrap(), "TEST-SERVICE");
}
