//! Caller-side examples, not additional psn-codec public APIs.
//! Format admission remains claimed/unverified, regardless of matched profile.
use psn_codec::identity::is_legacy_online_id;
use psn_codec::ticket::{Diagnostic, Options, Profile, TicketReport, inspect};

/// A caller may accept both families concurrently. Footer conventions distinguish
/// otherwise overlapping 2.1 layouts; neither convention authenticates an issuer.
/// This list exercises all known profiles; it is not a recommended deployment
/// default. The two-profile example selects only Psn21 and Rpcn21.
pub const ALLOWED: [Profile; 4] = [
    Profile::Psn20,
    Profile::Psn21,
    Profile::Psn30,
    Profile::Rpcn21,
];

#[derive(Debug)]
pub enum Rejection {
    Envelope,
    NoProfiles,
    Profiles(Vec<(Profile, Diagnostic)>),
    Claims(Diagnostic),
    OnlineId,
    #[cfg(feature = "base64")]
    Base64(psn_codec::encoding::Base64Error),
}

/// One strict inspect call per allowed profile until a conformant one matches.
/// An invalid schema is never rescued by diagnostic-mode partial claims.
pub fn admit<'a>(raw: &'a [u8], allowed: &[Profile]) -> Result<TicketReport<'a>, Rejection> {
    if allowed.is_empty() {
        return Err(Rejection::NoProfiles);
    }
    let mut failures = Vec::new();
    for &profile in allowed {
        match inspect(
            raw,
            &Options {
                profile,
                ..Options::default()
            },
        ) {
            Ok(report) => {
                let claims = report.claims().map_err(Rejection::Claims)?;
                if !is_legacy_online_id(claims.np_id.online_id().as_str()) {
                    return Err(Rejection::OnlineId);
                }
                return Ok(report);
            }
            Err(error) => failures.push((profile, error)),
        }
    }
    Err(Rejection::Profiles(failures))
}

/// Decode an exact u16 envelope after any outer framing checks. Its length
/// must describe the whole remaining payload; no ignored trailing bytes.
pub fn prefixed<'a>(request: &'a [u8], allowed: &[Profile]) -> Result<TicketReport<'a>, Rejection> {
    let prefix: [u8; 2] = request
        .get(..2)
        .ok_or(Rejection::Envelope)?
        .try_into()
        .map_err(|_| Rejection::Envelope)?;
    if usize::from(u16::from_be_bytes(prefix)) != request.len() - 2 {
        return Err(Rejection::Envelope);
    }
    admit(&request[2..], allowed)
}

/// Decode a raw ticket or an exact u16 envelope after outer framing checks.
/// Only a complete successful interpretation may yield an identity. A raw-first
/// attempt preserves the existing envelope preference without a partial parser.
pub fn raw_or_prefixed<'a>(
    payload: &'a [u8],
    allowed: &[Profile],
) -> Result<TicketReport<'a>, Rejection> {
    match admit(payload, allowed) {
        Ok(report) => Ok(report),
        Err(raw_error) => {
            let Some(prefix) = payload.get(..2) else {
                return Err(raw_error);
            };
            if usize::from(u16::from_be_bytes([prefix[0], prefix[1]])) != payload.len() - 2 {
                return Err(raw_error);
            }
            admit(&payload[2..], allowed)
        }
    }
}

#[cfg(feature = "base64")]
#[derive(Clone, Copy, Debug)]
pub struct OwnedLogin {
    pub version: u32,
    pub account_id: psn_codec::AccountId,
    pub np_id: psn_codec::SceNpId,
    pub service_id: psn_codec::ServiceId,
}

/// Decode base64 into owned identity values; envelope and storage policy stay local.
/// Return owned values because the decoded buffer is local. No persistence-key
/// scheme or authenticated realm is inferred from the name/profile/issuer claim.
#[cfg(feature = "base64")]
pub fn base64_identity(
    encoded: &[u8],
    allowed: &[Profile],
    options: &psn_codec::encoding::Base64Options,
) -> Result<OwnedLogin, Rejection> {
    let raw = psn_codec::encoding::decode_base64(encoded, options).map_err(Rejection::Base64)?;
    let report = admit(&raw, allowed)?;
    let claims = report.claims().map_err(Rejection::Claims)?;
    Ok(OwnedLogin {
        version: report
            .version()
            .expect("strict report has a complete header"),
        account_id: claims.account_id,
        np_id: claims.np_id,
        service_id: claims.service_id,
    })
}
