#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! Bounded binary ticket decoding. Parsing never authenticates an identity.
//!
//! ```
//! use psn_codec::ticket::{inspect, Options};
//! let error = inspect(&[], &Options::default()).unwrap_err();
//! assert_eq!(error.code, psn_codec::ticket::Code::TruncatedHeader);
//! // Identity values can be copied out before dropping the input/report.
//! let (account, np_id, service) = {
//!     let bytes = include_bytes!("../tests/fixtures/rpcn21-unsigned.bin").to_vec();
//!     let report = inspect(&bytes, &Options::default())?;
//!     let claims = report.claims()?;
//!     (claims.account_id, claims.np_id, claims.service_id)
//! };
//! assert_eq!(u64::from(account), 0x0102030405060708);
//! assert_eq!(np_id.online_id().as_str(), "Test_Player");
//! assert!(np_id.platform_bytes().is_none());
//! assert_eq!(service.as_str().unwrap(), "TEST-SERVICE");
//! # Ok::<(), psn_codec::ticket::Diagnostic>(())
//! ```
extern crate alloc;
#[cfg(feature = "base64")]
pub mod encoding;
pub mod identity;
pub use identity::{AccountId, OnlineId, SceNpId, ServiceId};
/// Collect conformant layouts from an explicitly allowed list. Different
/// versions skip cheaply; a match is still not issuer authentication.
///
/// ```
/// use psn_codec::ticket::{inspect, Code, Diagnostic, Options, Profile};
/// let bytes = include_bytes!("../tests/fixtures/psn30-synthetic.bin");
/// let mut matches = Vec::new();
/// for profile in [Profile::Psn20, Profile::Psn21, Profile::Psn30] {
///     let options = Options { profile, ..Default::default() };
///     match inspect(bytes, &options) {
///         Ok(report) => {
///             let claims = report.claims()?; // no reparsing
///             assert_eq!(claims.np_id.online_id().as_str(), "Synthetic_User");
///             matches.push(report.profile());
///         }
///         Err(error) if matches!(error.code, Code::UnsupportedVersion | Code::ProfileMismatch) => continue,
///         Err(error) => return Err(error),
///     }
/// }
/// assert_eq!(matches, [Profile::Psn30]);
/// # Ok::<(), Diagnostic>(())
/// ```
pub mod ticket;
