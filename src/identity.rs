//! Owned platform identity values. All have private fields and implement Copy.
//! None authenticates an identity. Construction copies short values; accessors
//! expose immutable views, so input mutation cannot change an existing value.
//!
//! ```
//! use psn_codec::{AccountId, OnlineId, SceNpId, ServiceId};
//! let account = AccountId::from(42);
//! let name_only = SceNpId::from(OnlineId::try_from("Player_1")?);
//! assert_eq!(name_only.online_id().as_str(), "Player_1");
//! assert!(name_only.platform_bytes().is_none());
//! let mut wire = [0u8; 36];
//! wire[..8].copy_from_slice(b"Player_1");
//! let platform = SceNpId::try_from(&wire[..])?;
//! assert_eq!(platform.online_id(), name_only.online_id());
//! assert!(platform.platform_bytes().is_some());
//! let service = ServiceId::from([0u8; 24]);
//! assert_eq!(service.as_bytes().len(), 24);
//! assert_eq!(ServiceId::try_from(&[0u8; 24][..])?, service);
//! let independent_name: OnlineId = *platform.online_id();
//! assert_eq!(independent_name.as_str(), "Player_1");
//! assert_eq!(u64::from(account), 42);
//! # Ok::<(), psn_codec::identity::IdentityError>(())
//! ```
use core::{fmt, str};

/// Numeric account claim. Acquire from [`Claims::account_id`](crate::ticket::Claims::account_id)
/// or `AccountId::from(number)`.
/// Extract with `u64::from(account)`; this is independent of [`SceNpId`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountId(u64);
impl From<u64> for AccountId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}
impl From<AccountId> for u64 {
    fn from(value: AccountId) -> Self {
        value.0
    }
}
impl fmt::Debug for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountId([redacted])")
    }
}

/// Validation metadata only, never raw identity contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityError {
    InvalidWidth { expected: usize, actual: usize },
    OnlineIdTooLong { actual: usize },
    MissingTerminator,
    InvalidUtf8,
    InvalidPadding,
}
impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
#[cfg(feature = "std")]
impl std::error::Error for IdentityError {}

/// Owned logical online ID: at most 16 UTF-8 bytes, no NUL, stored inline.
/// Acquire with `OnlineId::try_from(name)` or [`SceNpId::online_id`].
/// Minimum length and legacy ASCII alphabet are separate service policy.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OnlineId {
    bytes: [u8; 16],
    len: u8,
}
impl TryFrom<&str> for OnlineId {
    type Error = IdentityError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() > 16 {
            return Err(IdentityError::OnlineIdTooLong {
                actual: value.len(),
            });
        }
        if value.as_bytes().contains(&0) {
            return Err(IdentityError::InvalidPadding);
        }
        let mut bytes = [0; 16];
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        Ok(Self {
            bytes,
            len: value.len() as u8,
        })
    }
}
impl OnlineId {
    /// Logical name only; no padding. The reference borrows this owned value.
    pub fn as_str(&self) -> &str {
        str::from_utf8(self.as_bytes()).expect("validated UTF-8")
    }
    /// Immutable view of the logical name's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}
impl fmt::Debug for OnlineId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OnlineId([redacted])")
    }
}

/// Owned exact 24-byte service field. Acquire from
/// [`Claims::service_id`](crate::ticket::Claims::service_id),
/// `ServiceId::from(array)` or `ServiceId::try_from(slice)`. The latter requires
/// exactly 24 bytes. No padding/normalization is invented.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServiceId([u8; 24]);
impl From<[u8; 24]> for ServiceId {
    fn from(value: [u8; 24]) -> Self {
        Self(value)
    }
}
impl TryFrom<&[u8]> for ServiceId {
    type Error = IdentityError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let raw = value.try_into().map_err(|_| IdentityError::InvalidWidth {
            expected: 24,
            actual: value.len(),
        })?;
        Ok(Self(raw))
    }
}
impl ServiceId {
    /// Exact bytes including padding, borrowed immutably from this value.
    pub fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }
    /// Optional checked text interpretation; raw-byte equality remains exact.
    pub fn as_str(&self) -> Result<&str, IdentityError> {
        let end = self.0.iter().position(|b| *b == 0).unwrap_or(24);
        if self.0[end..].iter().any(|b| *b != 0) {
            return Err(IdentityError::InvalidPadding);
        }
        str::from_utf8(&self.0[..end]).map_err(|_| IdentityError::InvalidUtf8)
    }
}
impl fmt::Debug for ServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServiceId([redacted])")
    }
}

/// Owned logical NP identity with optional original platform representation.
/// Ticket [`Claims::np_id`](crate::ticket::Claims::np_id) and `SceNpId::from(online)`
/// carry a name with no platform bytes. `SceNpId::try_from(slice)` copies a
/// complete 36-byte record, requiring a UTF-8 name terminated within its first
/// 17 bytes. All unknown/padding bytes are preserved without interpretation.
/// Private fields keep the logical name consistent with any stored record.
/// This logical model is not an ABI-compatible 36-byte wire struct.
/// Equality/hashing include presence and all original bytes; compare online_id()
/// explicitly for logical-name equality. This is not a numeric account ID.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SceNpId {
    online_id: OnlineId,
    platform_bytes: Option<[u8; 36]>,
}
impl From<OnlineId> for SceNpId {
    fn from(online_id: OnlineId) -> Self {
        Self {
            online_id,
            platform_bytes: None,
        }
    }
}
impl TryFrom<&[u8]> for SceNpId {
    type Error = IdentityError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let raw: [u8; 36] = value.try_into().map_err(|_| IdentityError::InvalidWidth {
            expected: 36,
            actual: value.len(),
        })?;
        let end = raw[..17]
            .iter()
            .position(|b| *b == 0)
            .ok_or(IdentityError::MissingTerminator)?;
        let name = str::from_utf8(&raw[..end]).map_err(|_| IdentityError::InvalidUtf8)?;
        Ok(Self {
            online_id: OnlineId::try_from(name)?,
            platform_bytes: Some(raw),
        })
    }
}
impl SceNpId {
    /// Logical online name. Return a reference to avoid temporary-value borrows;
    /// copy the OnlineId with `*id.online_id()` when independent ownership is useful.
    pub fn online_id(&self) -> &OnlineId {
        &self.online_id
    }
    /// Original 36 bytes, or None for ticket/name-only identities. Never synthesized.
    pub fn platform_bytes(&self) -> Option<&[u8; 36]> {
        self.platform_bytes.as_ref()
    }
    /// Original 20-byte handle, including unused bytes; None without a record.
    pub fn handle_bytes(&self) -> Option<&[u8]> {
        self.platform_bytes.as_ref().map(|b| &b[..20])
    }
    /// Original eight option bytes; None without a record.
    pub fn option_bytes(&self) -> Option<&[u8]> {
        self.platform_bytes.as_ref().map(|b| &b[20..28])
    }
    /// Original eight reserved bytes; None without a record.
    pub fn reserved_bytes(&self) -> Option<&[u8]> {
        self.platform_bytes.as_ref().map(|b| &b[28..36])
    }
}
impl fmt::Debug for SceNpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SceNpId([redacted])")
    }
}

/// Legacy service name policy: 3–16 ASCII letters, digits, hyphens or underscores.
pub fn is_legacy_online_id(value: &str) -> bool {
    (3..=16).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
