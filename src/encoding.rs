//! Optional standard-alphabet base64 decoding with input/output budgets.
use alloc::vec::Vec;
use base64::{Engine, engine::general_purpose::STANDARD};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Whitespace {
    Reject,
    AllowAscii,
}
#[derive(Clone, Copy, Debug)]
pub struct Base64Options {
    pub max_encoded_bytes: usize,
    pub max_decoded_bytes: usize,
    pub whitespace: Whitespace,
}
impl Default for Base64Options {
    fn default() -> Self {
        Self {
            max_encoded_bytes: 131072,
            max_decoded_bytes: 65536,
            whitespace: Whitespace::Reject,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base64Error {
    EncodedLimit,
    DecodedLimit,
    InvalidEncoding,
}
impl core::fmt::Display for Base64Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
#[cfg(feature = "std")]
impl std::error::Error for Base64Error {}
/// Canonical padding and zero pad bits are required. ASCII whitespace can be
/// explicitly allowed; its bytes count against the encoded-input budget.
pub fn decode_base64(input: &[u8], options: &Base64Options) -> Result<Vec<u8>, Base64Error> {
    if input.len() > options.max_encoded_bytes {
        return Err(Base64Error::EncodedLimit);
    }
    let normalized;
    let encoded = match options.whitespace {
        Whitespace::Reject => input,
        Whitespace::AllowAscii => {
            normalized = input
                .iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .collect::<Vec<_>>();
            &normalized
        }
    };
    if encoded.len() % 4 != 0 {
        return Err(Base64Error::InvalidEncoding);
    }
    let padding = encoded.iter().rev().take_while(|b| **b == b'=').count();
    if padding > 2 {
        return Err(Base64Error::InvalidEncoding);
    }
    let size = (encoded.len() / 4)
        .checked_mul(3)
        .and_then(|n| n.checked_sub(padding))
        .ok_or(Base64Error::InvalidEncoding)?;
    if size > options.max_decoded_bytes {
        return Err(Base64Error::DecodedLimit);
    }
    let mut out = alloc::vec![0; size];
    let len = STANDARD
        .decode_slice(encoded, &mut out)
        .map_err(|_| Base64Error::InvalidEncoding)?;
    out.truncate(len);
    Ok(out)
}
