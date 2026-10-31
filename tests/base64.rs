#![cfg(feature = "base64")]
use psn_codec::encoding::*;
#[test]
fn vectors_and_canonical_rejections() {
    let o = Base64Options::default();
    for (encoded, plain) in [
        ("", ""),
        ("Zg==", "f"),
        ("Zm8=", "fo"),
        ("Zm9v", "foo"),
        ("Zm9vYmFy", "foobar"),
    ] {
        assert_eq!(
            decode_base64(encoded.as_bytes(), &o).unwrap(),
            plain.as_bytes()
        );
    }
    for encoded in ["Zh==", "Zm9=", "Zg", "Zg===", "=g==", "Zm-_=", "Zm9v\n"] {
        assert!(decode_base64(encoded.as_bytes(), &o).is_err(), "{encoded}");
    }
    let mut o = o;
    o.whitespace = Whitespace::AllowAscii;
    assert_eq!(decode_base64(b" Zg==\r\n", &o).unwrap(), b"f");
    o.max_encoded_bytes = 4;
    assert_eq!(decode_base64(b" Zg==", &o), Err(Base64Error::EncodedLimit));
    o.max_decoded_bytes = 0;
    assert_eq!(decode_base64(b"Zg==", &o), Err(Base64Error::DecodedLimit));
}

#[test]
fn bounded_arbitrary_base64_and_padding() {
    let mut seed = 20261031u64;
    for len in 0..512 {
        let mut input = Vec::new();
        for _ in 0..len {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            input.push(seed as u8);
        }
        for whitespace in [Whitespace::Reject, Whitespace::AllowAscii] {
            let o = Base64Options {
                max_encoded_bytes: 511,
                max_decoded_bytes: 64,
                whitespace,
            };
            if let Ok(out) = decode_base64(&input, &o) {
                assert!(out.len() <= 64);
            }
        }
    }
}
