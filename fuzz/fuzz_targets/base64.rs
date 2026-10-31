#![no_main]
use libfuzzer_sys::fuzz_target;
use psn_codec::encoding::*;
fuzz_target!(|data: &[u8]| {
    for whitespace in [Whitespace::Reject, Whitespace::AllowAscii] {
        let options = Base64Options { whitespace, ..Default::default() };
        if let Ok(output) = decode_base64(data, &options) {
            assert!(output.len() <= options.max_decoded_bytes);
        }
    }
});
