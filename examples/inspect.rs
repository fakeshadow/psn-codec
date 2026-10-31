use psn_codec::ticket::{Options, inspect};
fn main() {
    let bytes = include_bytes!("../tests/fixtures/rpcn21-unsigned.bin");
    let report = inspect(bytes, &Options::default()).expect("within budget");
    println!("{report:?}"); // Metadata only, no credential contents.
}
