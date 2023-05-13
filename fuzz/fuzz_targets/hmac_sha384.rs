#![no_main]
use libfuzzer_sys::fuzz_target;
use hmac::{Hmac, Mac};
use sha2::Sha384;

fuzz_target!(|input: (&[u8], &[u8])| {
    let (key, data) = input;
    type HmacSha384 = Hmac<Sha384>;
    let mut mac = HmacSha384::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.clone().finalize().into_bytes();
    mac.verify_slice(&result).expect("Failed to verify message");
});