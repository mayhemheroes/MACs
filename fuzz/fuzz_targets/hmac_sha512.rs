#![no_main]
use libfuzzer_sys::fuzz_target;
use hmac::{Hmac, Mac};
use sha2::Sha512;

fuzz_target!(|input: (&[u8], &[u8])| {
    let (key, data) = input;
    type HmacSha512 = Hmac<Sha512>;
    let mut mac = HmacSha512::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.clone().finalize().into_bytes();
    mac.verify_slice(&result).expect("Failed to verify message");
});