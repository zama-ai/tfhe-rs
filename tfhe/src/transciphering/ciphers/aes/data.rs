//! Encode a clear `u128` (AES key or IV) as 128 bit ciphertexts, and back.
//!
//! Bytes are laid out in NIST order (byte 0 of the `u128` is the most
//! significant) and bits LSB-first within each byte, matching both
//! [`crate::transciphering::StreamCipher::bit_at`] and the layout consumed by
//! the AES round functions.

use crate::shortint::{Ciphertext, ClientKey};

pub fn encrypt_u128(cks: &ClientKey, data: u128) -> [Ciphertext; 128] {
    let bytes = data.to_be_bytes();
    std::array::from_fn(|i| cks.encrypt(((bytes[i / 8] >> (i % 8)) & 1) as u64))
}

pub fn decrypt_u128(cks: &ClientKey, bits: &[Ciphertext; 128]) -> u128 {
    let mut bytes = [0u8; 16];
    for (i, ct) in bits.iter().enumerate() {
        let bit = (cks.decrypt(ct) & 1) as u8;
        bytes[i / 8] |= bit << (i % 8);
    }
    u128::from_be_bytes(bytes)
}
