/*
 * Client-side (de-)encryption of the crate's input / output format
 * ----------------------------------------------------------------------------------------------- */

use tfhe::shortint::prelude::*;

use crate::u64_conv::{u64_to_vec_u2, vec_u2_to_u64};

/// Encrypts a u64 as 32 ciphertexts, each holding a 2-bit nibble in the low bits of the FHE message
/// space (the `u2l` format expected by [`crate::encrypt`] / [`crate::decrypt`]). The most
/// significant bits of the input are at index 0 in the output.
pub fn encrypt_u64_as_u2l(client_key: &ClientKey, x: u64) -> [Ciphertext; 32] {
    u64_to_vec_u2(x).map(|u2| client_key.encrypt(u2 as u64))
}

/// Reverse of [`encrypt_u64_as_u2l`].
pub fn decrypt_u2l_as_u64(client_key: &ClientKey, ct: &[Ciphertext; 32]) -> u64 {
    vec_u2_to_u64(std::array::from_fn(|n| {
        client_key.decrypt_message_and_carry(&ct[n]) as u8
    }))
}
