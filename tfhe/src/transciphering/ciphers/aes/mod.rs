//! Bit-sliced FHE AES-128 in CTR mode for transciphering.

mod data;
mod encrypt;
mod fhe;
mod key;
mod plain;
mod sbox;
#[cfg(test)]
mod test;

pub use data::{decrypt_u128, encrypt_u128};
pub use fhe::AesFheStream;
pub use key::AesFheKey;
pub use plain::AesPlainStream;
