//! Bit-sliced FHE AES-128 in CTR mode for transciphering.

mod encrypt;
mod fhe;
mod key;
mod plain;
mod sbox;
#[cfg(test)]
mod test;

pub use fhe::AesFheState;
pub use key::ExpandedAesFheKey;
pub use plain::AesPlainStream;

use crate::shortint::ciphertext::Degree;
use crate::shortint::{Ciphertext, ClientKey};
use crate::transciphering::ciphers::*;

#[derive(Clone, Copy)]
pub struct AesPlainKey {
    bits: [u8; 16],
}

impl AesPlainKey {
    pub fn expand(self) -> [bool; 128] {
        let mut out = [false; 128];
        unpack_bits_lsb_first(&self.bits, &mut out);
        out
    }

    pub fn encrypt(&self, client_key: &ClientKey) -> AesFheKey {
        self.expand()
            .map(|b| {
                let mut c = client_key.encrypt(b as u64);
                c.degree = Degree::new(1);
                c
            })
            .into()
    }
}

impl From<u128> for AesPlainKey {
    fn from(value: u128) -> Self {
        Self {
            bits: value.to_be_bytes(),
        }
    }
}

impl From<[u8; 16]> for AesPlainKey {
    fn from(value: [u8; 16]) -> Self {
        Self { bits: value }
    }
}

impl From<[bool; 128]> for AesPlainKey {
    fn from(value: [bool; 128]) -> Self {
        let mut bits = [0u8; 16];
        pack_bits_lsb_first(&value, &mut bits);
        Self { bits }
    }
}

pub struct AesFheKey {
    pub key: [Ciphertext; 128],
}

impl From<[Ciphertext; 128]> for AesFheKey {
    fn from(value: [Ciphertext; 128]) -> Self {
        Self { key: value }
    }
}

/// Big endian byte order
#[derive(Clone, Copy)]
pub struct AesIv {
    bits: [u8; 16],
}

impl AesIv {
    pub fn to_u128(self) -> u128 {
        u128::from_be_bytes(self.bits)
    }
}

impl From<u128> for AesIv {
    fn from(value: u128) -> Self {
        Self {
            bits: value.to_be_bytes(),
        }
    }
}

impl From<[u8; 16]> for AesIv {
    fn from(value: [u8; 16]) -> Self {
        Self { bits: value }
    }
}

impl From<[bool; 128]> for AesIv {
    fn from(value: [bool; 128]) -> Self {
        let mut bits = [0u8; 16];
        pack_bits_lsb_first(&value, &mut bits);
        Self { bits }
    }
}
