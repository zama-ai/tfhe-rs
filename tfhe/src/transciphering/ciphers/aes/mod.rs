//! Bit-sliced FHE AES-128 in CTR mode for transciphering.

mod encrypt;
mod fhe;
mod key;
mod plain;
mod sbox;
#[cfg(test)]
mod test;

pub use fhe::AesFheState;
pub use key::AesFheRoundKeys;
pub use plain::AesPlainState;

use crate::shortint::ciphertext::Degree;
use crate::shortint::{Ciphertext, ClientKey};
use crate::transciphering::ciphers::*;

/// Big endian byte order.
///
/// The 16 key bytes are stored most-significant first, so for a `u128` value
/// `bits[0]` holds the top byte. `expand()` then unpacks each byte LSB-first
/// into the `[bool; 128]` consumed by the bit-sliced circuit:
///
/// ```text
/// u128 = 0xB0 B1 B2 ... BF              (16 bytes, big endian)
///           │  │            │
///           ▼  ▼            ▼
/// bits  = [ B0 B1 B2 ...    BF ]        bits[0] = MSB byte, bits[15] = LSB byte
///
/// within one byte, expand() goes LSB-first:
///
///   byte  = b7 b6 b5 b4 b3 b2 b1 b0     (binary, MSB .. LSB)
///   bool[] = [ b0 b1 b2 b3 b4 b5 b6 b7 ]  (increasing array index)
/// ```
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
        AesFheKey {
            key: self.expand().map(|b| {
                let mut c = client_key.encrypt(b as u64);
                c.degree = Degree::new(1);
                c
            }),
        }
    }

    pub(crate) fn to_csprng_key_u128(self) -> u128 {
        u128::from_ne_bytes(self.bits)
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
    key: [Ciphertext; 128],
}

/// AES-128 IV / initial CTR counter, stored in the native-endian in-memory
/// layout of a `u128`.
///
/// `#[repr(align(16))]` plus `from_ne_bytes`/`to_ne_bytes` make `u128 <-> AesIv`
/// a zero-cost reinterpret, with no byteswap on any platform. The big-endian
/// (NIST) byte convention is applied only at the `[u8; 16]` boundary:
///
/// ```text
///   AesIv::from(u128)      bits = value.to_ne_bytes()    // native, no swap
///   AesIv::to_u128()       u128::from_ne_bytes(bits)     // native, no swap
///   AesIv::from([u8; 16])  bits = from_be_bytes(value)   // big-endian (NIST)
/// ```
#[repr(align(16))]
#[derive(Clone, Copy)]
pub struct AesIv {
    bits: [u8; 16],
}

impl AesIv {
    pub fn to_u128(self) -> u128 {
        u128::from_ne_bytes(self.bits)
    }
}

impl From<u128> for AesIv {
    fn from(value: u128) -> Self {
        Self {
            bits: value.to_ne_bytes(),
        }
    }
}

impl From<[u8; 16]> for AesIv {
    fn from(value: [u8; 16]) -> Self {
        u128::from_be_bytes(value).into()
    }
}

impl From<[bool; 128]> for AesIv {
    fn from(value: [bool; 128]) -> Self {
        let mut bits = [0u8; 16];
        pack_bits_lsb_first(&value, &mut bits);
        Self { bits }
    }
}
