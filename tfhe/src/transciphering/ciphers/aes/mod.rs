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
pub use plain::AesPlainStream;

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
        self.expand()
            .map(|b| {
                let mut c = client_key.encrypt(b as u64);
                c.degree = Degree::new(1);
                c
            })
            .into()
    }

    pub(crate) fn to_be_bytes(self) -> [u8; 16] {
        self.bits
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
    /// Every bit must be a clean degree-1 (single-bit) ciphertext: the noise /
    /// degree budget in the key schedule and round functions assumes it (see
    /// [`key::AesFheRoundKeys::new`]). `ClientKey::encrypt` defaults the degree
    /// to `message_modulus - 1` (3 for `2_2`), so callers must clamp it back to
    /// 1, as [`AesPlainKey::encrypt`] does, before building the key.
    fn from(value: [Ciphertext; 128]) -> Self {
        debug_assert!(
            value.iter().all(|c| c.degree.get() <= 1),
            "AesFheKey requires degree-1 (single-bit) ciphertexts; got degrees {:?}",
            value.iter().map(|c| c.degree.get()).collect::<Vec<_>>(),
        );
        Self { key: value }
    }
}

/// Big endian byte order.
///
/// Same layout as [`AesPlainKey`]: the 16 IV bytes are stored most-significant
/// first, so for a `u128` value `bits[0]` holds the top byte. When expanded to
/// `[bool; 128]` (e.g. the CTR counter block) each byte is taken LSB-first:
///
/// ```text
/// u128 = 0xB0 B1 B2 ... BF              (16 bytes, big endian)
///           │  │            │
///           ▼  ▼            ▼
/// bits  = [ B0 B1 B2 ...    BF ]        bits[0] = MSB byte, bits[15] = LSB byte
///
/// within one byte, the bool layout is LSB-first:
///
///   byte  = b7 b6 b5 b4 b3 b2 b1 b0     (binary, MSB .. LSB)
///   bool[] = [ b0 b1 b2 b3 b4 b5 b6 b7 ]  (increasing array index)
/// ```
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
