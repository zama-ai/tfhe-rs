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
pub struct AesPlainKey([u8; 16]);

impl AesPlainKey {
    pub fn expand(self) -> [bool; 128] {
        let mut out = [false; 128];
        unpack_bits_lsb_first(&self.0, &mut out);
        out
    }

    pub fn encrypt(&self, client_key: &ClientKey) -> AesFheKey {
        AesFheKey {
            key: self.expand().map(|b| client_key.encrypt_bool(b)),
        }
    }

    pub(crate) fn to_csprng_key_u128(self) -> u128 {
        u128::from_ne_bytes(self.0)
    }
}

impl From<u128> for AesPlainKey {
    fn from(value: u128) -> Self {
        value.to_be_bytes().into()
    }
}

impl From<[u8; 16]> for AesPlainKey {
    fn from(value: [u8; 16]) -> Self {
        Self(value)
    }
}

impl From<[bool; 128]> for AesPlainKey {
    fn from(value: [bool; 128]) -> Self {
        let mut bits = [0u8; 16];
        pack_bits_lsb_first(&value, &mut bits);
        bits.into()
    }
}

pub struct AesFheKey {
    key: [Ciphertext; 128],
}

impl AesFheKey {
    pub fn ciphertexts(&self) -> &[Ciphertext; 128] {
        &self.key
    }
}

/// AES-128 IV / initial CTR counter, as a plain 128-bit integer.
///
/// The counter is incremented directly (`iv + block_index`), the big-endian
/// (NIST) convention only applies when bytes are involved, i.e. at the
/// `[u8; 16]` / `[bool; 128]` construction boundaries.
#[derive(Clone, Copy)]
pub struct AesIv(u128);

impl AesIv {
    pub fn to_u128(self) -> u128 {
        self.0
    }
}

impl From<u128> for AesIv {
    fn from(value: u128) -> Self {
        Self(value)
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
        bits.into()
    }
}
