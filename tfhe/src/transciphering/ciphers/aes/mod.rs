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

use crate::named::Named;
use crate::shortint::oprf::OprfSeed;
use crate::shortint::{Ciphertext, ClientKey, ServerKey};
use crate::transciphering::backward_compatibility::{AesIvVersions, SerializableAesFheKeyVersions};
use crate::transciphering::ciphers::*;
use crate::transciphering::TranscipheringServerKey;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

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

#[derive(Clone, Serialize, Deserialize, Versionize)]
#[serde(into = "SerializableAesFheKey", try_from = "SerializableAesFheKey")]
#[versionize(into = "SerializableAesFheKey", try_from = "SerializableAesFheKey")]
pub struct AesFheKey {
    key: [Ciphertext; 128],
}

impl AesFheKey {
    pub fn ciphertexts(&self) -> &[Ciphertext; 128] {
        &self.key
    }

    pub fn new_random(
        seed: impl OprfSeed,
        transciphering_key: &TranscipheringServerKey,
        sks: &ServerKey,
    ) -> Self {
        let encrypted_bits = transciphering_key
            .oprf_key()
            .generate_random_boolean_sequence(seed, 128, sks);

        let key: [Ciphertext; 128] = encrypted_bits.try_into().expect("the vec has 128 elements");

        Self { key }
    }

    /// Decrypt the key bits
    pub fn decrypt(&self, client_key: &ClientKey) -> AesPlainKey {
        let mut decrypted_bits = [false; 128];
        for (ct, out) in self.key.iter().zip(decrypted_bits.iter_mut()) {
            *out = client_key.decrypt(ct) != 0;
        }
        AesPlainKey::from(decrypted_bits)
    }
}

/// Serialization form of [`AesFheKey`]. The 128 key ciphertexts are stored in a
/// `Vec` because serde/versionize don't support arrays longer than 32; the
/// fixed-size array is restored on deserialization.
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(SerializableAesFheKeyVersions)]
pub struct SerializableAesFheKey {
    key: Vec<Ciphertext>,
}

impl From<AesFheKey> for SerializableAesFheKey {
    fn from(value: AesFheKey) -> Self {
        Self {
            key: value.key.into(),
        }
    }
}

impl TryFrom<SerializableAesFheKey> for AesFheKey {
    type Error = crate::Error;

    fn try_from(value: SerializableAesFheKey) -> Result<Self, Self::Error> {
        let len = value.key.len();
        let key: [Ciphertext; 128] = value.key.try_into().map_err(|_| {
            crate::error!("an AES key must hold exactly 128 ciphertexts, got {len}")
        })?;
        Ok(Self { key })
    }
}

/// AES-128 IV / initial CTR counter, as a plain 128-bit integer.
///
/// The counter is incremented directly (`iv + block_index`), the big-endian
/// (NIST) convention only applies when bytes are involved, i.e. at the
/// `[u8; 16]` / `[bool; 128]` construction boundaries.
#[derive(Clone, Copy, Serialize, Deserialize, Versionize)]
#[versionize(AesIvVersions)]
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

impl Named for AesIv {
    const NAME: &'static str = "transciphering::AesIv";
}
