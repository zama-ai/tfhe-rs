//! A module with generic wrapper to handle at runtime either AES-128  or AES-256
use crate::generators::aes_ctr::{
    Aes128BlockCipher, Aes128Key, Aes256BlockCipher, Aes256Key, AesBlockCipher,
    AES_CALLS_PER_BATCH, BYTES_PER_AES_CALL,
};

/// An AES backend of the crate shall implement the needed variants of AES
pub trait AesBackend {
    type Aes128BlockCipher: Aes128BlockCipher;
    type Aes256BlockCipher: Aes256BlockCipher;
}

pub enum AnyAesKey {
    Aes128(Aes128Key),
    Aes256(Aes256Key),
}

impl From<Aes128Key> for AnyAesKey {
    fn from(key: Aes128Key) -> Self {
        Self::Aes128(key)
    }
}

impl From<Aes256Key> for AnyAesKey {
    fn from(key: Aes256Key) -> Self {
        Self::Aes256(key)
    }
}

pub enum AnyAesBlockCipher<B>
where
    B: AesBackend,
{
    Aes128(B::Aes128BlockCipher),
    Aes256(B::Aes256BlockCipher),
}

// Written by hand rather than derived: `#[derive(Clone)]` would emit a `B: Clone` bound, but `B` is
// only a marker and never stored. The variants get `Clone` from the `AesBlockCipher` supertrait.
impl<B> Clone for AnyAesBlockCipher<B>
where
    B: AesBackend,
{
    fn clone(&self) -> Self {
        match self {
            Self::Aes128(aes) => Self::Aes128(aes.clone()),
            Self::Aes256(aes) => Self::Aes256(aes.clone()),
        }
    }
}

impl<B> AesBlockCipher for AnyAesBlockCipher<B>
where
    B: AesBackend,
{
    type Key = AnyAesKey;

    fn new(key: Self::Key) -> Self {
        match key {
            AnyAesKey::Aes128(key) => Self::Aes128(B::Aes128BlockCipher::new(key)),
            AnyAesKey::Aes256(key) => Self::Aes256(B::Aes256BlockCipher::new(key)),
        }
    }

    fn generate_batch(
        &mut self,
        data: [u128; AES_CALLS_PER_BATCH],
    ) -> [u8; crate::generators::aes_ctr::BYTES_PER_BATCH] {
        match self {
            Self::Aes128(aes) => aes.generate_batch(data),
            Self::Aes256(aes) => aes.generate_batch(data),
        }
    }

    fn generate_next(&mut self, data: u128) -> [u8; BYTES_PER_AES_CALL] {
        match self {
            Self::Aes128(aes) => aes.generate_next(data),
            Self::Aes256(aes) => aes.generate_next(data),
        }
    }
}
