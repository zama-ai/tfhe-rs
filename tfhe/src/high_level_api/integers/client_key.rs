use crate::core_crypto::prelude::UnsignedNumeric;
use crate::integer::ciphertext::{CompressedRadixCiphertext, RadixCiphertext};
use crate::high_level_api::internal_traits::{DecryptionKey, EncryptionKey};
use crate::integer::public_key::CompactPublicKey;

impl<ClearType> DecryptionKey<RadixCiphertext, ClearType> for crate::integer::ClientKey
where
    ClearType: crate::integer::block_decomposition::RecomposableFrom<u64> + UnsignedNumeric,
{
    fn decrypt(&self, ciphertext: &RadixCiphertext) -> ClearType {
        self.decrypt_radix(ciphertext)
    }
}

impl<T> EncryptionKey<(T, usize), RadixCiphertext> for crate::integer::ClientKey
where
    T: crate::integer::block_decomposition::DecomposableInto<u64> + UnsignedNumeric,
{
    fn encrypt(&self, value: (T, usize)) -> RadixCiphertext {
        self.encrypt_radix(value.0, value.1)
    }
}

impl<T> EncryptionKey<(T, usize), RadixCiphertext> for crate::integer::PublicKey
where
    T: crate::integer::block_decomposition::DecomposableInto<u64> + UnsignedNumeric,
{
    fn encrypt(&self, value: (T, usize)) -> RadixCiphertext {
        self.encrypt_radix(value.0, value.1)
    }
}

impl<T> EncryptionKey<(T, usize), RadixCiphertext> for crate::integer::CompressedPublicKey
where
    T: crate::integer::block_decomposition::DecomposableInto<u64> + UnsignedNumeric,
{
    fn encrypt(&self, value: (T, usize)) -> RadixCiphertext {
        self.encrypt_radix(value.0, value.1)
    }
}

impl<T> EncryptionKey<(T, usize), CompressedRadixCiphertext> for crate::integer::ClientKey
where
    T: crate::integer::block_decomposition::DecomposableInto<u64> + UnsignedNumeric,
{
    fn encrypt(&self, value: (T, usize)) -> CompressedRadixCiphertext {
        self.encrypt_radix_compressed(value.0, value.1)
    }
}

impl<T> EncryptionKey<(T, usize), RadixCiphertext> for CompactPublicKey
where
    T: crate::integer::block_decomposition::DecomposableInto<u64> + UnsignedNumeric,
{
    fn encrypt(&self, value: (T, usize)) -> RadixCiphertext {
        self.encrypt_radix(value.0, value.1)
    }
}

