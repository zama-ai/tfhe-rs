use crate::core_crypto::prelude::{SignedNumeric, UnsignedNumeric};
use crate::high_level_api::internal_traits::{DecryptionKey, EncryptionKey};
use crate::integer::ciphertext::{
    CompressedRadixCiphertext, CompressedSignedRadixCiphertext, RadixCiphertext,
};
use crate::integer::client_key::RecomposableSignedInteger;
use crate::integer::public_key::CompactPublicKey;
use crate::integer::SignedRadixCiphertext;

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

// Signed Integers
impl<ClearType> DecryptionKey<SignedRadixCiphertext, ClearType> for crate::integer::ClientKey
where
    ClearType: RecomposableSignedInteger,
{
    fn decrypt(&self, ciphertext: &SignedRadixCiphertext) -> ClearType {
        self.decrypt_signed_radix(ciphertext)
    }
}

impl<T> EncryptionKey<(T, usize), SignedRadixCiphertext> for crate::integer::ClientKey
where
    T: crate::integer::block_decomposition::DecomposableInto<u64> + SignedNumeric,
{
    fn encrypt(&self, value: (T, usize)) -> SignedRadixCiphertext {
        self.encrypt_signed_radix(value.0, value.1)
    }
}

impl<T> EncryptionKey<(T, usize), CompressedSignedRadixCiphertext> for crate::integer::ClientKey
where
    T: crate::integer::block_decomposition::DecomposableInto<u64> + SignedNumeric,
{
    fn encrypt(&self, value: (T, usize)) -> CompressedSignedRadixCiphertext {
        self.encrypt_signed_radix_compressed(value.0, value.1)
    }
}

impl<T> EncryptionKey<(T, usize), SignedRadixCiphertext> for crate::integer::PublicKey
where
    T: crate::integer::block_decomposition::DecomposableInto<u64> + SignedNumeric,
{
    fn encrypt(&self, value: (T, usize)) -> SignedRadixCiphertext {
        self.encrypt_signed_radix(value.0, value.1)
    }
}

impl<T> EncryptionKey<(T, usize), SignedRadixCiphertext> for crate::integer::CompressedPublicKey
where
    T: crate::integer::block_decomposition::DecomposableInto<u64> + SignedNumeric,
{
    fn encrypt(&self, value: (T, usize)) -> SignedRadixCiphertext {
        self.encrypt_signed_radix(value.0, value.1)
    }
}

impl<T> EncryptionKey<(T, usize), SignedRadixCiphertext> for CompactPublicKey
where
    T: crate::integer::block_decomposition::DecomposableInto<u64> + SignedNumeric,
{
    fn encrypt(&self, value: (T, usize)) -> SignedRadixCiphertext {
        self.encrypt_signed_radix(value.0, value.1)
    }
}
