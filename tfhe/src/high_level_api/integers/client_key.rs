use crate::core_crypto::prelude::UnsignedNumeric;
use crate::high_level_api::internal_traits::DecryptionKey;
use crate::integer::ciphertext::RadixCiphertext;

impl<ClearType> DecryptionKey<RadixCiphertext, ClearType> for crate::integer::ClientKey
where
    ClearType: crate::integer::block_decomposition::RecomposableFrom<u64> + UnsignedNumeric,
{
    fn decrypt(&self, ciphertext: &RadixCiphertext) -> ClearType {
        self.decrypt_radix(ciphertext)
    }
}
