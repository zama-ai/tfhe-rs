use super::types::base::RadixCiphertextDyn;
use crate::high_level_api::internal_traits::DecryptionKey;

impl<ClearType> DecryptionKey<RadixCiphertextDyn, ClearType> for crate::integer::ClientKey
where
    ClearType: crate::integer::block_decomposition::RecomposableFrom<u64>,
{
    fn decrypt(&self, ciphertext: &RadixCiphertextDyn) -> ClearType {
        match ciphertext {
            RadixCiphertextDyn::Big(ct) => self.decrypt_radix(ct),
            RadixCiphertextDyn::Small(ct) => self.decrypt_radix(ct),
        }
    }
}
