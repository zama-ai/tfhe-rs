use super::server_key::RadixCiphertextDyn;
use crate::high_level_api::internal_traits::DecryptionKey;

impl<ClearType> DecryptionKey<RadixCiphertextDyn, ClearType> for crate::integer::ClientKey
where
    ClearType: Default + bytemuck::Pod,
{
    fn decrypt(&self, ciphertext: &RadixCiphertextDyn) -> ClearType {
        match ciphertext {
            RadixCiphertextDyn::Big(ct) => self.decrypt_radix(ct),
            RadixCiphertextDyn::Small(ct) => self.decrypt_radix(ct),
        }
    }
}
