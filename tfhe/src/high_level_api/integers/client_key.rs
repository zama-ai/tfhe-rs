use super::server_key::RadixCiphertextDyn;
use crate::high_level_api::internal_traits::DecryptionKey;

impl DecryptionKey<RadixCiphertextDyn, u16> for crate::integer::ClientKey {
    fn decrypt(&self, ciphertext: &RadixCiphertextDyn) -> u16 {
        let clear: u64 = match ciphertext {
            RadixCiphertextDyn::Big(ct) => self.decrypt_radix(ct),
            RadixCiphertextDyn::Small(ct) => self.decrypt_radix(ct),
        };

        clear as u16
    }
}

impl DecryptionKey<RadixCiphertextDyn, u32> for crate::integer::ClientKey {
    fn decrypt(&self, ciphertext: &RadixCiphertextDyn) -> u32 {
        let clear: u64 = match ciphertext {
            RadixCiphertextDyn::Big(ct) => self.decrypt_radix(ct),
            RadixCiphertextDyn::Small(ct) => self.decrypt_radix(ct),
        };

        clear as u32
    }
}

impl<ClearType> DecryptionKey<RadixCiphertextDyn, ClearType> for crate::integer::ClientKey
where
    ClearType: crate::integer::encryption::AsLittleEndianWords + Default,
{
    fn decrypt(&self, ciphertext: &RadixCiphertextDyn) -> ClearType {
        match ciphertext {
            RadixCiphertextDyn::Big(ct) => self.decrypt_radix(ct),
            RadixCiphertextDyn::Small(ct) => self.decrypt_radix(ct),
        }
    }
}
