/// Trait to be implemented on keys that encrypts clear values into ciphertexts
pub(crate) trait EncryptionKey<ClearType, CiphertextType> {
    /// The encryption process
    fn encrypt(&self, value: ClearType) -> CiphertextType;
}

/// Trait to be implemented on keys that decrypts ciphertext into clear values
pub(crate) trait DecryptionKey<CiphertextType, ClearType> {
    /// The decryption process
    fn decrypt(&self, ciphertext: &CiphertextType) -> ClearType;
}

pub trait TypeIdentifier {
    fn type_variant(&self) -> crate::high_level_api::errors::Type;
}
