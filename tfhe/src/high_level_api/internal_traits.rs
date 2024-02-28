/// Trait to be implemented on keys that encrypts clear values into ciphertexts
#[allow(dead_code)]
pub(crate) trait EncryptionKey<ClearType, CiphertextType> {
    /// The encryption process
    fn encrypt(&self, value: ClearType) -> CiphertextType;
}

/// Trait to be implemented on keys that decrypts ciphertext into clear values
#[allow(dead_code)]
pub(crate) trait DecryptionKey<CiphertextType, ClearType> {
    /// The decryption process
    fn decrypt(&self, ciphertext: &CiphertextType) -> ClearType;
}

#[allow(dead_code)]
pub trait FromParameters<P> {
    fn from_parameters(parameters: P) -> Self;
}

#[allow(dead_code)]
pub trait ParameterType: Clone {
    /// The Id allows to differentiate the different parameters
    /// as well as retrieving the corresponding client key and server key
    type Id: Copy;
}

#[allow(dead_code)]
pub trait TypeIdentifier {
    fn type_variant(&self) -> crate::high_level_api::errors::Type;
}
