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

pub trait FromParameters<P> {
    fn from_parameters(parameters: P) -> Self;
}

pub trait ParameterType: Clone {
    /// The Id allows to differentiate the different parameters
    /// as well as retrieving the corresponding client key and server key
    type Id: Copy;
    /// The ciphertext type that will be wrapped.
    type InnerCiphertext: serde::Serialize + for<'de> serde::Deserialize<'de>;
    /// The client key type that will be wrapped.
    type InnerClientKey;
    /// The public key that will be wrapped;
    type InnerPublicKey;
    /// The server key type that will be wrapped.
    type InnerServerKey;
}
