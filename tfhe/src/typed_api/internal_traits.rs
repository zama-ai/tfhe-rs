/// Trait to be implemented on keys that encrypts clear values into ciphertexts
pub(crate) trait EncryptionKey<ClearType> {
    /// The type of ciphertext returned as a result of the encryption
    type Ciphertext;

    /// The encryption process
    fn encrypt(&self, value: ClearType) -> Self::Ciphertext;
}

/// Trait to be implemented on keys that decrypts ciphertext into clear values
pub(crate) trait DecryptionKey<ClearType> {
    /// The type of ciphertext that this key decrypts
    type Ciphertext;

    /// The decryption process
    fn decrypt(&self, ciphertext: &Self::Ciphertext) -> ClearType;
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
