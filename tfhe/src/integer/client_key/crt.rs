use super::{ClientKey, SecretEncryptionKeyView};
use crate::integer::backward_compatibility::client_key::CrtClientKeyVersions;
use crate::integer::ciphertext::{CompressedCrtCiphertext, CrtCiphertext};
use crate::integer::client_key::utils::i_crt;
use crate::integer::encryption::encrypt_crt;
use crate::shortint::parameters::MessageModulus;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

/// Client key "specialized" for CRT decomposition.
///
/// This key is a simple wrapper of the [ClientKey],
/// that only encrypt and decrypt in CRT decomposition.
///
/// # Example
///
/// ```rust
/// use tfhe::integer::CrtClientKey;
/// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128;
///
/// let basis = vec![2, 3, 5];
/// let cks = CrtClientKey::new(PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128, basis);
///
/// let msg = 13_u64;
///
/// // Encryption:
/// let ct = cks.encrypt(msg);
///
/// // Decryption:
/// let dec = cks.decrypt(&ct);
/// assert_eq!(msg, dec);
/// ```
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Versionize)]
#[versionize(CrtClientKeyVersions)]
pub struct CrtClientKey {
    key: ClientKey,
    moduli: Vec<u64>,
}

impl AsRef<ClientKey> for CrtClientKey {
    fn as_ref(&self) -> &ClientKey {
        &self.key
    }
}

impl<'key> From<&'key CrtClientKey> for SecretEncryptionKeyView<'key> {
    fn from(value: &'key CrtClientKey) -> Self {
        Self {
            key: (&value.key.key).into(),
        }
    }
}

impl CrtClientKey {
    pub fn new<P>(parameters: P, moduli: Vec<u64>) -> Self
    where
        P: Into<crate::shortint::PBSParameters>,
    {
        Self {
            key: ClientKey::new(parameters.into()),
            moduli,
        }
    }

    /// Encrypts an integer using crt representation
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::CrtClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let basis: Vec<u64> = vec![2, 3, 5];
    /// let cks = CrtClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, basis);
    ///
    /// let msg = 13_u64;
    ///
    /// // Encryption:
    /// let ct = cks.encrypt(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt(&self, message: u64) -> CrtCiphertext {
        self.encrypt_impl(
            message,
            crate::shortint::ClientKey::encrypt_with_message_modulus,
        )
    }

    pub fn encrypt_compressed(&self, message: u64) -> CompressedCrtCiphertext {
        self.encrypt_impl(
            message,
            crate::shortint::ClientKey::encrypt_with_message_modulus_compressed,
        )
    }

    /// Encrypts a small integer message using the client key and some moduli without padding bit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::CrtClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let basis: Vec<u64> = vec![2, 3, 5];
    /// let cks = CrtClientKey::new(PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128, basis);
    ///
    /// let msg = 13_u64;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_native_crt(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_native_crt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_native_crt(&self, message: u64) -> CrtCiphertext {
        self.encrypt_impl(message, crate::shortint::ClientKey::encrypt_native_crt)
    }

    pub fn encrypt_native_crt_compressed(&self, message: u64) -> CompressedCrtCiphertext {
        self.encrypt_impl(
            message,
            crate::shortint::ClientKey::encrypt_native_crt_compressed,
        )
    }

    /// Decrypts an integer in crt decomposition
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::CrtClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let basis: Vec<u64> = vec![2, 3, 5];
    /// let cks = CrtClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, basis);
    ///
    /// let msg = 27_u64;
    ///
    /// // Encryption:
    /// let ct = cks.encrypt(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt(&self, ciphertext: &CrtCiphertext) -> u64 {
        let mut val: Vec<u64> = Vec::with_capacity(ciphertext.blocks.len());

        // Decrypting each block individually
        for (c_i, b_i) in ciphertext.blocks.iter().zip(ciphertext.moduli.iter()) {
            // decrypt the component i of the integer and multiply it by the radix product
            val.push(self.key.key.decrypt_message_and_carry(c_i) % b_i);
        }

        // Computing the inverse CRT to recompose the message
        let result = i_crt(&ciphertext.moduli, &val);

        let whole_modulus: u64 = ciphertext.moduli.iter().copied().product();

        result % whole_modulus
    }

    /// Decrypts a ciphertext encrypting an integer message with some moduli basis without
    /// padding bit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::CrtClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let basis: Vec<u64> = vec![2, 3, 5];
    /// let cks = CrtClientKey::new(PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128, basis);
    ///
    /// let msg = 27_u64;
    /// // Encryption of one message:
    /// let ct = cks.encrypt_native_crt(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_native_crt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt_native_crt(&self, ciphertext: &CrtCiphertext) -> u64 {
        let mut val: Vec<u64> = vec![];

        //Decrypting each block individually
        for (c_i, b_i) in ciphertext.blocks.iter().zip(ciphertext.moduli.iter()) {
            //decrypt the component i of the integer and multiply it by the radix product
            val.push(
                self.key
                    .key
                    .decrypt_message_native_crt(c_i, MessageModulus(*b_i)),
            );
        }

        //Computing the inverse CRT to recompose the message
        let result = i_crt(&ciphertext.moduli, &val);

        let whole_modulus: u64 = ciphertext.moduli.iter().copied().product();

        result % whole_modulus
    }

    fn encrypt_impl<Block, CrtCiphertextType, F>(
        &self,
        message: u64,
        encrypt_block: F,
    ) -> CrtCiphertextType
    where
        F: Fn(&crate::shortint::ClientKey, u64, MessageModulus) -> Block,
        CrtCiphertextType: From<(Vec<Block>, Vec<u64>)>,
    {
        encrypt_crt(&self.key.key, message, self.moduli.clone(), encrypt_block)
    }

    /// Returns the parameters used by the client key.
    pub fn parameters(&self) -> crate::shortint::AtomicPatternParameters {
        self.key.parameters()
    }

    pub fn moduli(&self) -> &[u64] {
        self.moduli.as_slice()
    }
}

impl From<(ClientKey, Vec<u64>)> for CrtClientKey {
    fn from((key, moduli): (ClientKey, Vec<u64>)) -> Self {
        Self { key, moduli }
    }
}
