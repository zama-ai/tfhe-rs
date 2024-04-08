use super::base::FheBool;
use crate::high_level_api::booleans::inner::InnerBoolean;
use crate::high_level_api::global_state;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::with_thread_local_cuda_stream;
use crate::high_level_api::keys::InternalServerKey;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::BooleanBlock;
use crate::prelude::{FheDecrypt, FheTrivialEncrypt, FheTryEncrypt, FheTryTrivialEncrypt};
use crate::shortint::ciphertext::Degree;
use crate::{ClientKey, CompactPublicKey, CompressedPublicKey, PublicKey};

impl FheTryEncrypt<bool, ClientKey> for FheBool {
    type Error = crate::Error;

    fn try_encrypt(value: bool, key: &ClientKey) -> Result<Self, Self::Error> {
        let integer_client_key = &key.key.key;
        let mut ciphertext = Self::new(integer_client_key.encrypt_bool(value));
        ciphertext.ciphertext.move_to_device_of_server_key_if_set();
        Ok(ciphertext)
    }
}

impl FheTryEncrypt<bool, CompactPublicKey> for FheBool {
    type Error = crate::Error;

    fn try_encrypt(value: bool, key: &CompactPublicKey) -> Result<Self, Self::Error> {
        let mut ciphertext = key.key.key.encrypt_radix(value as u8, 1);
        ciphertext.blocks[0].degree = Degree::new(1);
        Ok(Self::new(BooleanBlock::new_unchecked(
            ciphertext.blocks.into_iter().next().unwrap(),
        )))
    }
}

impl FheTrivialEncrypt<bool> for FheBool {
    /// Creates a trivial encryption of a bool.
    ///
    /// # Warning
    ///
    /// Trivial encryptions are not real encryptions, as a trivially encrypted
    /// ciphertext can be decrypted by any key (in fact, no key is actually needed).
    ///
    /// Trivial encryptions become real encrypted data once used in an operation
    /// that involves a real ciphertext
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt_trivial(true);
    ///
    /// let decrypted: bool = a.decrypt(&client_key);
    /// assert_eq!(decrypted, true);
    /// ```
    #[track_caller]
    fn encrypt_trivial(value: bool) -> Self {
        Self::try_encrypt_trivial(value).unwrap()
    }
}

impl FheTryEncrypt<bool, CompressedPublicKey> for FheBool {
    type Error = crate::Error;

    fn try_encrypt(value: bool, key: &CompressedPublicKey) -> Result<Self, Self::Error> {
        let key = &key.key;
        let mut ciphertext = Self::new(key.encrypt_bool(value));
        ciphertext.ciphertext.move_to_device_of_server_key_if_set();
        Ok(ciphertext)
    }
}

impl FheTryEncrypt<bool, PublicKey> for FheBool {
    type Error = crate::Error;

    fn try_encrypt(value: bool, key: &PublicKey) -> Result<Self, Self::Error> {
        let key = &key.key;
        let mut ciphertext = Self::new(key.encrypt_bool(value));
        ciphertext.ciphertext.move_to_device_of_server_key_if_set();
        Ok(ciphertext)
    }
}

impl FheDecrypt<bool> for FheBool {
    /// Decrypts the value
    fn decrypt(&self, key: &ClientKey) -> bool {
        key.key.key.decrypt_bool(&self.ciphertext.on_cpu())
    }
}

impl FheTryTrivialEncrypt<bool> for FheBool {
    type Error = crate::Error;

    fn try_encrypt_trivial(value: bool) -> Result<Self, Self::Error> {
        let ciphertext = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                InnerBoolean::Cpu(key.pbs_key().create_trivial_boolean_block(value))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner = cuda_key
                    .key
                    .create_trivial_radix(u64::from(value), 1, stream);
                InnerBoolean::Cuda(CudaBooleanBlock::from_cuda_radix_ciphertext(
                    inner.ciphertext,
                ))
            }),
        });
        Ok(Self::new(ciphertext))
    }
}
