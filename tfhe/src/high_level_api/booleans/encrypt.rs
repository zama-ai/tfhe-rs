use super::base::FheBool;
use crate::high_level_api::booleans::inner::InnerBoolean;
use crate::high_level_api::global_state;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::prelude::{FheDecrypt, FheTrivialEncrypt, FheTryEncrypt, FheTryTrivialEncrypt};
use crate::{ClientKey, CompressedPublicKey, PublicKey};

impl FheTryEncrypt<bool, ClientKey> for FheBool {
    type Error = crate::Error;

    fn try_encrypt(value: bool, key: &ClientKey) -> Result<Self, Self::Error> {
        let integer_client_key = &key.key.key;
        let mut ciphertext = Self::new(
            integer_client_key.encrypt_bool(value),
            key.tag.clone(),
            ReRandomizationMetadata::default(),
        );
        ciphertext.ciphertext.move_to_device_of_server_key_if_set();
        Ok(ciphertext)
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
    /// assert!(decrypted);
    /// ```
    #[track_caller]
    fn encrypt_trivial(value: bool) -> Self {
        Self::try_encrypt_trivial(value).unwrap()
    }
}

impl FheTryEncrypt<bool, CompressedPublicKey> for FheBool {
    type Error = crate::Error;

    fn try_encrypt(value: bool, key: &CompressedPublicKey) -> Result<Self, Self::Error> {
        let mut ciphertext = Self::new(
            key.key.encrypt_bool(value),
            key.tag.clone(),
            ReRandomizationMetadata::default(),
        );
        ciphertext.ciphertext.move_to_device_of_server_key_if_set();
        Ok(ciphertext)
    }
}

impl FheTryEncrypt<bool, PublicKey> for FheBool {
    type Error = crate::Error;

    fn try_encrypt(value: bool, key: &PublicKey) -> Result<Self, Self::Error> {
        let mut ciphertext = Self::new(
            key.key.encrypt_bool(value),
            key.tag.clone(),
            ReRandomizationMetadata::default(),
        );
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
        let (ciphertext, tag) = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let ct = InnerBoolean::Cpu(key.pbs_key().create_trivial_boolean_block(value));
                (ct, key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner: CudaUnsignedRadixCiphertext =
                    cuda_key
                        .key
                        .key
                        .create_trivial_radix(u64::from(value), 1, streams);
                let ct = InnerBoolean::Cuda(CudaBooleanBlock::from_cuda_radix_ciphertext(
                    inner.into_inner(),
                ));
                (ct, cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support trivial encryption")
            }
        });
        Ok(Self::new(
            ciphertext,
            tag,
            ReRandomizationMetadata::default(),
        ))
    }
}
