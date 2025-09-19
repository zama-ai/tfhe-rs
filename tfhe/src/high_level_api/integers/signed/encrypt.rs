use crate::core_crypto::prelude::SignedNumeric;
use crate::high_level_api::global_state;
use crate::high_level_api::integers::FheIntId;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use crate::integer::block_decomposition::{DecomposableInto, RecomposableSignedInteger};
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
use crate::prelude::{FheDecrypt, FheTrivialEncrypt, FheTryEncrypt, FheTryTrivialEncrypt};
use crate::{ClientKey, CompressedPublicKey, FheInt, PublicKey};

impl<Id, ClearType> FheDecrypt<ClearType> for FheInt<Id>
where
    Id: FheIntId,
    ClearType: RecomposableSignedInteger,
{
    /// Decrypts a [FheInt] to a signed type.
    ///
    /// The unsigned type has to be explicit.
    ///
    /// # Example
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(7288i16, &client_key);
    ///
    /// // i16 is explicit
    /// let decrypted: i16 = a.decrypt(&client_key);
    /// assert_eq!(decrypted, 7288i16);
    ///
    /// // i32 is explicit
    /// let decrypted: i32 = a.decrypt(&client_key);
    /// assert_eq!(decrypted, 7288i32);
    /// ```
    fn decrypt(&self, key: &ClientKey) -> ClearType {
        key.key.key.decrypt_signed_radix(&self.ciphertext.on_cpu())
    }
}

impl<Id, T> FheTryEncrypt<T, ClientKey> for FheInt<Id>
where
    Id: FheIntId,
    T: DecomposableInto<u64> + SignedNumeric,
{
    type Error = crate::Error;

    fn try_encrypt(value: T, key: &ClientKey) -> Result<Self, Self::Error> {
        let ciphertext = key
            .key
            .key
            .encrypt_signed_radix(value, Id::num_blocks(key.message_modulus()));
        Ok(Self::new(
            ciphertext,
            key.tag.clone(),
            ReRandomizationMetadata::default(),
        ))
    }
}

impl<Id, T> FheTryEncrypt<T, PublicKey> for FheInt<Id>
where
    Id: FheIntId,
    T: DecomposableInto<u64> + SignedNumeric,
{
    type Error = crate::Error;

    fn try_encrypt(value: T, key: &PublicKey) -> Result<Self, Self::Error> {
        let ciphertext = key
            .key
            .encrypt_signed_radix(value, Id::num_blocks(key.message_modulus()));
        Ok(Self::new(
            ciphertext,
            key.tag.clone(),
            ReRandomizationMetadata::default(),
        ))
    }
}

impl<Id, T> FheTryEncrypt<T, CompressedPublicKey> for FheInt<Id>
where
    Id: FheIntId,
    T: DecomposableInto<u64> + SignedNumeric,
{
    type Error = crate::Error;

    fn try_encrypt(value: T, key: &CompressedPublicKey) -> Result<Self, Self::Error> {
        let ciphertext = key
            .key
            .encrypt_signed_radix(value, Id::num_blocks(key.message_modulus()));
        Ok(Self::new(
            ciphertext,
            key.tag.clone(),
            ReRandomizationMetadata::default(),
        ))
    }
}

impl<Id, T> FheTryTrivialEncrypt<T> for FheInt<Id>
where
    T: DecomposableInto<u64>,
    Id: FheIntId,
{
    type Error = crate::Error;

    /// Creates a trivial encryption of a signed integer.
    ///
    /// # Warning
    ///
    /// Trivial encryptions are not real encryptions, as a trivially encrypted
    /// ciphertext can be decrypted by any key (in fact, no key is actually needed).
    ///
    /// Trivial encryptions become real encrypted data once used in an operation
    /// that involves a real ciphertext
    fn try_encrypt_trivial(value: T) -> Result<Self, Self::Error> {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let ciphertext: crate::integer::SignedRadixCiphertext = key
                    .pbs_key()
                    .create_trivial_radix(value, Id::num_blocks(key.message_modulus()));
                Ok(Self::new(
                    ciphertext,
                    key.tag.clone(),
                    ReRandomizationMetadata::default(),
                ))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner: CudaSignedRadixCiphertext = cuda_key.key.key.create_trivial_radix(
                    value,
                    Id::num_blocks(cuda_key.key.key.message_modulus),
                    streams,
                );
                Ok(Self::new(
                    inner,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                ))
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => panic!("Hpu does not currently support signed operation"),
        })
    }
}

impl<Id, T> FheTrivialEncrypt<T> for FheInt<Id>
where
    T: DecomposableInto<u64>,
    Id: FheIntId,
{
    /// Creates a trivial encryption of a signed integer.
    ///
    /// # Warning
    ///
    /// Trivial encryptions are not real encryptions, as a trivially encrypted
    /// ciphertext can be decrypted by any key (in fact, no key is actually needed).
    ///
    /// Trivial encryptions become real encrypted data once used in an operation
    /// that involves a real ciphertext
    #[track_caller]
    fn encrypt_trivial(value: T) -> Self {
        Self::try_encrypt_trivial(value).unwrap()
    }
}
