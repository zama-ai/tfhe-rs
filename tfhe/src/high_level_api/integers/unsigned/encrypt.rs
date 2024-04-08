use crate::core_crypto::prelude::UnsignedNumeric;
use crate::high_level_api::global_state;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::with_thread_local_cuda_stream;
use crate::high_level_api::integers::FheUintId;
use crate::high_level_api::keys::InternalServerKey;
use crate::integer::block_decomposition::{DecomposableInto, RecomposableFrom};
use crate::prelude::{FheDecrypt, FheTrivialEncrypt, FheTryEncrypt, FheTryTrivialEncrypt};
use crate::{ClientKey, CompactPublicKey, CompressedPublicKey, FheUint, PublicKey};

impl<Id, ClearType> FheDecrypt<ClearType> for FheUint<Id>
where
    Id: FheUintId,
    ClearType: RecomposableFrom<u64> + UnsignedNumeric,
{
    /// Decrypts a [FheUint] to an unsigned type.
    ///
    /// The unsigned type has to be explicit.
    ///
    /// # Example
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(7288u16, &client_key);
    ///
    /// // u16 is explicit
    /// let decrypted: u16 = a.decrypt(&client_key);
    /// assert_eq!(decrypted, 7288u16);
    ///
    /// // u32 is explicit
    /// let decrypted: u32 = a.decrypt(&client_key);
    /// assert_eq!(decrypted, 7288u32);
    /// ```
    fn decrypt(&self, key: &ClientKey) -> ClearType {
        key.key.key.decrypt_radix(&self.ciphertext.on_cpu())
    }
}

impl<Id, T> FheTryEncrypt<T, ClientKey> for FheUint<Id>
where
    Id: FheUintId,
    T: DecomposableInto<u64> + UnsignedNumeric,
{
    type Error = crate::Error;

    fn try_encrypt(value: T, key: &ClientKey) -> Result<Self, Self::Error> {
        let cpu_ciphertext = key
            .key
            .key
            .encrypt_radix(value, Id::num_blocks(key.message_modulus()));
        let mut ciphertext = Self::new(cpu_ciphertext);

        ciphertext.move_to_device_of_server_key_if_set();

        Ok(ciphertext)
    }
}

impl<Id, T> FheTryEncrypt<T, PublicKey> for FheUint<Id>
where
    Id: FheUintId,
    T: DecomposableInto<u64> + UnsignedNumeric,
{
    type Error = crate::Error;

    fn try_encrypt(value: T, key: &PublicKey) -> Result<Self, Self::Error> {
        let cpu_ciphertext = key
            .key
            .encrypt_radix(value, Id::num_blocks(key.message_modulus()));
        let mut ciphertext = Self::new(cpu_ciphertext);

        ciphertext.move_to_device_of_server_key_if_set();

        Ok(ciphertext)
    }
}

impl<Id, T> FheTryEncrypt<T, CompressedPublicKey> for FheUint<Id>
where
    Id: FheUintId,
    T: DecomposableInto<u64> + UnsignedNumeric,
{
    type Error = crate::Error;

    fn try_encrypt(value: T, key: &CompressedPublicKey) -> Result<Self, Self::Error> {
        let cpu_ciphertext = key
            .key
            .encrypt_radix(value, Id::num_blocks(key.message_modulus()));
        let mut ciphertext = Self::new(cpu_ciphertext);

        ciphertext.move_to_device_of_server_key_if_set();
        Ok(ciphertext)
    }
}

impl<Id, T> FheTryEncrypt<T, CompactPublicKey> for FheUint<Id>
where
    Id: FheUintId,
    T: DecomposableInto<u64> + UnsignedNumeric,
{
    type Error = crate::Error;

    fn try_encrypt(value: T, key: &CompactPublicKey) -> Result<Self, Self::Error> {
        let cpu_ciphertext = key
            .key
            .key
            .encrypt_radix(value, Id::num_blocks(key.message_modulus()));
        let mut ciphertext = Self::new(cpu_ciphertext);

        ciphertext.move_to_device_of_server_key_if_set();
        Ok(ciphertext)
    }
}

impl<Id, T> FheTryTrivialEncrypt<T> for FheUint<Id>
where
    T: DecomposableInto<u64> + UnsignedNumeric,
    Id: FheUintId,
{
    type Error = crate::Error;

    fn try_encrypt_trivial(value: T) -> Result<Self, Self::Error> {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let ciphertext: crate::integer::RadixCiphertext = key
                    .pbs_key()
                    .create_trivial_radix(value, Id::num_blocks(key.message_modulus()));
                Ok(Self::new(ciphertext))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner = cuda_key.key.create_trivial_radix(
                    value,
                    Id::num_blocks(cuda_key.key.message_modulus),
                    stream,
                );
                Ok(Self::new(inner))
            }),
        })
    }
}

impl<Id, T> FheTrivialEncrypt<T> for FheUint<Id>
where
    T: DecomposableInto<u64> + UnsignedNumeric,
    Id: FheUintId,
{
    /// Creates a trivially encrypted FheUint
    ///
    /// A trivial encryption is not an encryption, the value can be retrieved
    /// by anyone as if it were a clear value.
    ///
    /// Thus no client or public key is needed to create a trivial encryption,
    /// this can be useful to initialize some values.
    ///
    /// As soon as a trivial encryption is used in an operation that involves
    /// non trivial encryption, the result will be non trivial (secure).
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt_trivial(7288u16);
    ///
    /// let decrypted: u16 = a.decrypt(&client_key);
    /// assert_eq!(decrypted, 7288u16);
    /// ```
    #[track_caller]
    fn encrypt_trivial(value: T) -> Self {
        Self::try_encrypt_trivial(value).unwrap()
    }
}
