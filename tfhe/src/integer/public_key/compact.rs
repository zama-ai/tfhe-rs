use crate::core_crypto::commons::traits::Container;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::CompactCiphertextList;
use crate::integer::client_key::secret_encryption_key::SecretEncryptionKey;
use crate::integer::ClientKey;
use crate::shortint::parameters::compact_public_key_only::CompactPublicKeyEncryptionParameters;
use crate::shortint::{
    CompactPrivateKey as ShortintCompactPrivateKey, CompactPublicKey as ShortintCompactPublicKey,
    CompressedCompactPublicKey as ShortintCompressedCompactPublicKey,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactPrivateKey<C: Container<Element = u64>> {
    pub(crate) key: ShortintCompactPrivateKey<C>,
}

impl<C: Container<Element = u64>> CompactPrivateKey<C> {
    pub fn from_raw_parts(key: ShortintCompactPrivateKey<C>) -> Self {
        Self { key }
    }

    pub fn into_raw_parts(self) -> ShortintCompactPrivateKey<C> {
        let Self { key } = self;
        key
    }

    pub fn key(&self) -> &ShortintCompactPrivateKey<C> {
        &self.key
    }
}

impl CompactPrivateKey<Vec<u64>> {
    pub fn new(parameters: CompactPublicKeyEncryptionParameters) -> Self {
        Self {
            key: ShortintCompactPrivateKey::new(parameters),
        }
    }
}

impl<'key, C: Container<Element = u64>> TryFrom<&'key CompactPrivateKey<C>>
    for CompactPrivateKey<&'key [u64]>
{
    type Error = crate::Error;

    fn try_from(value: &'key CompactPrivateKey<C>) -> Result<Self, Self::Error> {
        Ok(Self {
            key: value.key().as_view(),
        })
    }
}

impl<'key> TryFrom<&'key ClientKey> for CompactPrivateKey<&'key [u64]> {
    type Error = crate::Error;

    fn try_from(client_key: &'key ClientKey) -> Result<Self, Self::Error> {
        let compact_private_key: ShortintCompactPrivateKey<&'key [u64]> =
            (&client_key.key).try_into()?;

        Ok(Self {
            key: compact_private_key,
        })
    }
}

impl<'key, C: Container<Element = u64>> From<&'key CompactPrivateKey<C>>
    for SecretEncryptionKey<&'key [u64]>
{
    fn from(value: &'key CompactPrivateKey<C>) -> Self {
        Self {
            key: (&value.key).into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompactPublicKey {
    pub(crate) key: ShortintCompactPublicKey,
}

impl CompactPublicKey {
    pub fn new<'data, C>(compact_private_key: C) -> Self
    where
        C: TryInto<CompactPrivateKey<&'data [u64]>, Error = crate::Error>,
    {
        Self::try_new(compact_private_key).expect(
            "Incompatible parameters, the lwe_dimension of the secret key must be a power of two",
        )
    }

    pub fn try_new<'data, C>(input_key: C) -> Result<Self, crate::Error>
    where
        C: TryInto<CompactPrivateKey<&'data [u64]>, Error = crate::Error>,
    {
        let compact_private_key: CompactPrivateKey<&[u64]> = input_key.try_into()?;

        let key = ShortintCompactPublicKey::new(&compact_private_key.key);
        Ok(Self { key })
    }

    /// Deconstruct a [`CompactPublicKey`] into its constituents.
    pub fn into_raw_parts(self) -> ShortintCompactPublicKey {
        self.key
    }

    /// Construct a [`CompactPublicKey`] from its constituents.
    pub fn from_raw_parts(key: ShortintCompactPublicKey) -> Self {
        Self { key }
    }

    pub fn encrypt_radix_compact<T: DecomposableInto<u64> + std::ops::Shl<usize, Output = T>>(
        &self,
        message: T,
        num_blocks_per_integer: usize,
    ) -> CompactCiphertextList {
        CompactCiphertextList::builder(self)
            .push_with_num_blocks(message, num_blocks_per_integer)
            .build()
    }

    pub fn encrypt_slice_radix_compact<
        T: DecomposableInto<u64> + std::ops::Shl<usize, Output = T>,
    >(
        &self,
        messages: &[T],
        num_blocks: usize,
    ) -> CompactCiphertextList {
        self.encrypt_iter_radix_compact(messages.iter().copied(), num_blocks)
    }

    pub fn encrypt_iter_radix_compact<
        T: DecomposableInto<u64> + std::ops::Shl<usize, Output = T>,
    >(
        &self,
        message_iter: impl Iterator<Item = T>,
        num_blocks_per_integer: usize,
    ) -> CompactCiphertextList {
        let mut builder = CompactCiphertextList::builder(self);
        builder.extend_with_num_blocks(message_iter, num_blocks_per_integer);
        builder.build()
    }

    pub fn size_elements(&self) -> usize {
        self.key.size_elements()
    }

    pub fn size_bytes(&self) -> usize {
        self.key.size_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompressedCompactPublicKey {
    pub(crate) key: ShortintCompressedCompactPublicKey,
}

impl CompressedCompactPublicKey {
    pub fn new(client_key: &ClientKey) -> Self {
        let key = ShortintCompressedCompactPublicKey::new(&client_key.key);
        Self { key }
    }

    /// Deconstruct a [`CompressedCompactPublicKey`] into its constituents.
    pub fn into_raw_parts(self) -> ShortintCompressedCompactPublicKey {
        self.key
    }

    /// Construct a [`CompressedCompactPublicKey`] from its constituents.
    pub fn from_raw_parts(key: ShortintCompressedCompactPublicKey) -> Self {
        Self { key }
    }

    pub fn decompress(&self) -> CompactPublicKey {
        CompactPublicKey {
            key: self.key.decompress(),
        }
    }
}
