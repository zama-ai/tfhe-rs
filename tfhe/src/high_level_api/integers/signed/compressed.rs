use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::SignedNumeric;
use crate::high_level_api::integers::{FheInt, FheIntId};
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::CompressedSignedRadixCiphertext;
use crate::integer::parameters::RadixCiphertextConformanceParams;
use crate::named::Named;
use crate::prelude::FheTryEncrypt;
use crate::shortint::PBSParameters;
use crate::{ClientKey, ServerKey};
use std::marker::PhantomData;

/// Compressed [FheInt]
///
/// Meant to save in storage space / transfer.
///
/// - A Compressed type must be decompressed using [decompress](Self::decompress) before it can be
///   used.
/// - It is not possible to compress an existing [FheInt]. compression can only be achieved at
///   encryption time by a [ClientKey]
///
///
/// # Example
///
/// ```rust
/// use tfhe::prelude::*;
/// use tfhe::{generate_keys, CompressedFheInt32, ConfigBuilder};
///
/// let (client_key, _) = generate_keys(ConfigBuilder::default());
/// let compressed = CompressedFheInt32::encrypt(i32::MIN, &client_key);
///
/// let decompressed = compressed.decompress();
/// let decrypted: i32 = decompressed.decrypt(&client_key);
/// assert_eq!(decrypted, i32::MIN);
/// ```
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CompressedFheInt<Id>
where
    Id: FheIntId,
{
    pub(in crate::high_level_api::integers) ciphertext: CompressedSignedRadixCiphertext,
    pub(in crate::high_level_api::integers) id: Id,
}

impl<Id> CompressedFheInt<Id>
where
    Id: FheIntId,
{
    pub(in crate::high_level_api::integers) fn new(inner: CompressedSignedRadixCiphertext) -> Self {
        Self {
            ciphertext: inner,
            id: Id::default(),
        }
    }

    pub fn into_raw_parts(self) -> (CompressedSignedRadixCiphertext, Id) {
        let Self { ciphertext, id } = self;
        (ciphertext, id)
    }

    pub fn from_raw_parts(ciphertext: CompressedSignedRadixCiphertext, id: Id) -> Self {
        Self { ciphertext, id }
    }
}

impl<Id> CompressedFheInt<Id>
where
    Id: FheIntId,
{
    /// Decompress to a [FheInt]
    ///
    /// See [CompressedFheInt] example.
    pub fn decompress(self) -> FheInt<Id> {
        let inner = self.ciphertext.into();
        FheInt::new(inner)
    }
}

impl<Id, T> FheTryEncrypt<T, ClientKey> for CompressedFheInt<Id>
where
    Id: FheIntId,
    T: DecomposableInto<u64> + SignedNumeric,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &ClientKey) -> Result<Self, Self::Error> {
        let integer_client_key = &key.key.key;
        let inner = integer_client_key
            .encrypt_signed_radix_compressed(value, Id::num_blocks(key.message_modulus()));
        Ok(Self::new(inner))
    }
}

pub struct CompressedFheIntConformanceParams<Id: FheIntId> {
    params: RadixCiphertextConformanceParams,
    id: PhantomData<Id>,
}

impl<Id: FheIntId, P: Into<PBSParameters>> From<P> for CompressedFheIntConformanceParams<Id> {
    fn from(params: P) -> Self {
        let params = params.into();
        Self {
            params: RadixCiphertextConformanceParams {
                shortint_params: params.to_shortint_conformance_param(),
                num_blocks_per_integer: Id::num_blocks(params.message_modulus()),
            },
            id: PhantomData,
        }
    }
}

impl<Id: FheIntId> From<&ServerKey> for CompressedFheIntConformanceParams<Id> {
    fn from(sk: &ServerKey) -> Self {
        Self {
            params: RadixCiphertextConformanceParams {
                shortint_params: sk.key.pbs_key().key.conformance_params(),
                num_blocks_per_integer: Id::num_blocks(sk.key.pbs_key().message_modulus()),
            },
            id: PhantomData,
        }
    }
}

impl<Id: FheIntId> ParameterSetConformant for CompressedFheInt<Id> {
    type ParameterSet = CompressedFheIntConformanceParams<Id>;

    fn is_conformant(&self, params: &CompressedFheIntConformanceParams<Id>) -> bool {
        self.ciphertext.is_conformant(&params.params)
    }
}

impl<Id: FheIntId> Named for CompressedFheInt<Id> {
    const NAME: &'static str = "high_level_api::CompressedFheInt";
}
