use tfhe_versionable::Versionize;

use crate::backward_compatibility::integers::{
    CompressedFheIntVersions, CompressedSignedRadixCiphertextVersions,
};
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::SignedNumeric;
use crate::high_level_api::global_state::with_cpu_internal_keys;
use crate::high_level_api::integers::signed::base::FheIntConformanceParams;
use crate::high_level_api::integers::{FheInt, FheIntId};
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use crate::high_level_api::traits::Tagged;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::{
    CompressedModulusSwitchedSignedRadixCiphertext,
    CompressedSignedRadixCiphertext as IntegerCompressedSignedRadixCiphertext,
};
use crate::integer::parameters::RadixCiphertextConformanceParams;
use crate::named::Named;
use crate::prelude::FheTryEncrypt;
use crate::{ClientKey, Tag};

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
#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedFheIntVersions)]
pub struct CompressedFheInt<Id>
where
    Id: FheIntId,
{
    pub(in crate::high_level_api) ciphertext: CompressedSignedRadixCiphertext,
    pub(in crate::high_level_api) id: Id,
    pub(crate) tag: Tag,
}

impl<Id> Tagged for CompressedFheInt<Id>
where
    Id: FheIntId,
{
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

impl<Id> CompressedFheInt<Id>
where
    Id: FheIntId,
{
    pub(in crate::high_level_api::integers) fn new(
        inner: CompressedSignedRadixCiphertext,
        tag: Tag,
    ) -> Self {
        Self {
            ciphertext: inner,
            id: Id::default(),
            tag,
        }
    }

    pub fn into_raw_parts(self) -> (CompressedSignedRadixCiphertext, Id, Tag) {
        let Self {
            ciphertext,
            id,
            tag,
        } = self;
        (ciphertext, id, tag)
    }

    pub fn from_raw_parts(ciphertext: CompressedSignedRadixCiphertext, id: Id, tag: Tag) -> Self {
        Self {
            ciphertext,
            id,
            tag,
        }
    }
}

impl<Id> CompressedFheInt<Id>
where
    Id: FheIntId,
{
    /// Decompress to a [FheInt]
    ///
    /// See [CompressedFheInt] example.
    pub fn decompress(&self) -> FheInt<Id> {
        let ciphertext = match &self.ciphertext {
            CompressedSignedRadixCiphertext::Seeded(ct) => ct.decompress(),
            CompressedSignedRadixCiphertext::ModulusSwitched(ct) => {
                with_cpu_internal_keys(|sk| sk.pbs_key().decompress_signed_parallelized(ct))
            }
        };
        FheInt::new(
            ciphertext,
            self.tag.clone(),
            ReRandomizationMetadata::default(),
        )
    }
}

impl<Id, T> FheTryEncrypt<T, ClientKey> for CompressedFheInt<Id>
where
    Id: FheIntId,
    T: DecomposableInto<u64> + SignedNumeric,
{
    type Error = crate::Error;

    fn try_encrypt(value: T, key: &ClientKey) -> Result<Self, Self::Error> {
        let integer_client_key = &key.key.key;
        let inner = integer_client_key
            .encrypt_signed_radix_compressed(value, Id::num_blocks(key.message_modulus()));
        Ok(Self::new(
            CompressedSignedRadixCiphertext::Seeded(inner),
            key.tag.clone(),
        ))
    }
}

impl<Id: FheIntId> ParameterSetConformant for CompressedFheInt<Id> {
    type ParameterSet = FheIntConformanceParams<Id>;

    fn is_conformant(&self, params: &FheIntConformanceParams<Id>) -> bool {
        let Self {
            ciphertext,
            id: _,
            tag: _,
        } = self;

        ciphertext.is_conformant(&params.params)
    }
}

impl<Id: FheIntId> Named for CompressedFheInt<Id> {
    const NAME: &'static str = "high_level_api::CompressedFheInt";
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedSignedRadixCiphertextVersions)]
pub enum CompressedSignedRadixCiphertext {
    Seeded(IntegerCompressedSignedRadixCiphertext),
    ModulusSwitched(CompressedModulusSwitchedSignedRadixCiphertext),
}

impl ParameterSetConformant for CompressedSignedRadixCiphertext {
    type ParameterSet = RadixCiphertextConformanceParams;
    fn is_conformant(&self, params: &RadixCiphertextConformanceParams) -> bool {
        match self {
            Self::Seeded(ct) => ct.is_conformant(params),
            Self::ModulusSwitched(ct) => ct.is_conformant(params),
        }
    }
}

impl<Id> FheInt<Id>
where
    Id: FheIntId,
{
    pub fn compress(&self) -> CompressedFheInt<Id> {
        let a = with_cpu_internal_keys(|sk| {
            sk.pbs_key()
                .switch_modulus_and_compress_signed_parallelized(&self.ciphertext.on_cpu())
        });

        CompressedFheInt::new(
            CompressedSignedRadixCiphertext::ModulusSwitched(a),
            self.tag.clone(),
        )
    }
}
