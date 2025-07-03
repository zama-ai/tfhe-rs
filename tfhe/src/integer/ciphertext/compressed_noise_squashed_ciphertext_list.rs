use super::{
    DataKind, SquashedNoiseBooleanBlock, SquashedNoiseRadixCiphertext,
    SquashedNoiseSignedRadixCiphertext,
};
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::commons::math::random::{Deserialize, Serialize};
use crate::core_crypto::gpu::CudaStreams;
use crate::integer::backward_compatibility::list_compression::{
    CompressedNoiseSquashingCompressionKeyVersions, CompressedSquashedNoiseCiphertextListVersions,
    NoiseSquashingCompressionPrivateKeyVersions,
};
use crate::integer::noise_squashing::{NoiseSquashingPrivateKey, NoiseSquashingPrivateKeyView};
use crate::named::Named;
use crate::shortint::ciphertext::{
    CompressedSquashedNoiseCiphertextList as ShortintCompressedSquashedNoiseCiphertextList,
    SquashedNoiseCiphertext,
};
use crate::shortint::list_compression::{
    CompressedNoiseSquashingCompressionKey as ShortintCompressedNoiseSquashingCompressionKey,
    NoiseSquashingCompressionKey as ShortintNoiseSquashingCompressionKey,
    NoiseSquashingCompressionKeyConformanceParams,
    NoiseSquashingCompressionPrivateKey as ShortintNoiseSquashingCompressionPrivateKey,
};
use crate::shortint::parameters::NoiseSquashingCompressionParameters;
use crate::Versionize;

use crate::integer::backward_compatibility::list_compression::NoiseSquashingCompressionKeyVersions;
use crate::integer::gpu::ciphertext::{
    CudaCompressedSquashedNoiseCiphertextList, SquashedCudaCompressible,
};
use crate::integer::gpu::list_compression::server_keys::CudaNoiseSquashingCompressionKey;

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(NoiseSquashingCompressionPrivateKeyVersions)]
pub struct NoiseSquashingCompressionPrivateKey {
    pub(crate) key: ShortintNoiseSquashingCompressionPrivateKey,
}

impl Named for NoiseSquashingCompressionPrivateKey {
    const NAME: &'static str = "integer::NoiseSquashingCompressionPrivateKey";
}

impl NoiseSquashingCompressionPrivateKey {
    pub fn new(params: NoiseSquashingCompressionParameters) -> Self {
        let key = ShortintNoiseSquashingCompressionPrivateKey::new(params);

        Self { key }
    }

    pub fn private_key_view(&self) -> NoiseSquashingPrivateKeyView {
        NoiseSquashingPrivateKeyView {
            key: (&self.key).into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CompressedNoiseSquashingCompressionKeyVersions)]
pub struct CompressedNoiseSquashingCompressionKey {
    pub(crate) key: ShortintCompressedNoiseSquashingCompressionKey,
}

impl ParameterSetConformant for CompressedNoiseSquashingCompressionKey {
    type ParameterSet = NoiseSquashingCompressionKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self { key } = self;
        key.is_conformant(parameter_set)
    }
}

impl CompressedNoiseSquashingCompressionKey {
    pub fn decompress(&self) -> NoiseSquashingCompressionKey {
        let key = self.key.decompress();
        NoiseSquashingCompressionKey { key }
    }
}

impl Named for CompressedNoiseSquashingCompressionKey {
    const NAME: &'static str = "integer::CompressedNoiseSquashingCompressionKey";
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(NoiseSquashingCompressionKeyVersions)]
pub struct NoiseSquashingCompressionKey {
    pub(crate) key: ShortintNoiseSquashingCompressionKey,
}

impl Named for NoiseSquashingCompressionKey {
    const NAME: &'static str = "integer::NoiseSquashingCompressionKey";
}

impl ParameterSetConformant for NoiseSquashingCompressionKey {
    type ParameterSet = NoiseSquashingCompressionKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self { key } = self;
        key.is_conformant(parameter_set)
    }
}

impl NoiseSquashingPrivateKey {
    pub fn new_noise_squashing_compression_key(
        &self,
        private_compression_key: &NoiseSquashingCompressionPrivateKey,
    ) -> NoiseSquashingCompressionKey {
        let key = self
            .key
            .new_noise_squashing_compression_key(&private_compression_key.key);

        NoiseSquashingCompressionKey { key }
    }

    pub fn new_compressed_noise_squashing_compression_key(
        &self,
        private_compression_key: &NoiseSquashingCompressionPrivateKey,
    ) -> CompressedNoiseSquashingCompressionKey {
        let key = self
            .key
            .new_compressed_noise_squashing_compression_key(&private_compression_key.key);

        CompressedNoiseSquashingCompressionKey { key }
    }
}

/// List that stores compressed noise squashed ciphertext
#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CompressedSquashedNoiseCiphertextListVersions)]
pub struct CompressedSquashedNoiseCiphertextList {
    pub(crate) list: ShortintCompressedSquashedNoiseCiphertextList,
    pub(crate) info: Vec<DataKind>,
}

impl Named for CompressedSquashedNoiseCiphertextList {
    const NAME: &'static str = "integer::CompressedSquashedNoiseCiphertextList";
}

impl CompressedSquashedNoiseCiphertextList {
    /// Returns a builder to create a list
    pub fn builder() -> CompressedSquashedNoiseCiphertextListBuilder {
        CompressedSquashedNoiseCiphertextListBuilder::new()
    }

    /// Returns the number of squashed noise ciphertext that are stored
    pub fn len(&self) -> usize {
        self.info.len()
    }

    // Returns whether the list is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn blocks_of(&self, index: usize) -> Option<(Vec<SquashedNoiseCiphertext>, DataKind)> {
        let preceding_infos = self.info.get(..index)?;
        let current_info = self.info.get(index).copied()?;
        let message_modulus = self.list.message_modulus().unwrap();

        let start_block_index: usize = preceding_infos
            .iter()
            .copied()
            .map(|kind| kind.num_blocks(message_modulus).div_ceil(2))
            .sum();

        let end_block_index =
            start_block_index + current_info.num_blocks(message_modulus).div_ceil(2);

        Some((
            (start_block_index..end_block_index)
                .map(|i| self.list.unpack(i).unwrap())
                .collect(),
            current_info,
        ))
    }

    pub fn get_kind_of(&self, index: usize) -> Option<DataKind> {
        self.info.get(index).copied()
    }

    /// Decompress the squashed noise ciphertext at the given index slot
    ///
    /// # Note
    ///
    /// After decompression, the resulting ciphertext is under the parameters
    /// of the [NoiseSquashingCompressionKey].
    pub fn get<T>(&self, index: usize) -> crate::Result<Option<T>>
    where
        T: SquashedNoiseExpandable,
    {
        self.blocks_of(index)
            .map(|(ns_blocks, data_kind)| T::from_expanded_blocks(ns_blocks, data_kind))
            .transpose()
    }
}

mod sealed {
    use super::*;
    pub trait Sealed {}

    impl Sealed for SquashedNoiseRadixCiphertext {}
    impl Sealed for SquashedNoiseSignedRadixCiphertext {}
    impl Sealed for SquashedNoiseBooleanBlock {}

    impl Sealed for crate::SquashedNoiseFheBool {}
    impl Sealed for crate::SquashedNoiseFheUint {}
    impl Sealed for crate::SquashedNoiseFheInt {}
}

pub trait SquashedNoiseCompressible: sealed::Sealed {
    fn compress_into(self, messages: &mut Vec<SquashedNoiseCiphertext>) -> DataKind;
}

impl SquashedNoiseCompressible for SquashedNoiseRadixCiphertext {
    fn compress_into(mut self, messages: &mut Vec<SquashedNoiseCiphertext>) -> DataKind {
        messages.append(&mut self.packed_blocks);
        DataKind::Unsigned(self.original_block_count)
    }
}

impl SquashedNoiseCompressible for SquashedNoiseSignedRadixCiphertext {
    fn compress_into(mut self, messages: &mut Vec<SquashedNoiseCiphertext>) -> DataKind {
        messages.append(&mut self.packed_blocks);
        DataKind::Signed(self.original_block_count)
    }
}

impl SquashedNoiseCompressible for SquashedNoiseBooleanBlock {
    fn compress_into(self, messages: &mut Vec<SquashedNoiseCiphertext>) -> DataKind {
        messages.push(self.ciphertext);
        DataKind::Boolean
    }
}

pub trait SquashedNoiseExpandable: Sized + sealed::Sealed {
    fn from_expanded_blocks(
        blocks: Vec<SquashedNoiseCiphertext>,
        kind: DataKind,
    ) -> crate::Result<Self>;
}

fn create_error_message(tried: DataKind, actual: DataKind) -> crate::Error {
    fn name(kind: DataKind) -> &'static str {
        match kind {
            DataKind::Unsigned(_) => "SquashedNoiseRadixCiphertext",
            DataKind::Signed(_) => "SquashedNoiseSignedRadixCiphertext",
            DataKind::Boolean => "SquashedNoiseBooleanBlock",
            DataKind::String { .. } => "SquashedNoiseFheString",
        }
    }
    crate::error!(
        "Tried to expand a {}, but a {} is stored in this slot",
        name(tried),
        name(actual)
    )
}

impl SquashedNoiseExpandable for SquashedNoiseRadixCiphertext {
    fn from_expanded_blocks(
        blocks: Vec<SquashedNoiseCiphertext>,
        kind: DataKind,
    ) -> crate::Result<Self> {
        if let DataKind::Unsigned(block_count) = kind {
            Ok(Self {
                packed_blocks: blocks,
                original_block_count: block_count,
            })
        } else {
            Err(create_error_message(DataKind::Unsigned(0), kind))
        }
    }
}

impl SquashedNoiseExpandable for SquashedNoiseSignedRadixCiphertext {
    fn from_expanded_blocks(
        blocks: Vec<SquashedNoiseCiphertext>,
        kind: DataKind,
    ) -> crate::Result<Self> {
        if let DataKind::Signed(block_count) = kind {
            Ok(Self {
                packed_blocks: blocks,
                original_block_count: block_count,
            })
        } else {
            Err(create_error_message(DataKind::Signed(0), kind))
        }
    }
}

impl SquashedNoiseExpandable for SquashedNoiseBooleanBlock {
    fn from_expanded_blocks(
        mut blocks: Vec<SquashedNoiseCiphertext>,
        kind: DataKind,
    ) -> crate::Result<Self> {
        if DataKind::Boolean == kind {
            assert_eq!(blocks.len(), 1);
            Ok(Self {
                ciphertext: blocks.pop().unwrap(),
            })
        } else {
            Err(create_error_message(DataKind::Boolean, kind))
        }
    }
}

pub struct CompressedSquashedNoiseCiphertextListBuilder {
    list: Vec<SquashedNoiseCiphertext>,
    info: Vec<DataKind>,
}

impl Default for CompressedSquashedNoiseCiphertextListBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CompressedSquashedNoiseCiphertextListBuilder {
    pub fn new() -> Self {
        Self {
            list: vec![],
            info: vec![],
        }
    }

    pub fn push(&mut self, value: impl SquashedNoiseCompressible) -> &mut Self {
        let n = self.list.len();
        let kind = value.compress_into(&mut self.list);

        // Check that the number of blocks that were added matches the
        // number of blocks advertised by the DataKind
        let num_blocks = self
            .list
            .last()
            .map_or(0, |ct| kind.num_blocks(ct.message_modulus()))
            .div_ceil(2); // Because blocks are packed when noise squashed
        assert_eq!(n + num_blocks, self.list.len());

        self.info.push(kind);
        self
    }

    pub fn build(
        &self,
        comp_key: &NoiseSquashingCompressionKey,
    ) -> CompressedSquashedNoiseCiphertextList {
        let list = comp_key
            .key
            .compress_noise_squashed_ciphertexts_into_list(&self.list);

        CompressedSquashedNoiseCiphertextList {
            list,
            info: self.info.clone(),
        }
    }
}
