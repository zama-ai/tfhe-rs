use super::{
    DataKind, SquashedNoiseBooleanBlock, SquashedNoiseRadixCiphertext,
    SquashedNoiseSignedRadixCiphertext,
};
use crate::conformance::ParameterSetConformant;
#[cfg(feature = "gpu")]
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
use serde::{Deserialize, Serialize};
use std::num::NonZero;

use crate::integer::backward_compatibility::list_compression::NoiseSquashingCompressionKeyVersions;
#[cfg(feature = "gpu")]
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

    pub fn private_key_view(&self) -> NoiseSquashingPrivateKeyView<'_> {
        NoiseSquashingPrivateKeyView {
            key: (&self.key).into(),
        }
    }

    pub fn from_raw_parts(key: ShortintNoiseSquashingCompressionPrivateKey) -> Self {
        Self { key }
    }

    pub fn into_raw_parts(self) -> ShortintNoiseSquashingCompressionPrivateKey {
        self.key
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

    #[cfg(feature = "gpu")]
    pub fn decompress_to_cuda(&self, streams: &CudaStreams) -> CudaNoiseSquashingCompressionKey {
        let compression_key = self.decompress();

        CudaNoiseSquashingCompressionKey::from_noise_squashing_compression_key(
            &compression_key,
            streams,
        )
    }

    pub fn from_raw_parts(key: ShortintCompressedNoiseSquashingCompressionKey) -> Self {
        Self { key }
    }

    pub fn into_raw_parts(self) -> ShortintCompressedNoiseSquashingCompressionKey {
        self.key
    }
}

impl Named for CompressedNoiseSquashingCompressionKey {
    const NAME: &'static str = "integer::CompressedNoiseSquashingCompressionKey";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(NoiseSquashingCompressionKeyVersions)]
pub struct NoiseSquashingCompressionKey {
    pub(crate) key: ShortintNoiseSquashingCompressionKey,
}

impl NoiseSquashingCompressionKey {
    pub fn from_raw_parts(key: ShortintNoiseSquashingCompressionKey) -> Self {
        Self { key }
    }

    pub fn into_raw_parts(self) -> ShortintNoiseSquashingCompressionKey {
        self.key
    }
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
    fn compress_into(self, messages: &mut Vec<SquashedNoiseCiphertext>) -> Option<DataKind>;
}

impl SquashedNoiseCompressible for SquashedNoiseRadixCiphertext {
    fn compress_into(mut self, messages: &mut Vec<SquashedNoiseCiphertext>) -> Option<DataKind> {
        messages.append(&mut self.packed_blocks);
        NonZero::new(self.original_block_count).map(DataKind::Unsigned)
    }
}

impl SquashedNoiseCompressible for SquashedNoiseSignedRadixCiphertext {
    fn compress_into(mut self, messages: &mut Vec<SquashedNoiseCiphertext>) -> Option<DataKind> {
        messages.append(&mut self.packed_blocks);
        NonZero::new(self.original_block_count).map(DataKind::Signed)
    }
}

impl SquashedNoiseCompressible for SquashedNoiseBooleanBlock {
    fn compress_into(self, messages: &mut Vec<SquashedNoiseCiphertext>) -> Option<DataKind> {
        messages.push(self.ciphertext);
        Some(DataKind::Boolean)
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
                original_block_count: block_count.get(),
            })
        } else {
            Err(create_error_message(
                DataKind::Unsigned(1.try_into().unwrap()),
                kind,
            ))
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
                original_block_count: block_count.get(),
            })
        } else {
            Err(create_error_message(
                DataKind::Signed(1.try_into().unwrap()),
                kind,
            ))
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
        let maybe_kind = value.compress_into(&mut self.list);

        let Some(modulus) = self.list.last().map(|ct| ct.message_modulus()) else {
            assert!(
                maybe_kind.is_none(),
                "Internal error: Incoherent block count with regard to kind"
            );
            return self;
        };

        let Some(kind) = maybe_kind else {
            assert_eq!(
                n,
                self.list.len(),
                "Internal error: Incoherent block count with regard to kind"
            );
            return self;
        };

        let num_blocks = kind.num_blocks(modulus).div_ceil(2); // Because blocks are packed when noise squashed

        // Check that the number of blocks that were added matches the
        // number of blocks advertised by the DataKind
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::integer::noise_squashing::NoiseSquashingKey;
    use crate::shortint::parameters::test_params::{
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use rand::Rng;

    #[test]
    fn test_compressed_noise_squashed_ciphertext_list() {
        let param = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_parameters =
            TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        // The goal is to test that encrypting a value stored in a type
        // for which the bit count does not match the target block count of the encrypted
        // radix properly applies upcasting/downcasting
        let (cks, sks) = crate::integer::keycache::KEY_CACHE
            .get_from_params(param, crate::integer::IntegerKeyKind::Radix);
        let noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_parameters);
        let noise_squashing_key = NoiseSquashingKey::new(&cks, &noise_squashing_private_key);

        let noise_squashing_compression_private_key = NoiseSquashingCompressionPrivateKey::new(
            TEST_PARAM_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        );
        let compression_key = noise_squashing_private_key
            .new_noise_squashing_compression_key(&noise_squashing_compression_private_key);

        let mut rng = rand::thread_rng();

        const NUM_BLOCKS: usize = 16;

        let clear_a = rng.gen_range(0..=i32::MAX);
        let clear_b = rng.gen_range(i32::MIN..=-1);
        let clear_c = rng.gen::<u32>();
        let clear_d = rng.gen::<bool>();

        let ct_a = cks.encrypt_signed_radix(clear_a, NUM_BLOCKS);
        let ct_b = cks.encrypt_signed_radix(clear_b, NUM_BLOCKS);
        let ct_c = cks.encrypt_radix(clear_c, NUM_BLOCKS);
        let ct_d = cks.encrypt_bool(clear_d);

        let ns_ct_a = noise_squashing_key
            .squash_signed_radix_ciphertext_noise(&sks, &ct_a)
            .unwrap();
        let ns_ct_b = noise_squashing_key
            .squash_signed_radix_ciphertext_noise(&sks, &ct_b)
            .unwrap();
        let ns_ct_c = noise_squashing_key
            .squash_radix_ciphertext_noise(&sks, &ct_c)
            .unwrap();
        let ns_ct_d = noise_squashing_key
            .squash_boolean_block_noise(&sks, &ct_d)
            .unwrap();

        let list = CompressedSquashedNoiseCiphertextList::builder()
            .push(ns_ct_a)
            .push(ns_ct_b)
            .push(ns_ct_c)
            .push(ns_ct_d)
            .build(&compression_key);

        let ns_ct_a: SquashedNoiseSignedRadixCiphertext = list.get(0).unwrap().unwrap();
        let ns_ct_b: SquashedNoiseSignedRadixCiphertext = list.get(1).unwrap().unwrap();
        let ns_ct_c: SquashedNoiseRadixCiphertext = list.get(2).unwrap().unwrap();
        let ns_ct_d: SquashedNoiseBooleanBlock = list.get(3).unwrap().unwrap();

        let decryption_key = noise_squashing_compression_private_key.private_key_view();

        let d_clear_a: i32 = decryption_key.decrypt_signed_radix(&ns_ct_a).unwrap();
        let d_clear_b: i32 = decryption_key.decrypt_signed_radix(&ns_ct_b).unwrap();
        let d_clear_c: u32 = decryption_key.decrypt_radix(&ns_ct_c).unwrap();
        let d_clear_d = decryption_key.decrypt_bool(&ns_ct_d).unwrap();

        assert_eq!(clear_a, d_clear_a);
        assert_eq!(clear_b, d_clear_b);
        assert_eq!(clear_c, d_clear_c);
        assert_eq!(clear_d, d_clear_d);
    }
}
