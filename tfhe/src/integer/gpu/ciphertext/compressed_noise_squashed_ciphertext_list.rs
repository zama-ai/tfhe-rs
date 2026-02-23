use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::compressed_modulus_switched_glwe_ciphertext::CompressedModulusSwitchedGlweCiphertext;
use crate::core_crypto::prelude::LweCiphertextCount;
use crate::error::error;
use crate::integer::ciphertext::{
    CompressedSquashedNoiseCiphertextList as IntegerCompressedSquashedNoiseCiphertextList,
    CompressedSquashedNoiseCiphertextList, DataKind,
};
use crate::integer::gpu::ciphertext::info::{CudaBlockInfo, CudaRadixCiphertextInfo};
use crate::integer::gpu::ciphertext::squashed_noise::{
    CudaSquashedNoiseBooleanBlock, CudaSquashedNoiseRadixCiphertext,
    CudaSquashedNoiseSignedRadixCiphertext,
};
use crate::integer::gpu::cuda_backend_decompress_128;
use crate::integer::gpu::list_compression::server_keys::{
    CudaNoiseSquashingCompressionKey, CudaPackedGlweCiphertextList,
};
use crate::shortint::ciphertext::{CompressedSquashedNoiseCiphertextListMeta, Degree, NoiseLevel};
use crate::shortint::{AtomicPatternKind, PBSOrder};
use crate::{shortint, GpuIndex};
use itertools::Itertools;
use shortint::ciphertext::CompressedSquashedNoiseCiphertextList as ShortintCompressedSquashedNoiseCiphertextList;
use std::num::NonZeroUsize;

pub struct CudaCompressedSquashedNoiseCiphertextListBuilder {
    pub(crate) ciphertexts: Vec<CudaSquashedNoiseRadixCiphertext>,
    pub(crate) info: Vec<DataKind>,
}

#[derive(Clone)]
pub struct CudaCompressedSquashedNoiseCiphertextList {
    pub(crate) packed_list: CudaPackedGlweCiphertextList<u128>,
    pub(crate) info: Vec<DataKind>,
}

impl CudaCompressedSquashedNoiseCiphertextList {
    pub(crate) fn to_compressed_squashed_noise_ciphertext_list(
        &self,
        streams: &CudaStreams,
    ) -> IntegerCompressedSquashedNoiseCiphertextList {
        // Extract the packed list
        let vec_packed_integers = self.packed_list.to_vec_packed_integers(streams);
        let lwe_per_glwe = self.packed_list.meta.unwrap().lwe_per_glwe;
        let total_num_lwes = self.packed_list.bodies_count();

        let glwe_ciphertext_list = vec_packed_integers
            .iter()
            .enumerate()
            .map(|(pack_index, packed_integers)| {
                // Calculate number of LWEs for this GLWE
                let num_lwes =
                    std::cmp::min(lwe_per_glwe.0, total_num_lwes - pack_index * lwe_per_glwe.0);

                CompressedModulusSwitchedGlweCiphertext::from_raw_parts(
                    packed_integers.clone(),
                    self.packed_list.meta.unwrap().glwe_dimension,
                    self.packed_list.meta.unwrap().polynomial_size,
                    LweCiphertextCount(num_lwes),
                    self.packed_list.meta.unwrap().ciphertext_modulus,
                )
            })
            .collect_vec();

        // Extract the metadata
        let meta = Some(CompressedSquashedNoiseCiphertextListMeta {
            message_modulus: self.packed_list.meta.unwrap().message_modulus,
            carry_modulus: self.packed_list.meta.unwrap().carry_modulus,
            lwe_per_glwe: self.packed_list.meta.unwrap().lwe_per_glwe,
        });

        let list = ShortintCompressedSquashedNoiseCiphertextList {
            glwe_ciphertext_list,
            meta,
        };

        let info = self.info.clone();

        IntegerCompressedSquashedNoiseCiphertextList { list, info }
    }

    pub(crate) fn from_compressed_squashed_noise_ciphertext_list(
        ct: &CompressedSquashedNoiseCiphertextList,
        streams: &CudaStreams,
    ) -> Self {
        Self {
            packed_list: CudaPackedGlweCiphertextList::from_glwe_ciphertext_list(&ct.list, streams),
            info: ct.info.clone(),
        }
    }

    pub fn gpu_indexes(&self) -> &[GpuIndex] {
        self.packed_list.data.gpu_indexes.as_slice()
    }

    pub fn duplicate(&self, streams: &CudaStreams) -> Self {
        Self {
            packed_list: self.packed_list.duplicate(streams),
            info: self.info.clone(),
        }
    }

    /// Returns the number of squashed noise ciphertext that are stored
    pub fn len(&self) -> usize {
        self.info.len()
    }

    pub fn is_empty(&self) -> bool {
        self.info.len() == 0
    }
}

pub trait CudaSquashedNoiseCompressible {
    fn compress_into(
        self,
        messages: &mut Vec<CudaSquashedNoiseRadixCiphertext>,
        streams: &CudaStreams,
    ) -> Option<DataKind>;
}

impl CudaSquashedNoiseCompressible for CudaSquashedNoiseRadixCiphertext {
    fn compress_into(
        self,
        messages: &mut Vec<CudaSquashedNoiseRadixCiphertext>,
        streams: &CudaStreams,
    ) -> Option<DataKind> {
        let x = self.duplicate(streams);
        let num_blocks = x.original_block_count;

        let num_blocks = NonZeroUsize::new(num_blocks);
        if num_blocks.is_some() {
            messages.push(x)
        }
        num_blocks.map(DataKind::Unsigned)
    }
}

impl CudaSquashedNoiseCompressible for CudaSquashedNoiseSignedRadixCiphertext {
    fn compress_into(
        self,
        messages: &mut Vec<CudaSquashedNoiseRadixCiphertext>,
        streams: &CudaStreams,
    ) -> Option<DataKind> {
        let x = self.duplicate(streams);
        let num_blocks = x.ciphertext.original_block_count;

        let num_blocks = NonZeroUsize::new(num_blocks);
        if num_blocks.is_some() {
            messages.push(x.ciphertext)
        }
        num_blocks.map(DataKind::Signed)
    }
}

impl CudaSquashedNoiseCompressible for CudaSquashedNoiseBooleanBlock {
    fn compress_into(
        self,
        messages: &mut Vec<CudaSquashedNoiseRadixCiphertext>,
        streams: &CudaStreams,
    ) -> Option<DataKind> {
        let x = self.duplicate(streams);

        messages.push(x.ciphertext);
        Some(DataKind::Boolean)
    }
}

impl CudaCompressedSquashedNoiseCiphertextListBuilder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            ciphertexts: vec![],
            info: vec![],
        }
    }

    pub fn push<T: CudaSquashedNoiseCompressible>(
        &mut self,
        data: T,
        streams: &CudaStreams,
    ) -> &mut Self {
        if let Some(kind) = data.compress_into(&mut self.ciphertexts, streams) {
            self.info.push(kind);
        }
        self
    }

    pub fn extend<T>(&mut self, values: impl Iterator<Item = T>, streams: &CudaStreams) -> &mut Self
    where
        T: CudaSquashedNoiseCompressible,
    {
        for value in values {
            self.push(value, streams);
        }
        self
    }

    pub fn build(
        &self,
        comp_key: &CudaNoiseSquashingCompressionKey,
        streams: &CudaStreams,
    ) -> CudaCompressedSquashedNoiseCiphertextList {
        let packed_list =
            comp_key.compress_noise_squashed_ciphertexts_into_list(&self.ciphertexts, streams);
        CudaCompressedSquashedNoiseCiphertextList {
            packed_list,
            info: self.info.clone(),
        }
    }
}

fn create_error_message(tried: DataKind, actual: DataKind) -> crate::Error {
    fn name(kind: DataKind) -> &'static str {
        match kind {
            DataKind::Unsigned(_) => "CudaSquashedNoiseRadixCiphertext",
            DataKind::Signed(_) => "CudaSquashedNoiseSignedRadixCiphertext",
            DataKind::Boolean => "CudaSquashedNoiseBooleanBlock",
            DataKind::String { .. } => "Unsupported type",
        }
    }
    error!(
        "Tried to expand a {}, but a {} is stored in this slot",
        name(tried),
        name(actual)
    )
}

pub trait CudaSquashedNoiseExpandable: Sized {
    fn from_expanded_blocks(
        blocks: CudaLweCiphertextList<u128>,
        info: CudaRadixCiphertextInfo,
        kind: DataKind,
    ) -> crate::Result<Self>;
}

impl CudaSquashedNoiseExpandable for CudaSquashedNoiseRadixCiphertext {
    fn from_expanded_blocks(
        blocks: CudaLweCiphertextList<u128>,
        info: CudaRadixCiphertextInfo,
        kind: DataKind,
    ) -> crate::Result<Self> {
        if let DataKind::Unsigned(block_count) = kind {
            Ok(Self {
                packed_d_blocks: blocks,
                original_block_count: block_count.get(),
                info,
            })
        } else {
            Err(create_error_message(
                DataKind::Unsigned(NonZeroUsize::new(0).unwrap()),
                kind,
            ))
        }
    }
}

impl CudaSquashedNoiseExpandable for CudaSquashedNoiseSignedRadixCiphertext {
    fn from_expanded_blocks(
        blocks: CudaLweCiphertextList<u128>,
        info: CudaRadixCiphertextInfo,
        kind: DataKind,
    ) -> crate::Result<Self> {
        if let DataKind::Signed(block_count) = kind {
            Ok(Self {
                ciphertext: CudaSquashedNoiseRadixCiphertext {
                    packed_d_blocks: blocks,
                    original_block_count: block_count.get(),
                    info,
                },
            })
        } else {
            Err(create_error_message(
                DataKind::Signed(NonZeroUsize::new(0).unwrap()),
                kind,
            ))
        }
    }
}

impl CudaSquashedNoiseExpandable for CudaSquashedNoiseBooleanBlock {
    fn from_expanded_blocks(
        blocks: CudaLweCiphertextList<u128>,
        info: CudaRadixCiphertextInfo,
        kind: DataKind,
    ) -> crate::Result<Self> {
        if kind == DataKind::Boolean {
            Ok(Self {
                ciphertext: CudaSquashedNoiseRadixCiphertext {
                    packed_d_blocks: blocks,
                    original_block_count: 1,
                    info,
                },
            })
        } else {
            Err(create_error_message(DataKind::Boolean, kind))
        }
    }
}

impl CudaCompressedSquashedNoiseCiphertextList {
    pub fn builder() -> CudaCompressedSquashedNoiseCiphertextListBuilder {
        CudaCompressedSquashedNoiseCiphertextListBuilder::new()
    }
    pub fn unpack(
        &self,
        kind: DataKind,
        start_block_index: usize,
        end_block_index: usize,
        streams: &CudaStreams,
    ) -> Result<(CudaLweCiphertextList<u128>, CudaRadixCiphertextInfo), crate::Error> {
        // Check this first to make sure we don't try to access the metadata if the list is empty
        if end_block_index >= self.packed_list.bodies_count() {
            return Err(error!(
            "Tried getting index {end_block_index} for CudaCompressedSquashedNoiseCiphertextList \
            with {} elements, out of bound access.",
            self.packed_list.bodies_count()
        ));
        }

        let meta = self.packed_list.meta.as_ref().ok_or_else(|| {
            error!("Missing ciphertext metadata in CudaCompressedSquashedNoiseCiphertextList")
        })?;

        let indexes_array = (start_block_index..=end_block_index)
            .map(|x| x as u32)
            .collect_vec();

        let compression_glwe_dimension = meta.glwe_dimension;
        let compression_polynomial_size = meta.polynomial_size;
        let indexes_array_len = LweCiphertextCount(indexes_array.len());

        let message_modulus = meta.message_modulus;
        let carry_modulus = meta.carry_modulus;
        let ciphertext_modulus = meta.ciphertext_modulus;

        let lwe_dimension = meta
            .glwe_dimension
            .to_equivalent_lwe_dimension(meta.polynomial_size);

        let mut output_lwe = CudaLweCiphertextList::new(
            lwe_dimension,
            indexes_array_len,
            ciphertext_modulus,
            streams,
        );

        unsafe {
            cuda_backend_decompress_128(
                streams,
                &mut output_lwe,
                &self.packed_list,
                message_modulus,
                carry_modulus,
                compression_glwe_dimension,
                compression_polynomial_size,
                lwe_dimension,
                indexes_array.as_slice(),
                indexes_array_len.0 as u32,
            );
        }
        streams.synchronize();
        let degree = match kind {
            DataKind::Unsigned(_) | DataKind::Signed(_) | DataKind::String { .. } => {
                Degree::new(message_modulus.0 - 1)
            }
            DataKind::Boolean => Degree::new(1),
        };

        let first_block_info = CudaBlockInfo {
            degree,
            message_modulus,
            carry_modulus,
            atomic_pattern: AtomicPatternKind::Standard(PBSOrder::KeyswitchBootstrap),
            noise_level: NoiseLevel::NOMINAL,
        };

        let blocks = vec![first_block_info; output_lwe.0.lwe_ciphertext_count.0];

        Ok((output_lwe, CudaRadixCiphertextInfo { blocks }))
    }

    #[allow(clippy::unnecessary_wraps)]
    fn blocks_of(
        &self,
        index: usize,
        streams: &CudaStreams,
    ) -> Option<(
        CudaLweCiphertextList<u128>,
        CudaRadixCiphertextInfo,
        DataKind,
    )> {
        let preceding_infos = self.info.get(..index)?;
        let current_data_kind = self.info.get(index).copied()?;
        let message_modulus = self.packed_list.message_modulus()?;

        // Squashed CTs have blocks packed in pairs
        let start_block_index: usize = preceding_infos
            .iter()
            .copied()
            .map(|kind| kind.num_blocks(message_modulus).div_ceil(2))
            .sum();

        let end_block_index =
            start_block_index + current_data_kind.num_blocks(message_modulus).div_ceil(2) - 1;

        let (unpacked, info) = self
            .unpack(
                current_data_kind,
                start_block_index,
                end_block_index,
                streams,
            )
            .unwrap();
        Some((unpacked, info, current_data_kind))
    }

    pub fn get<T>(&self, index: usize, streams: &CudaStreams) -> crate::Result<Option<T>>
    where
        T: CudaSquashedNoiseExpandable,
    {
        self.blocks_of(index, streams)
            .map(|(blocks, info, kind)| T::from_expanded_blocks(blocks, info, kind))
            .transpose()
    }
}

#[cfg(test)]
mod test {
    use crate::core_crypto::gpu::CudaStreams;
    use crate::integer::ciphertext::NoiseSquashingCompressionPrivateKey;
    use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
    use crate::integer::gpu::ciphertext::squashed_noise::{
        CudaSquashedNoiseBooleanBlock, CudaSquashedNoiseRadixCiphertext,
        CudaSquashedNoiseSignedRadixCiphertext,
    };
    use crate::integer::gpu::ciphertext::{
        CudaCompressedSquashedNoiseCiphertextList, CudaSignedRadixCiphertext,
        CudaUnsignedRadixCiphertext,
    };
    use crate::integer::gpu::list_compression::server_keys::CudaNoiseSquashingCompressionKey;
    use crate::integer::gpu::{gen_keys_radix_gpu, CudaServerKey};
    use crate::integer::noise_squashing::NoiseSquashingPrivateKey;
    use crate::integer::{ClientKey, CompressedServerKey};
    use crate::shortint::parameters::test_params::{
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use crate::shortint::ShortintParameterSet;
    use itertools::Itertools;
    use rand::Rng;

    #[test]
    fn test_cuda_compressed_noise_squashed_ciphertext_list() {
        let param = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_parameters =
            TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_compression_parameters =
            TEST_PARAM_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        const NUM_BLOCKS: usize = 16;
        let streams = CudaStreams::new_multi_gpu();

        let cks = ClientKey::new(param);
        let compressed_sks = CompressedServerKey::new_radix_compressed_server_key(&cks);
        let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_sks, &streams);

        let noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_parameters);

        let compressed_noise_squashing_compression_key =
            cks.new_compressed_noise_squashing_key(&noise_squashing_private_key);

        let cuda_noise_squashing_key =
            compressed_noise_squashing_compression_key.decompress_to_cuda(&streams);

        let noise_squashing_compression_private_key =
            NoiseSquashingCompressionPrivateKey::new(noise_squashing_compression_parameters);
        let noise_squashing_compression_key = noise_squashing_private_key
            .new_noise_squashing_compression_key(&noise_squashing_compression_private_key);
        let cuda_noise_squashing_compression_key =
            CudaNoiseSquashingCompressionKey::from_noise_squashing_compression_key(
                &noise_squashing_compression_key,
                &streams,
            );

        let mut rng = rand::rng();

        let clear_a = rng.gen_range(0..=i32::MAX);
        let clear_b = rng.gen_range(i32::MIN..=-1);
        let clear_c = rng.gen::<u32>();
        let clear_d = rng.gen::<bool>();

        let ct_a = cks.encrypt_signed_radix(clear_a, NUM_BLOCKS);
        let ct_b = cks.encrypt_signed_radix(clear_b, NUM_BLOCKS);
        let ct_c = cks.encrypt_radix(clear_c, NUM_BLOCKS);
        let ct_d = cks.encrypt_bool(clear_d);

        let d_ct_a = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct_a, &streams);
        let d_ct_b = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct_b, &streams);
        let d_ct_c = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_c, &streams);
        let d_ct_d = CudaBooleanBlock::from_boolean_block(&ct_d, &streams);

        let d_ns_ct_a = cuda_noise_squashing_key
            .squash_signed_radix_ciphertext_noise(&cuda_sks, &d_ct_a, &streams)
            .unwrap();
        let d_ns_ct_b = cuda_noise_squashing_key
            .squash_signed_radix_ciphertext_noise(&cuda_sks, &d_ct_b, &streams)
            .unwrap();
        let d_ns_ct_c = cuda_noise_squashing_key
            .squash_radix_ciphertext_noise(&cuda_sks, &d_ct_c.ciphertext, &streams)
            .unwrap();
        let d_ns_ct_d = cuda_noise_squashing_key
            .squash_boolean_block_noise(&cuda_sks, &d_ct_d, &streams)
            .unwrap();

        let cuda_list = CudaCompressedSquashedNoiseCiphertextList::builder()
            .push(d_ns_ct_a, &streams)
            .push(d_ns_ct_b, &streams)
            .push(d_ns_ct_c, &streams)
            .push(d_ns_ct_d, &streams)
            .build(&cuda_noise_squashing_compression_key, &streams);

        let d_decompressed_ns_ct_a: CudaSquashedNoiseSignedRadixCiphertext =
            cuda_list.get(0, &streams).unwrap().unwrap();
        let d_decompressed_ns_ct_b: CudaSquashedNoiseSignedRadixCiphertext =
            cuda_list.get(1, &streams).unwrap().unwrap();
        let d_decompressed_ns_ct_c: CudaSquashedNoiseRadixCiphertext =
            cuda_list.get(2, &streams).unwrap().unwrap();
        let d_decompressed_ns_ct_d: CudaSquashedNoiseBooleanBlock =
            cuda_list.get(3, &streams).unwrap().unwrap();

        let ns_ct_a = d_decompressed_ns_ct_a.to_squashed_noise_signed_radix_ciphertext(&streams);
        let ns_ct_b = d_decompressed_ns_ct_b.to_squashed_noise_signed_radix_ciphertext(&streams);
        let ns_ct_c = d_decompressed_ns_ct_c.to_squashed_noise_radix_ciphertext(&streams);
        let ns_ct_d = d_decompressed_ns_ct_d.to_squashed_noise_boolean_block(&streams);

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

    const NB_TESTS: usize = 5;
    const NB_OPERATOR_TESTS: usize = 3;

    #[test]
    fn test_gpu_extended_compressed_noise_squashed_ciphertext_compression() {
        const NUM_BLOCKS: usize = 16;
        let streams = CudaStreams::new_multi_gpu();

        for (params, noise_squashing_parameters, noise_squashing_compression_parameters) in [(
            TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
            TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            TEST_PARAM_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )] {
            let (radix_cks, sks) =
                gen_keys_radix_gpu::<ShortintParameterSet>(params, NUM_BLOCKS, &streams);
            let cks = radix_cks.as_ref();

            let noise_squashing_private_key =
                NoiseSquashingPrivateKey::new(noise_squashing_parameters);

            let compressed_noise_squashing_compression_key =
                cks.new_compressed_noise_squashing_key(&noise_squashing_private_key);

            let cuda_noise_squashing_key =
                compressed_noise_squashing_compression_key.decompress_to_cuda(&streams);

            let noise_squashing_compression_private_key =
                NoiseSquashingCompressionPrivateKey::new(noise_squashing_compression_parameters);
            let noise_squashing_compression_key = noise_squashing_private_key
                .new_noise_squashing_compression_key(&noise_squashing_compression_private_key);
            let cuda_noise_squashing_compression_key =
                CudaNoiseSquashingCompressionKey::from_noise_squashing_compression_key(
                    &noise_squashing_compression_key,
                    &streams,
                );

            let decryption_key = noise_squashing_compression_private_key.private_key_view();

            let mut rng = rand::rng();

            // How many uints of NUM_BLOCKS we have to push in the list to ensure it
            // internally has more than one packed GLWE
            let max_nb_messages: usize =
                1 + 2 * noise_squashing_compression_parameters.lwe_per_glwe.0 / NUM_BLOCKS;

            let message_modulus: u128 = cks.parameters().message_modulus().0 as u128;

            for _ in 0..NB_TESTS {
                // Unsigned
                let modulus = message_modulus.pow(NUM_BLOCKS as u32);
                for _ in 0..NB_OPERATOR_TESTS {
                    let nb_messages = rng.gen_range(1..=max_nb_messages as u64);
                    let messages = (0..nb_messages)
                        .map(|_| rng.gen::<u128>() % modulus)
                        .collect::<Vec<_>>();

                    let d_cts = messages
                        .iter()
                        .map(|message| {
                            let ct = radix_cks.encrypt(*message);
                            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams)
                        })
                        .collect_vec();

                    let mut builder = CudaCompressedSquashedNoiseCiphertextList::builder();

                    for d_ct in d_cts {
                        let d_and_ct = sks.bitand(&d_ct, &d_ct, &streams);
                        let d_and_ns_ct = cuda_noise_squashing_key
                            .squash_radix_ciphertext_noise(&sks, &d_and_ct.ciphertext, &streams)
                            .unwrap();
                        builder.push(d_and_ns_ct, &streams);
                    }

                    let cuda_compressed =
                        builder.build(&cuda_noise_squashing_compression_key, &streams);

                    for (i, message) in messages.iter().enumerate() {
                        let d_decompressed_ns_ct: CudaSquashedNoiseRadixCiphertext =
                            cuda_compressed.get(i, &streams).unwrap().unwrap();
                        let decompressed_ns_ct =
                            d_decompressed_ns_ct.to_squashed_noise_radix_ciphertext(&streams);
                        let decrypted: u128 =
                            decryption_key.decrypt_radix(&decompressed_ns_ct).unwrap();
                        assert_eq!(decrypted, *message);
                    }
                }

                // Signed
                let modulus = message_modulus.pow((NUM_BLOCKS - 1) as u32) as i128;
                for _ in 0..NB_OPERATOR_TESTS {
                    let nb_messages = rng.gen_range(1..=max_nb_messages as u64);
                    let messages = (0..nb_messages)
                        .map(|_| rng.gen::<i128>() % modulus)
                        .collect::<Vec<_>>();

                    let d_cts = messages
                        .iter()
                        .map(|message| {
                            let ct = radix_cks.encrypt_signed(*message);
                            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct, &streams)
                        })
                        .collect_vec();

                    let mut builder = CudaCompressedSquashedNoiseCiphertextList::builder();

                    for d_ct in d_cts {
                        let d_and_ct = sks.bitand(&d_ct, &d_ct, &streams);
                        let d_and_ns_ct = cuda_noise_squashing_key
                            .squash_signed_radix_ciphertext_noise(&sks, &d_and_ct, &streams)
                            .unwrap();
                        builder.push(d_and_ns_ct, &streams);
                    }

                    let cuda_compressed =
                        builder.build(&cuda_noise_squashing_compression_key, &streams);

                    for (i, message) in messages.iter().enumerate() {
                        let d_decompressed_ns_ct: CudaSquashedNoiseSignedRadixCiphertext =
                            cuda_compressed.get(i, &streams).unwrap().unwrap();
                        let decompressed_ns_ct = d_decompressed_ns_ct
                            .to_squashed_noise_signed_radix_ciphertext(&streams);
                        let decrypted: i128 = decryption_key
                            .decrypt_signed_radix(&decompressed_ns_ct)
                            .unwrap();
                        assert_eq!(decrypted, *message);
                    }
                }

                // Boolean
                for _ in 0..NB_OPERATOR_TESTS {
                    let nb_messages = rng.gen_range(1..=max_nb_messages as u64);
                    let messages = (0..nb_messages)
                        .map(|_| rng.gen::<i64>() % 2 != 0)
                        .collect::<Vec<_>>();

                    let d_cts = messages
                        .iter()
                        .map(|message| {
                            let ct = radix_cks.encrypt_bool(*message);
                            CudaBooleanBlock::from_boolean_block(&ct, &streams)
                        })
                        .collect_vec();

                    let mut builder = CudaCompressedSquashedNoiseCiphertextList::builder();

                    for d_boolean_ct in d_cts {
                        let d_ct = d_boolean_ct.0;
                        let d_and_ct = sks.bitand(&d_ct, &d_ct, &streams);
                        let d_and_boolean_ct =
                            CudaBooleanBlock::from_cuda_radix_ciphertext(d_and_ct.ciphertext);
                        let d_and_boolean_ns_ct = cuda_noise_squashing_key
                            .squash_boolean_block_noise(&sks, &d_and_boolean_ct, &streams)
                            .unwrap();
                        builder.push(d_and_boolean_ns_ct, &streams);
                    }

                    let cuda_compressed =
                        builder.build(&cuda_noise_squashing_compression_key, &streams);

                    for (i, message) in messages.iter().enumerate() {
                        let d_decompressed_ns_ct: CudaSquashedNoiseBooleanBlock =
                            cuda_compressed.get(i, &streams).unwrap().unwrap();
                        let decompressed_ns_ct =
                            d_decompressed_ns_ct.to_squashed_noise_boolean_block(&streams);
                        let decrypted = decryption_key.decrypt_bool(&decompressed_ns_ct).unwrap();
                        assert_eq!(decrypted, *message);
                    }
                }

                // Hybrid
                enum MessageType {
                    Unsigned(u128),
                    Signed(i128),
                    Boolean(bool),
                }
                for _ in 0..NB_OPERATOR_TESTS {
                    let mut builder = CudaCompressedSquashedNoiseCiphertextList::builder();

                    let nb_messages = rng.gen_range(1..=max_nb_messages as u64);
                    let mut messages = vec![];
                    for _ in 0..nb_messages {
                        let case_selector = rng.gen_range(0..3);
                        match case_selector {
                            0 => {
                                // Unsigned
                                let modulus = message_modulus.pow(NUM_BLOCKS as u32);
                                let message = rng.gen::<u128>() % modulus;
                                let ct = radix_cks.encrypt(message);
                                let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                                    &ct, &streams,
                                );
                                let d_and_ct = sks.bitand(&d_ct, &d_ct, &streams);
                                let d_and_ns_ct = cuda_noise_squashing_key
                                    .squash_radix_ciphertext_noise(
                                        &sks,
                                        &d_and_ct.ciphertext,
                                        &streams,
                                    )
                                    .unwrap();
                                builder.push(d_and_ns_ct, &streams);
                                messages.push(MessageType::Unsigned(message));
                            }
                            1 => {
                                // Signed
                                let modulus = message_modulus.pow((NUM_BLOCKS - 1) as u32) as i128;
                                let message = rng.gen::<i128>() % modulus;
                                let ct = radix_cks.encrypt_signed(message);
                                let d_ct = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(
                                    &ct, &streams,
                                );
                                let d_and_ct = sks.bitand(&d_ct, &d_ct, &streams);
                                let d_and_ns_ct = cuda_noise_squashing_key
                                    .squash_signed_radix_ciphertext_noise(&sks, &d_and_ct, &streams)
                                    .unwrap();
                                builder.push(d_and_ns_ct, &streams);
                                messages.push(MessageType::Signed(message));
                            }
                            _ => {
                                // Boolean
                                let message = rng.gen::<i64>() % 2 != 0;
                                let ct = radix_cks.encrypt_bool(message);
                                let d_boolean_ct =
                                    CudaBooleanBlock::from_boolean_block(&ct, &streams);
                                let d_ct = d_boolean_ct.0;
                                let d_and_ct = sks.bitand(&d_ct, &d_ct, &streams);
                                let d_and_boolean_ct = CudaBooleanBlock::from_cuda_radix_ciphertext(
                                    d_and_ct.ciphertext,
                                );
                                let d_and_ns_ct = cuda_noise_squashing_key
                                    .squash_boolean_block_noise(&sks, &d_and_boolean_ct, &streams)
                                    .unwrap();
                                builder.push(d_and_ns_ct, &streams);
                                messages.push(MessageType::Boolean(message));
                            }
                        }
                    }

                    let cuda_compressed =
                        builder.build(&cuda_noise_squashing_compression_key, &streams);

                    for (i, val) in messages.iter().enumerate() {
                        match val {
                            MessageType::Unsigned(message) => {
                                let d_decompressed_ns_ct: CudaSquashedNoiseRadixCiphertext =
                                    cuda_compressed.get(i, &streams).unwrap().unwrap();
                                let decompressed_ns_ct = d_decompressed_ns_ct
                                    .to_squashed_noise_radix_ciphertext(&streams);
                                let decrypted: u128 =
                                    decryption_key.decrypt_radix(&decompressed_ns_ct).unwrap();
                                assert_eq!(decrypted, *message);
                            }
                            MessageType::Signed(message) => {
                                let d_decompressed_ns_ct: CudaSquashedNoiseSignedRadixCiphertext =
                                    cuda_compressed.get(i, &streams).unwrap().unwrap();
                                let decompressed_ns_ct = d_decompressed_ns_ct
                                    .to_squashed_noise_signed_radix_ciphertext(&streams);
                                let decrypted: i128 = decryption_key
                                    .decrypt_signed_radix(&decompressed_ns_ct)
                                    .unwrap();
                                assert_eq!(decrypted, *message);
                            }
                            MessageType::Boolean(message) => {
                                let d_decompressed_ns_ct: CudaSquashedNoiseBooleanBlock =
                                    cuda_compressed.get(i, &streams).unwrap().unwrap();
                                let decompressed_ns_ct =
                                    d_decompressed_ns_ct.to_squashed_noise_boolean_block(&streams);
                                let decrypted: bool =
                                    decryption_key.decrypt_bool(&decompressed_ns_ct).unwrap();
                                assert_eq!(decrypted, *message);
                            }
                        }
                    }
                }
            }
        }
    }
}
