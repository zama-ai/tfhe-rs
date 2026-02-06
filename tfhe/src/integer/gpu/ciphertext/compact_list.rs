use crate::core_crypto::commons::traits::contiguous_entity_container::ContiguousEntityContainer;
use crate::core_crypto::entities::LweCompactCiphertextList;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{
    lwe_compact_ciphertext_list_size, CiphertextModulus, LweCiphertext, LweCiphertextCount,
};
use crate::integer::ciphertext::{CompactCiphertextListExpander, DataKind};
use crate::integer::gpu::ciphertext::compressed_ciphertext_list::CudaExpandable;
use crate::integer::gpu::ciphertext::info::{CudaBlockInfo, CudaRadixCiphertextInfo};
use crate::integer::gpu::ciphertext::{CudaRadixCiphertext, CudaVec, KsType, LweDimension};
use crate::integer::gpu::key_switching_key::CudaKeySwitchingKey;
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaDynamicKeyswitchingKey};
use crate::integer::gpu::{cuda_backend_expand, PBSType};
use crate::shortint::ciphertext::CompactCiphertextList;
use crate::shortint::parameters::{
    CompactCiphertextListExpansionKind, Degree, LweBskGroupingFactor, NoiseLevel,
};
use crate::shortint::{AtomicPatternKind, CarryModulus, Ciphertext, MessageModulus};
use crate::GpuIndex;
use itertools::Itertools;
use serde::Deserializer;
use tfhe_cuda_backend::cuda_bind::cuda_memcpy_async_to_gpu;
#[derive(Clone)]
pub struct CudaCompactCiphertextListInfo {
    pub info: CudaBlockInfo,
    pub data_kind: DataKind,
}

#[derive(Clone)]
pub struct CudaCompactCiphertextListExpander {
    pub(crate) expanded_blocks: CudaLweCiphertextList<u64>,
    pub(crate) blocks_info: Vec<CudaCompactCiphertextListInfo>,
}

impl CudaCompactCiphertextListExpander {
    pub fn new(
        expanded_blocks: CudaLweCiphertextList<u64>,
        info: Vec<CudaCompactCiphertextListInfo>,
    ) -> Self {
        Self {
            expanded_blocks,
            blocks_info: info,
        }
    }

    pub fn len(&self) -> usize {
        self.blocks_info.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get_kind_of(&self, index: usize) -> Option<DataKind> {
        let blocks = self.blocks_info.get(index)?;
        Some(blocks.data_kind)
    }

    pub fn message_modulus(&self, index: usize) -> Option<MessageModulus> {
        let blocks = self.blocks_info.get(index)?;
        Some(blocks.info.message_modulus)
    }

    pub fn carry_modulus(&self, index: usize) -> Option<CarryModulus> {
        let blocks = self.blocks_info.get(index)?;
        Some(blocks.info.carry_modulus)
    }

    fn blocks_of(
        &self,
        index: usize,
        streams: &CudaStreams,
    ) -> Option<(CudaRadixCiphertext, DataKind)> {
        let preceding_infos = self.blocks_info.get(..index)?;
        let current_info = self.blocks_info.get(index)?;
        let message_modulus = self.blocks_info.get(index)?.info.message_modulus;

        let start_block_index: usize = preceding_infos
            .iter()
            .clone()
            .map(|ct_info| ct_info.data_kind.num_blocks(message_modulus))
            .sum();

        let block_count = current_info.data_kind.num_blocks(message_modulus);
        let end_block_index = start_block_index + block_count;

        if block_count == 0 {
            return None;
        }

        let blocks = CudaRadixCiphertext {
            d_blocks: self
                .expanded_blocks
                .get(streams, start_block_index..end_block_index),
            info: CudaRadixCiphertextInfo {
                blocks: vec![
                    CudaBlockInfo {
                        degree: match current_info.data_kind {
                            DataKind::Boolean => Degree(1),
                            _ => current_info.info.degree,
                        },
                        message_modulus: current_info.info.message_modulus,
                        carry_modulus: current_info.info.carry_modulus,
                        atomic_pattern: current_info.info.atomic_pattern,
                        noise_level: current_info.info.noise_level,
                    };
                    block_count
                ],
            },
        };
        Some((blocks, current_info.data_kind))
    }
    fn get_blocks_of_size_on_gpu(&self, index: usize, streams: &CudaStreams) -> Option<u64> {
        let preceding_infos = self.blocks_info.get(..index)?;
        let current_info = self.blocks_info.get(index)?;
        let message_modulus = self.blocks_info.get(index)?.info.message_modulus;

        let start_block_index: usize = preceding_infos
            .iter()
            .clone()
            .map(|ct_info| ct_info.data_kind.num_blocks(message_modulus))
            .sum();

        let block_count = current_info.data_kind.num_blocks(message_modulus);
        let end_block_index = start_block_index + block_count;

        Some(
            self.expanded_blocks
                .get_decompression_size_on_gpu(streams, start_block_index..end_block_index),
        )
    }

    pub fn get<T>(&self, index: usize, streams: &CudaStreams) -> crate::Result<Option<T>>
    where
        T: CudaExpandable,
    {
        self.blocks_of(index, streams)
            .map(|(blocks, kind)| T::from_expanded_blocks(blocks, kind))
            .transpose()
    }

    pub fn get_decompression_size_on_gpu(
        &self,
        index: usize,
        streams: &CudaStreams,
    ) -> Option<u64> {
        self.get_blocks_of_size_on_gpu(index, streams)
    }

    pub fn to_compact_ciphertext_list_expander(
        &self,
        streams: &CudaStreams,
    ) -> CompactCiphertextListExpander {
        let lwe_ciphertext_list = self.expanded_blocks.to_lwe_ciphertext_list(streams);
        let ciphertext_modulus = self.expanded_blocks.ciphertext_modulus();

        let expanded_blocks = lwe_ciphertext_list
            .iter()
            .zip(self.blocks_info.clone())
            .map(|(ct, info)| {
                let lwe = LweCiphertext::from_container(ct.as_ref().to_vec(), ciphertext_modulus);
                Ciphertext::new(
                    lwe,
                    info.info.degree,
                    info.info.noise_level,
                    info.info.message_modulus,
                    info.info.carry_modulus,
                    info.info.atomic_pattern,
                )
            })
            .collect_vec();
        let info = self
            .blocks_info
            .iter()
            .map(|ct_info| ct_info.data_kind)
            .collect_vec();

        CompactCiphertextListExpander::new(expanded_blocks, info)
    }

    pub fn duplicate(&self) -> Self {
        Self {
            expanded_blocks: self.expanded_blocks.clone(),
            blocks_info: self.blocks_info.iter().cloned().collect_vec(),
        }
    }
}

// FlattenedVecCudaCompactCiphertextList flattens a Vec<CompactCiphertextList> into a single
// contiguous device array for improved GPU memory access. To avoid complex calculations of
// lwe_dimension and lwe_ciphertext_count at runtime, these and other attributes are pre-computed
// and stored directly in the CudaVec structure.
pub struct CudaFlattenedVecCompactCiphertextList {
    d_flattened_vec: CudaVec<u64>,
    num_lwe_per_compact_list: Vec<u32>,
    pub(crate) data_info: Vec<DataKind>,
    is_boolean: Vec<bool>,
    pub(crate) lwe_dimension: LweDimension,
    pub(crate) lwe_ciphertext_count: LweCiphertextCount,
    pub(crate) degree: Degree,
    pub(crate) message_modulus: MessageModulus,
    pub(crate) carry_modulus: CarryModulus,
    pub(crate) expansion_kind: CompactCiphertextListExpansionKind,
    pub(crate) ciphertext_modulus: CiphertextModulus<u64>,
}

impl CudaFlattenedVecCompactCiphertextList {
    pub(crate) fn from_vec_shortint_compact_ciphertext_list(
        vec_compact_list: Vec<crate::shortint::ciphertext::CompactCiphertextList>,
        data_info: Vec<DataKind>,
        streams: &CudaStreams,
    ) -> Self {
        let first = vec_compact_list.first().unwrap();

        // We assume all ciphertexts will have the same lwe dimension
        let lwe_dimension = first.ct_list.lwe_size().to_lwe_dimension();
        let ciphertext_modulus = first.ct_list.ciphertext_modulus();

        let degree = first.degree;
        let message_modulus = first.message_modulus;
        let carry_modulus = first.carry_modulus;
        let expansion_kind = first.expansion_kind;

        // Compute total number of lwe ciphertexts we will be handling
        // Instead of creating a vector of LweCiphertextCount and converting it to Vec<u32> later
        // for expand(), we compute it directly in the Vec<u32> format that will be needed
        let num_lwe_per_compact_list = vec_compact_list
            .iter()
            .map(|x| x.ct_list.lwe_ciphertext_count().0 as u32)
            .collect_vec();

        let total_num_blocks =
            LweCiphertextCount(num_lwe_per_compact_list.iter().sum::<u32>() as usize);
        let total_size = num_lwe_per_compact_list
            .iter()
            .map(|lwe_ciphertext_count| {
                lwe_compact_ciphertext_list_size(
                    lwe_dimension,
                    LweCiphertextCount(*lwe_ciphertext_count as usize),
                )
            })
            .sum();

        let total_blocks: usize = data_info
            .iter()
            .map(|kind| kind.num_blocks(message_modulus))
            .sum();

        // Calculate the actual output size after unpacking
        let log_message_modulus = message_modulus.0.ilog2() as usize;
        let output_size = log_message_modulus * total_blocks.div_ceil(2);

        // `is_boolean` is a vector indicating whether each LWE corresponds to a boolean value or is
        // part of something else
        let mut is_boolean = data_info
            .iter()
            .flat_map(|data_kind| {
                let repetitions = match data_kind {
                    DataKind::Boolean => 1,
                    DataKind::Signed(x) => x.get(),
                    DataKind::Unsigned(x) => x.get(),
                    DataKind::String { .. } => panic!("DataKind not supported on GPUs"),
                };
                std::iter::repeat_n(matches!(data_kind, DataKind::Boolean), repetitions)
            })
            .collect_vec();
        // Usually we pack `log(message_modulus)` values per LWE; however, when the LWE comes from a
        // boolean, only one message will be found. To avoid reading memory garbage in the
        // backend, we need to pad to output_size when the block count is odd
        is_boolean.resize(output_size, false);

        // d_vec is an array with the concatenated compact lists
        let d_flattened_d_vec = unsafe {
            let mut d_flattened_d_vec = CudaVec::new_async(total_size, streams, 0);
            let mut offset: usize = 0;
            for compact_list in vec_compact_list {
                let container = compact_list.ct_list.clone().into_container();
                let expected_length = lwe_compact_ciphertext_list_size(
                    lwe_dimension,
                    compact_list.ct_list.lwe_ciphertext_count(),
                );
                assert_eq!(container.len(), expected_length);

                let dest_ptr = d_flattened_d_vec
                    .as_mut_c_ptr(0)
                    .add(offset * std::mem::size_of::<u64>());
                cuda_memcpy_async_to_gpu(
                    dest_ptr,
                    container.as_ptr().cast(),
                    (expected_length * std::mem::size_of::<u64>()) as u64,
                    streams.ptr[0],
                    streams.gpu_indexes[0].get(),
                );

                offset += expected_length;
            }
            d_flattened_d_vec
        };
        streams.synchronize();

        Self {
            d_flattened_vec: d_flattened_d_vec,
            lwe_dimension,
            lwe_ciphertext_count: total_num_blocks,
            degree,
            message_modulus,
            carry_modulus,
            expansion_kind,
            ciphertext_modulus,
            num_lwe_per_compact_list,
            data_info,
            is_boolean,
        }
    }

    pub(crate) fn from_integer_compact_ciphertext_list(
        compact_list: &crate::integer::ciphertext::CompactCiphertextList,
        streams: &CudaStreams,
    ) -> Self {
        let single_element_vec = vec![compact_list.ct_list.clone()];
        Self::from_vec_shortint_compact_ciphertext_list(
            single_element_vec,
            compact_list.info.clone(),
            streams,
        )
    }

    pub fn to_vec_shortint_compact_ciphertext_list(
        &self,
        streams: &CudaStreams,
    ) -> crate::Result<Vec<crate::shortint::ciphertext::CompactCiphertextList>> {
        // First we get the h_vec with all data copied from GPU
        let mut h_vec = vec![0u64; self.d_flattened_vec.len()];
        unsafe {
            self.d_flattened_vec
                .copy_to_cpu_async(h_vec.as_mut_slice(), streams, 0);
        }

        // Now we'll split it into individual lists
        let mut result = Vec::new();
        let mut offset = 0;

        // For each size in num_lwe_per_compact_list, compute the length of that slice
        // and extract it from h_vec
        for num_lwe in self.num_lwe_per_compact_list.iter() {
            let num_lwe = *num_lwe as usize;
            let length =
                lwe_compact_ciphertext_list_size(self.lwe_dimension, LweCiphertextCount(num_lwe));

            // Extract the slice from h_vec starting at current_offset with computed length
            let slice = &h_vec[offset..offset + length];

            // Create a new Vec from this slice
            let list = slice.to_vec();

            let lwe = LweCompactCiphertextList::from_container(
                list,
                self.lwe_dimension.to_lwe_size(),
                LweCiphertextCount(num_lwe),
                self.ciphertext_modulus,
            );
            let ct = CompactCiphertextList {
                ct_list: lwe,
                degree: self.degree,
                message_modulus: self.message_modulus,
                carry_modulus: self.carry_modulus,
                expansion_kind: self.expansion_kind,
            };
            result.push(ct);

            // Update offset for next iteration
            offset += length;
        }

        Ok(result)
    }

    /// Returns the first compact list in the vector as an integer compact ciphertext list
    pub fn to_integer_compact_ciphertext_list(
        &self,
        streams: &CudaStreams,
    ) -> crate::Result<crate::integer::ciphertext::CompactCiphertextList> {
        let shortint_compact_list = self.to_vec_shortint_compact_ciphertext_list(streams)?;
        Ok(crate::integer::ciphertext::CompactCiphertextList {
            ct_list: shortint_compact_list.first().unwrap().clone(),
            info: self.data_info.clone(),
        })
    }

    pub fn expand(
        &self,
        key: &CudaKeySwitchingKey,
        zk_type: crate::integer::gpu::ZKType,
        streams: &CudaStreams,
    ) -> crate::Result<CudaCompactCiphertextListExpander> {
        assert!(
            !self
                .data_info
                .iter()
                .any(|x| matches!(x, DataKind::String { .. })),
            "Strings are not supported on GPUs"
        );

        let lwe_dimension = self.lwe_dimension;
        let ciphertext_modulus = self.ciphertext_modulus;

        let input_lwe_ciphertext_count = self.lwe_ciphertext_count;
        let output_lwe_ciphertext_count = LweCiphertextCount(2 * input_lwe_ciphertext_count.0);

        let d_expanded_blocks = unsafe {
            let mut d_output = CudaLweCiphertextList::new(
                lwe_dimension,
                output_lwe_ciphertext_count,
                ciphertext_modulus,
                streams,
            );

            let d_input = &self.d_flattened_vec;
            let casting_key = key.key_switching_key_material;
            let sks = key.dest_server_key;

            let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) =
                &key.dest_server_key.key_switching_key
            else {
                panic!("Only the standard atomic pattern is supported on GPU")
            };

            let casting_key_type: KsType = casting_key.destination_key.into();

            match &sks.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_expand(
                        streams,
                        &mut d_output,
                        d_input,
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        &casting_key.lwe_keyswitch_key.d_vec,
                        sks.message_modulus,
                        sks.carry_modulus,
                        d_bsk.glwe_dimension(),
                        d_bsk.polynomial_size(),
                        d_bsk.input_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        casting_key
                            .lwe_keyswitch_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        casting_key
                            .lwe_keyswitch_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        casting_key.lwe_keyswitch_key.decomposition_level_count(),
                        casting_key.lwe_keyswitch_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        PBSType::Classical,
                        casting_key_type,
                        LweBskGroupingFactor(0),
                        self.num_lwe_per_compact_list.as_slice(),
                        self.is_boolean.as_slice(),
                        self.is_boolean.len() as u32,
                        zk_type,
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_expand(
                        streams,
                        &mut d_output,
                        d_input,
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        &casting_key.lwe_keyswitch_key.d_vec,
                        sks.message_modulus,
                        sks.carry_modulus,
                        d_multibit_bsk.glwe_dimension(),
                        d_multibit_bsk.polynomial_size(),
                        d_multibit_bsk.input_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        casting_key
                            .lwe_keyswitch_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        casting_key
                            .lwe_keyswitch_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        casting_key.lwe_keyswitch_key.decomposition_level_count(),
                        casting_key.lwe_keyswitch_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        PBSType::MultiBit,
                        casting_key_type,
                        d_multibit_bsk.grouping_factor,
                        self.num_lwe_per_compact_list.as_slice(),
                        self.is_boolean.as_slice(),
                        self.is_boolean.len() as u32,
                        zk_type,
                        None,
                    );
                }
            }
            d_output
        };

        let message_modulus = self.message_modulus;
        let carry_modulus = self.carry_modulus;
        let blocks_info = self
            .data_info
            .iter()
            .map(|data_kind| CudaCompactCiphertextListInfo {
                info: CudaBlockInfo {
                    degree: match data_kind {
                        DataKind::Boolean => Degree(1),
                        _ => Degree(message_modulus.0 - 1),
                    },
                    message_modulus,
                    carry_modulus,
                    atomic_pattern: AtomicPatternKind::Standard(key.dest_server_key.pbs_order),
                    noise_level: NoiseLevel::NOMINAL,
                },
                data_kind: *data_kind,
            })
            .collect_vec();

        Ok(CudaCompactCiphertextListExpander {
            expanded_blocks: d_expanded_blocks,
            blocks_info,
        })
    }

    pub fn duplicate(&self, streams: &CudaStreams) -> Self {
        Self {
            d_flattened_vec: self.d_flattened_vec.duplicate(streams),
            lwe_dimension: self.lwe_dimension,
            lwe_ciphertext_count: self.lwe_ciphertext_count,
            degree: self.degree,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            expansion_kind: self.expansion_kind,
            ciphertext_modulus: self.ciphertext_modulus,
            num_lwe_per_compact_list: self.num_lwe_per_compact_list.clone(),
            data_info: self.data_info.clone(),
            is_boolean: self.is_boolean.clone(),
        }
    }
    pub fn gpu_indexes(&self) -> &[GpuIndex] {
        self.d_flattened_vec.gpu_indexes.as_slice()
    }

    pub fn get_kind_of(&self, index: usize) -> Option<DataKind> {
        self.data_info.get(index).copied()
    }

    pub fn is_packed(&self) -> bool {
        self.degree.get() > self.message_modulus.corresponding_max_degree().get()
    }
}

impl<'de> serde::Deserialize<'de> for CudaFlattenedVecCompactCiphertextList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize the compact list on CPU as an integer CompactCiphertextList
        let cpu_list =
            crate::integer::ciphertext::CompactCiphertextList::deserialize(deserializer)?;
        let streams = CudaStreams::new_multi_gpu();

        Ok(Self::from_integer_compact_ciphertext_list(
            &cpu_list, &streams,
        ))
    }
}
