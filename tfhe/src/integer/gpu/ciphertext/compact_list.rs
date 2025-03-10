use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_compact_ciphertext_list::CudaLweCompactCiphertextList;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{
    lwe_compact_ciphertext_list_size, verify_lwe_compact_ciphertext_list, CiphertextModulus,
    LweBskGroupingFactor, LweCiphertextCount, LweDimension,
};
use crate::integer::ciphertext::DataKind;
use crate::integer::gpu::ciphertext::compressed_ciphertext_list::CudaExpandable;
use crate::integer::gpu::ciphertext::info::{CudaBlockInfo, CudaRadixCiphertextInfo};
use crate::integer::gpu::ciphertext::CudaRadixCiphertext;
use crate::integer::gpu::key_switching_key::CudaKeySwitchingKey;
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{CudaServerKey, PBSType};
use crate::integer::{CompactPublicKey, ProvenCompactCiphertextList};
use crate::shortint::ciphertext::CompactCiphertextList;
use crate::shortint::parameters::{CompactCiphertextListExpansionKind, Degree, NoiseLevel};
use crate::shortint::{CarryModulus, MessageModulus, PBSOrder};
use crate::zk::gpu::expand_async;
use crate::zk::CompactPkeCrs;
use itertools::Itertools;
use rayon::iter::ParallelIterator;
use rayon::prelude::IntoParallelRefIterator;
use tfhe_cuda_backend::cuda_bind::cuda_memcpy_async_gpu_to_gpu;

pub struct CudaCompactCiphertextList {
    pub d_ct_list: CudaLweCompactCiphertextList<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub expansion_kind: CompactCiphertextListExpansionKind,
}
pub struct CudaProvenCompactCiphertextList {
    pub(crate) h_proved_lists: ProvenCompactCiphertextList,
    pub(crate) d_compact_lists: Vec<CudaCompactCiphertextList>,
}

pub struct CudaCompactCiphertextListInfo {
    pub info: CudaBlockInfo,
    pub data_kind: DataKind,
}

pub struct CudaCompactCiphertextListExpander {
    expanded_blocks: CudaLweCiphertextList<u64>,
    blocks_info: Vec<CudaCompactCiphertextListInfo>,
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

    fn blocks_of(
        &self,
        index: usize,
        streams: &CudaStreams,
    ) -> Option<(CudaRadixCiphertext, DataKind)> {
        let preceding_infos = self.blocks_info.get(..index)?;
        let current_info = self.blocks_info.get(index).clone()?;
        let message_modulus = self.blocks_info.get(index).unwrap().info.message_modulus;

        let start_block_index: usize = preceding_infos
            .iter()
            .clone()
            .map(|ct_info| ct_info.data_kind.num_blocks(message_modulus))
            .sum();

        let end_block_index =
            start_block_index + current_info.data_kind.num_blocks(message_modulus);

        println!(
            "gpu start_block_index: {}, end_block_index: {}",
            start_block_index, end_block_index
        );

        let blocks = CudaRadixCiphertext {
            d_blocks: self
                .expanded_blocks
                .get(streams, start_block_index..end_block_index),
            info: CudaRadixCiphertextInfo {
                blocks: vec![current_info.info; end_block_index - start_block_index],
            },
        };
        println!("blocks len: {}", blocks.d_blocks.lwe_ciphertext_count().0);
        Some((blocks, current_info.data_kind))
    }

    pub fn get<T>(&self, index: usize, streams: &CudaStreams) -> crate::Result<Option<T>>
    where
        T: CudaExpandable,
    {
        self.blocks_of(index, streams)
            .map(|(blocks, kind)| {
                let x = blocks
                    .d_blocks
                    .to_lwe_ciphertext_list(&streams)
                    .into_container();
                let y = x.chunks(8).next().unwrap();
                println!(
                    "{} blocks: {:?}",
                    blocks.d_blocks.lwe_ciphertext_count().0,
                    x
                );
                T::from_expanded_blocks(blocks, kind)
            })
            .transpose()
    }
}

impl CudaCompactCiphertextList {
    pub fn from_compact_ciphertext_list(
        h_ct: &CompactCiphertextList,
        streams: &CudaStreams,
    ) -> Self {
        let result = unsafe { Self::from_compact_ciphertext_list_async(h_ct, streams) };
        streams.synchronize();
        result
    }

    pub unsafe fn from_compact_ciphertext_list_async(
        h_ct: &CompactCiphertextList,
        streams: &CudaStreams,
    ) -> Self {
        let d_ct_list = CudaLweCompactCiphertextList::from_lwe_compact_ciphertext_list_async(
            &h_ct.ct_list,
            &streams,
        );
        Self {
            d_ct_list,
            degree: h_ct.degree,
            message_modulus: h_ct.message_modulus,
            carry_modulus: h_ct.carry_modulus,
            expansion_kind: h_ct.expansion_kind,
        }
    }

    pub fn to_compact_ciphertext_list(&self, streams: &CudaStreams) -> CompactCiphertextList {
        let h_ct_list = self.d_ct_list.to_lwe_compact_ciphertext_list(&streams);
        CompactCiphertextList {
            ct_list: h_ct_list,
            degree: self.degree,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            expansion_kind: self.expansion_kind,
        }
    }
}

impl CudaProvenCompactCiphertextList {
    unsafe fn flatten_async(
        slice_ciphertext_list: &[CudaCompactCiphertextList],
        streams: &CudaStreams,
    ) -> CudaLweCiphertextList<u64> {
        let first = slice_ciphertext_list.first().unwrap();

        // We assume all ciphertexts will have the same lwe dimension
        let lwe_dimension = first.d_ct_list.0.lwe_dimension;
        let ciphertext_modulus = first.d_ct_list.0.ciphertext_modulus;

        // Compute total number of lwe ciphertexts we will be handling
        let total_num_blocks = LweCiphertextCount(
            slice_ciphertext_list
                .iter()
                .map(|x| x.d_ct_list.0.lwe_ciphertext_count.0)
                .sum(),
        );
        let total_size = slice_ciphertext_list
            .iter()
            .map(|x| {
                lwe_compact_ciphertext_list_size(lwe_dimension, x.d_ct_list.0.lwe_ciphertext_count)
            })
            .sum();

        println!("lwe_dimension: {:?}", lwe_dimension);
        println!("lwe_ciphertext_count: {:?}", total_num_blocks);
        println!("total_num_blocks: {:?}", total_num_blocks);
        let mut d_vec = CudaVec::new_async(total_size, streams, 0);
        println!("total_size: {:?}", total_size);
        let mut offset: usize = 0;
        for ciphertext_list in slice_ciphertext_list {
            let length = lwe_compact_ciphertext_list_size(
                lwe_dimension,
                ciphertext_list.d_ct_list.0.lwe_ciphertext_count,
            );
            let dest_ptr = d_vec
                .as_mut_c_ptr(0)
                .add(offset * std::mem::size_of::<u64>());
            println!("size: {length} / {}", total_size);
            cuda_memcpy_async_gpu_to_gpu(
                dest_ptr,
                ciphertext_list.d_ct_list.0.d_vec.as_c_ptr(0),
                (length * std::mem::size_of::<u64>()) as u64,
                streams.ptr[0],
                streams.gpu_indexes[0].get(),
            );

            println!("ct+: {}", ciphertext_list.d_ct_list.0.d_vec.len);
            println!("offset+: {}", ciphertext_list.d_ct_list.0.d_vec.len);
            offset += ciphertext_list.d_ct_list.0.d_vec.len;
        }

        CudaLweCiphertextList::from_cuda_vec(d_vec, total_num_blocks, ciphertext_modulus)
    }

    pub fn verify_and_expand(
        &self,
        crs: &CompactPkeCrs,
        public_key: &CompactPublicKey,
        metadata: &[u8],
        key: &CudaKeySwitchingKey,
        streams: &CudaStreams,
    ) -> crate::Result<CudaCompactCiphertextListExpander> {
        println!("gpu verify_and_expand");
        let not_all_valid =
            self.h_proved_lists
                .ct_list
                .proved_lists
                .par_iter()
                .any(|(ct_list, proof)| {
                    verify_lwe_compact_ciphertext_list(
                        &ct_list.ct_list,
                        &public_key.key.key,
                        proof,
                        crs,
                        metadata,
                    )
                    .is_invalid()
                });

        if not_all_valid {
            return Err(crate::ErrorKind::InvalidZkProof.into());
        }

        // We can call the function as we have verified the proofs
        self.expand_without_verification(key, streams)
    }

    pub fn expand_without_verification(
        &self,
        key: &CudaKeySwitchingKey,
        streams: &CudaStreams,
    ) -> crate::Result<CudaCompactCiphertextListExpander> {
        let expanded_blocks = unsafe { self.expand_without_verification_async(key, streams)? };
        streams.synchronize();

        let blocks_info = self
            .h_proved_lists
            .ct_list
            .proved_lists
            .iter()
            .zip(self.h_proved_lists.info.iter())
            .map(
                |((ct_list, proof), data_kind)| CudaCompactCiphertextListInfo {
                    info: CudaBlockInfo {
                        degree: ct_list.degree,
                        message_modulus: ct_list.message_modulus,
                        carry_modulus: ct_list.carry_modulus,
                        pbs_order: PBSOrder::KeyswitchBootstrap,
                        noise_level: NoiseLevel::NOMINAL,
                    },
                    data_kind: *data_kind,
                },
            )
            .collect_vec();

        Ok(CudaCompactCiphertextListExpander {
            expanded_blocks,
            blocks_info,
        })
    }

    pub unsafe fn expand_without_verification_async(
        &self,
        key: &CudaKeySwitchingKey,
        streams: &CudaStreams,
    ) -> crate::Result<CudaLweCiphertextList<u64>> {
        let lwe_dimension = self.lwe_dimension();
        let input_lwe_ciphertext_count = LweCiphertextCount(
            self.h_proved_lists
                .ct_list
                .proved_lists
                .iter()
                .map(|pair| pair.0.ct_list.lwe_ciphertext_count().0)
                .sum::<usize>(),
        );
        let output_lwe_ciphertext_count = LweCiphertextCount(2 * input_lwe_ciphertext_count.0);
        let ciphertext_modulus = self.ciphertext_modulus();

        let mut d_output = CudaLweCiphertextList::new(
            lwe_dimension,
            output_lwe_ciphertext_count,
            ciphertext_modulus,
            streams,
        );
        let d_input = &CudaProvenCompactCiphertextList::flatten_async(
            self.d_compact_lists.as_slice(),
            streams,
        );
        let ksk = &key.key_switching_key;
        let sks = key.dest_server_key;

        match &sks.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                expand_async(
                    streams,
                    &mut d_output.0.d_vec,
                    &d_input.0.d_vec,
                    &d_bsk.d_vec,
                    &ksk.d_vec,
                    sks.message_modulus,
                    sks.carry_modulus,
                    d_bsk.glwe_dimension(),
                    d_bsk.polynomial_size(),
                    d_bsk.input_lwe_dimension(),
                    ksk.decomposition_level_count(),
                    ksk.decomposition_base_log(),
                    d_bsk.decomp_level_count(),
                    d_bsk.decomp_base_log(),
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                    input_lwe_ciphertext_count,
                    d_bsk.input_lwe_dimension().0 as u32,
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                expand_async(
                    streams,
                    &mut d_output.0.d_vec,
                    &CudaProvenCompactCiphertextList::flatten_async(
                        self.d_compact_lists.as_slice(),
                        streams,
                    )
                    .0
                    .d_vec,
                    &d_multibit_bsk.d_vec,
                    &ksk.d_vec,
                    sks.message_modulus,
                    sks.carry_modulus,
                    d_multibit_bsk.glwe_dimension(),
                    d_multibit_bsk.polynomial_size(),
                    d_multibit_bsk.input_lwe_dimension(),
                    ksk.decomposition_level_count(),
                    ksk.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count(),
                    d_multibit_bsk.decomp_base_log(),
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                    input_lwe_ciphertext_count,
                    d_multibit_bsk.input_lwe_dimension().0 as u32,
                );
            }
        }

        Ok(d_output)
    }

    pub fn from_proven_compact_ciphertext_list(
        h_proved_lists: &ProvenCompactCiphertextList,
        streams: &CudaStreams,
    ) -> Self {
        let d_compact_lists: Vec<CudaCompactCiphertextList> = h_proved_lists
            .ct_list
            .proved_lists
            .par_iter()
            .map(|(ct_list, _proof)| {
                CudaCompactCiphertextList::from_compact_ciphertext_list(ct_list, streams)
            })
            .collect();

        CudaProvenCompactCiphertextList {
            h_proved_lists: h_proved_lists.clone(),
            d_compact_lists,
        }
    }

    pub fn lwe_dimension(&self) -> LweDimension {
        self.d_compact_lists
            .first()
            .unwrap()
            .d_ct_list
            .0
            .lwe_dimension
    }

    pub fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        self.d_compact_lists
            .first()
            .unwrap()
            .d_ct_list
            .0
            .lwe_ciphertext_count
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<u64> {
        self.d_compact_lists
            .first()
            .unwrap()
            .d_ct_list
            .0
            .ciphertext_modulus
    }
}
