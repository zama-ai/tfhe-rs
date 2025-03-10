use itertools::Itertools;
use rayon::prelude::IntoParallelRefIterator;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_compact_ciphertext_list::CudaLweCompactCiphertextList;
use crate::core_crypto::prelude::{verify_lwe_compact_ciphertext_list, CiphertextModulus, LweCiphertextCount, LweDimension};
use crate::shortint::parameters::{CompactCiphertextListExpansionKind, Degree, NoiseLevel};
use crate::shortint::{CarryModulus, MessageModulus, PBSOrder};
use crate::shortint::ciphertext::CompactCiphertextList;
use crate::zk::CompactPkeCrs;
use rayon::iter::ParallelIterator;
use crate::integer::{CompactPublicKey, ProvenCompactCiphertextList};
use crate::integer::ciphertext::DataKind;
use crate::integer::gpu::ciphertext::compressed_ciphertext_list::CudaExpandable;
use crate::integer::gpu::ciphertext::CudaRadixCiphertext;
use crate::integer::gpu::ciphertext::info::{CudaBlockInfo, CudaRadixCiphertextInfo};

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
    pub fn new(expanded_blocks: CudaLweCiphertextList<u64>, info: Vec<CudaCompactCiphertextListInfo>) -> Self {
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

        let end_block_index = start_block_index + current_info.data_kind.num_blocks(message_modulus) - 1;

        let blocks = CudaRadixCiphertext {
                    d_blocks: self.expanded_blocks.get(streams, start_block_index..end_block_index),
            info: CudaRadixCiphertextInfo{blocks : vec![current_info.info; end_block_index -
                start_block_index]},
                };
        Some((blocks, current_info.data_kind))
    }

    pub fn get<T>(
        &self,
        index: usize,
        streams: &CudaStreams,
    ) -> crate::Result<Option<T>>
    where
        T: CudaExpandable,
    {
        self.blocks_of(index, streams)
            .map(|(blocks, kind)| T::from_expanded_blocks(blocks, kind))
            .transpose()
    }
}

impl CudaCompactCiphertextList {
    pub fn from_compact_ciphertext_list(h_ct: &CompactCiphertextList, streams: &CudaStreams)
                                                     -> Self {
        let result = unsafe {
            Self::from_compact_ciphertext_list_async(h_ct, streams)
        };
        streams.synchronize();
        result
    }

    pub unsafe fn from_compact_ciphertext_list_async(h_ct: &CompactCiphertextList, streams: &CudaStreams)
                                                     -> Self {
        let d_ct_list = CudaLweCompactCiphertextList::from_lwe_compact_ciphertext_list_async(
            &h_ct.ct_list,
            &streams
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
        let h_ct_list = self.d_ct_list.to_lwe_compact_ciphertext_list(
            &streams
        );
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
    pub fn verify_and_expand(
        &self,
        crs: &CompactPkeCrs,
        public_key: &CompactPublicKey,
        metadata: &[u8],
        streams: &CudaStreams,
    ) -> crate::Result<CudaCompactCiphertextListExpander> {
        println!("gpu verify_and_expand");
        let not_all_valid = self.h_proved_lists.ct_list.proved_lists.par_iter().any(|(ct_list,
                                                                                      proof)| {

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
        self.expand_without_verification(streams)
    }

    pub fn expand_without_verification(
        &self,
        streams: &CudaStreams,
    ) -> crate::Result<CudaCompactCiphertextListExpander> {
        let expanded_blocks = unsafe {
        self.expand_without_verification_async(streams)?
        };
        streams.synchronize();

        let blocks_info = self.h_proved_lists.ct_list.proved_lists.iter().zip(self
            .h_proved_lists.info.iter()).map(|((ct_list,proof), data_kind)| {
            CudaCompactCiphertextListInfo {
                info: CudaBlockInfo {
            degree: ct_list.degree,
            message_modulus: ct_list.message_modulus,
            carry_modulus: ct_list.carry_modulus,
            pbs_order: PBSOrder::KeyswitchBootstrap,
            noise_level: NoiseLevel::NOMINAL,
            },
        data_kind: *data_kind,
        }}).collect_vec();

        Ok(CudaCompactCiphertextListExpander {expanded_blocks, blocks_info})
    }

    pub unsafe fn expand_without_verification_async(
        &self,
        streams: &CudaStreams,
    ) -> crate::Result<CudaLweCiphertextList<u64>> {
                let lwe_dimension = self.lwe_dimension();
                let lwe_ciphertext_count = self.lwe_ciphertext_count();
                let ciphertext_modulus = self.ciphertext_modulus();

                let mut d_output = CudaLweCiphertextList::new(lwe_dimension,lwe_ciphertext_count,
                 ciphertext_modulus, streams);
                let d_input = &self.d_compact_lists;

                // TODO: How do I get the bsk and ksk here?

        Ok(d_output)
    }


    pub fn from_proven_compact_ciphertext_list(
        h_proved_lists: &ProvenCompactCiphertextList,
        streams: &CudaStreams,
    ) -> Self {

        // TODO: Refactor this to concatenate all the lists
        let d_compact_lists: Vec<CudaCompactCiphertextList> = h_proved_lists.ct_list.proved_lists
            .par_iter()
            .map(|(ct_list, _proof)| { // Adjusted to use tuple destructuring for clarity
                CudaCompactCiphertextList::from_compact_ciphertext_list(ct_list, streams)
            })
            .collect();

        CudaProvenCompactCiphertextList{
            h_proved_lists: h_proved_lists.clone(),
            d_compact_lists,
        }
    }


    pub fn lwe_dimension(&self) -> LweDimension {
        self.d_compact_lists.first().unwrap().d_ct_list.0.lwe_dimension
    }

    pub fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        self.d_compact_lists.first().unwrap().d_ct_list.0.lwe_ciphertext_count
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<u64> {
        self.d_compact_lists.first().unwrap().d_ct_list.0.ciphertext_modulus
    }
}
