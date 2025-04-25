use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_compact_ciphertext_list::CudaLweCompactCiphertextList;
use crate::core_crypto::gpu::CudaStreams;
use crate::integer::ciphertext::DataKind;
use crate::integer::gpu::ciphertext::compressed_ciphertext_list::CudaExpandable;
use crate::integer::gpu::ciphertext::info::{CudaBlockInfo, CudaRadixCiphertextInfo};
use crate::integer::gpu::ciphertext::CudaRadixCiphertext;
use crate::shortint::ciphertext::CompactCiphertextList;
use crate::shortint::parameters::{CompactCiphertextListExpansionKind, Degree};
use crate::shortint::{CarryModulus, MessageModulus};

pub struct CudaCompactCiphertextList {
    pub(crate) d_ct_list: CudaLweCompactCiphertextList<u64>,
    pub(crate) degree: Degree,
    pub(crate) message_modulus: MessageModulus,
    pub(crate) carry_modulus: CarryModulus,
    pub(crate) expansion_kind: CompactCiphertextListExpansionKind,
}

#[derive(Clone)]
pub struct CudaCompactCiphertextListInfo {
    pub info: CudaBlockInfo,
    pub data_kind: DataKind,
}

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

    fn blocks_of(
        &self,
        index: usize,
        streams: &CudaStreams,
    ) -> Option<(CudaRadixCiphertext, DataKind)> {
        let preceding_infos = self.blocks_info.get(..index).unwrap();
        let current_info = self.blocks_info.get(index).unwrap();
        let message_modulus = self.blocks_info.get(index).unwrap().info.message_modulus;

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

    pub fn get<T>(&self, index: usize, streams: &CudaStreams) -> crate::Result<Option<T>>
    where
        T: CudaExpandable,
    {
        self.blocks_of(index, streams)
            .map(|(blocks, kind)| T::from_expanded_blocks(blocks, kind))
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

    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called after this function as soon as
    ///   synchronization is required
    pub unsafe fn from_compact_ciphertext_list_async(
        h_ct: &CompactCiphertextList,
        streams: &CudaStreams,
    ) -> Self {
        let d_ct_list = CudaLweCompactCiphertextList::from_lwe_compact_ciphertext_list_async(
            &h_ct.ct_list,
            streams,
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
        let h_ct_list = self.d_ct_list.to_lwe_compact_ciphertext_list(streams);
        CompactCiphertextList {
            ct_list: h_ct_list,
            degree: self.degree,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            expansion_kind: self.expansion_kind,
        }
    }
}
