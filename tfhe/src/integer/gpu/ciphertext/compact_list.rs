use crate::core_crypto::commons::traits::contiguous_entity_container::ContiguousEntityContainer;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_compact_ciphertext_list::CudaLweCompactCiphertextList;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweCiphertext;
use crate::integer::ciphertext::{CompactCiphertextListExpander, DataKind};
use crate::integer::gpu::ciphertext::compressed_ciphertext_list::CudaExpandable;
use crate::integer::gpu::ciphertext::info::{CudaBlockInfo, CudaRadixCiphertextInfo};
use crate::integer::gpu::ciphertext::CudaRadixCiphertext;
use crate::shortint::ciphertext::CompactCiphertextList;
use crate::shortint::parameters::{CompactCiphertextListExpansionKind, Degree};
use crate::shortint::{CarryModulus, Ciphertext, MessageModulus};
use itertools::Itertools;

pub struct CudaCompactCiphertextList {
    pub(crate) d_ct_list: CudaLweCompactCiphertextList<u64>,
    pub(crate) degree: Degree,
    pub(crate) message_modulus: MessageModulus,
    pub(crate) carry_modulus: CarryModulus,
    pub(crate) expansion_kind: CompactCiphertextListExpansionKind,
}

impl CudaCompactCiphertextList {
    pub fn duplicate(&self, streams: &CudaStreams) -> Self {
        Self {
            d_ct_list: self.d_ct_list.duplicate(streams),
            degree: self.degree,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            expansion_kind: self.expansion_kind,
        }
    }
}

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
        self.expanded_blocks.lwe_ciphertext_count().0
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
