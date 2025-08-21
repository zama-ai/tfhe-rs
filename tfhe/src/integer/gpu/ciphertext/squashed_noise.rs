use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{
    LweCiphertextCount, LweCiphertextList, LweCiphertextOwned, LweSize,
};
use crate::integer::ciphertext::{
    SquashedNoiseBooleanBlock, SquashedNoiseRadixCiphertext, SquashedNoiseSignedRadixCiphertext,
};
use crate::integer::gpu::ciphertext::info::{CudaBlockInfo, CudaRadixCiphertextInfo};
use crate::shortint::ciphertext::{Degree, NoiseLevel, SquashedNoiseCiphertext};
use crate::shortint::parameters::CoreCiphertextModulus;
use crate::shortint::{AtomicPatternKind, CarryModulus, MessageModulus, PBSOrder};
use crate::GpuIndex;
use itertools::Itertools;

pub struct CudaSquashedNoiseRadixCiphertext {
    pub packed_d_blocks: CudaLweCiphertextList<u128>,
    pub info: CudaRadixCiphertextInfo,
    pub original_block_count: usize,
}

pub struct CudaSquashedNoiseUnsignedRadixCiphertext {
    pub ciphertext: CudaSquashedNoiseRadixCiphertext,
}

pub struct CudaSquashedNoiseSignedRadixCiphertext {
    pub ciphertext: CudaSquashedNoiseRadixCiphertext,
}

pub struct CudaSquashedNoiseBooleanBlock {
    pub ciphertext: CudaSquashedNoiseRadixCiphertext,
}

impl CudaSquashedNoiseRadixCiphertext {
    pub(crate) fn new_zero(
        lwe_size: LweSize,
        lwe_ciphertext_count: LweCiphertextCount,
        ciphertext_modulus: CoreCiphertextModulus<u128>,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        original_block_count: usize,
        streams: &CudaStreams,
    ) -> Self {
        let mut blocks_info = Vec::with_capacity(lwe_ciphertext_count.0);

        for _ in 0..lwe_ciphertext_count.0 {
            blocks_info.push(CudaBlockInfo {
                degree: Degree::new(0u64),
                message_modulus,
                carry_modulus,
                atomic_pattern: AtomicPatternKind::Standard(PBSOrder::KeyswitchBootstrap),
                noise_level: NoiseLevel::ZERO,
            });
        }
        Self {
            packed_d_blocks: CudaLweCiphertextList::<u128>::new(
                lwe_size.to_lwe_dimension(),
                lwe_ciphertext_count,
                ciphertext_modulus,
                streams,
            ),
            info: CudaRadixCiphertextInfo {
                blocks: blocks_info,
            },
            original_block_count,
        }
    }

    pub fn duplicate(&self, streams: &CudaStreams) -> Self {
        Self {
            packed_d_blocks: self.packed_d_blocks.duplicate(streams),
            info: self.info.duplicate(),
            original_block_count: self.original_block_count,
        }
    }

    pub(crate) fn to_squashed_noise_radix_ciphertext(
        &self,
        streams: &CudaStreams,
    ) -> SquashedNoiseRadixCiphertext {
        let num_blocks = self.packed_d_blocks.lwe_ciphertext_count().0;
        let lwe_size = self.packed_d_blocks.lwe_dimension().to_lwe_size();
        let ct_modulus = self.packed_d_blocks.ciphertext_modulus();

        let lwe_ct_list_cpu = self.packed_d_blocks.to_lwe_ciphertext_list(streams);
        let mut packed_blocks = Vec::<SquashedNoiseCiphertext>::with_capacity(num_blocks);
        lwe_ct_list_cpu
            .as_ref()
            .chunks(lwe_size.0)
            .enumerate()
            .for_each(|(i, block)| {
                let block = LweCiphertextOwned::from_container(block.to_vec(), ct_modulus);
                let info = self.info.blocks[i];
                packed_blocks.push(SquashedNoiseCiphertext::new(
                    block,
                    info.degree,
                    info.message_modulus,
                    info.carry_modulus,
                ));
            });
        SquashedNoiseRadixCiphertext {
            packed_blocks,
            original_block_count: self.original_block_count,
        }
    }

    pub(crate) fn from_cpu_blocks(
        blocks: &[SquashedNoiseCiphertext],
        streams: &CudaStreams,
    ) -> Self {
        let mut h_radix_ciphertext = blocks
            .iter()
            .flat_map(|block| block.lwe_ciphertext().clone().into_container())
            .collect::<Vec<_>>();

        let lwe_size = blocks.first().unwrap().lwe_ciphertext().lwe_size();
        let ciphertext_modulus = blocks
            .first()
            .unwrap()
            .lwe_ciphertext()
            .ciphertext_modulus();

        let h_ct = LweCiphertextList::from_container(
            h_radix_ciphertext.as_mut_slice(),
            lwe_size,
            ciphertext_modulus,
        );
        let packed_d_blocks = CudaLweCiphertextList::from_lwe_ciphertext_list(&h_ct, streams);

        let info = CudaRadixCiphertextInfo {
            blocks: blocks
                .iter()
                .map(|block| CudaBlockInfo {
                    degree: block.degree(),
                    message_modulus: block.message_modulus(),
                    carry_modulus: block.carry_modulus(),
                    atomic_pattern: AtomicPatternKind::Standard(PBSOrder::KeyswitchBootstrap),
                    noise_level: NoiseLevel::NOMINAL,
                })
                .collect(),
        };

        let original_block_count = blocks.len();

        Self {
            packed_d_blocks,
            info,
            original_block_count,
        }
    }

    pub(crate) fn from_squashed_noise_ciphertext(
        ct: &SquashedNoiseCiphertext,
        streams: &CudaStreams,
    ) -> Self {
        Self {
            packed_d_blocks: CudaLweCiphertextList::from_lwe_ciphertext(
                ct.lwe_ciphertext(),
                streams,
            ),
            info: CudaRadixCiphertextInfo {
                blocks: vec![CudaBlockInfo {
                    degree: ct.degree(),
                    message_modulus: ct.message_modulus(),
                    carry_modulus: ct.carry_modulus(),
                    atomic_pattern: AtomicPatternKind::Standard(PBSOrder::KeyswitchBootstrap),
                    noise_level: NoiseLevel::NOMINAL,
                }],
            },
            original_block_count: 1,
        }
    }

    pub(crate) fn from_squashed_noise_radix_ciphertext(
        ct: &SquashedNoiseRadixCiphertext,
        streams: &CudaStreams,
    ) -> Self {
        let lwe_size = ct
            .packed_blocks
            .first()
            .unwrap()
            .lwe_ciphertext()
            .lwe_size();
        let ciphertext_modulus = ct
            .packed_blocks
            .first()
            .unwrap()
            .lwe_ciphertext()
            .ciphertext_modulus();

        let vec_lwe = ct
            .packed_blocks
            .iter()
            .flat_map(|ct| ct.lwe_ciphertext().clone().into_container())
            .collect_vec();
        let lwe_list = LweCiphertextList::from_container(vec_lwe, lwe_size, ciphertext_modulus);
        let packed_d_blocks = CudaLweCiphertextList::from_lwe_ciphertext_list(&lwe_list, streams);

        let info = CudaRadixCiphertextInfo {
            blocks: ct
                .packed_blocks
                .iter()
                .map(|ct| CudaBlockInfo {
                    degree: ct.degree(),
                    message_modulus: ct.message_modulus(),
                    carry_modulus: ct.carry_modulus(),
                    atomic_pattern: AtomicPatternKind::KeySwitch32,
                    noise_level: NoiseLevel::NOMINAL,
                })
                .collect_vec(),
        };

        let original_block_count = ct.original_block_count;

        Self {
            packed_d_blocks,
            info,
            original_block_count,
        }
    }

    pub fn gpu_indexes(&self) -> &[GpuIndex] {
        self.packed_d_blocks.0.d_vec.gpu_indexes.as_slice()
    }
}

impl CudaSquashedNoiseSignedRadixCiphertext {
    pub fn to_squashed_noise_signed_radix_ciphertext(
        &self,
        streams: &CudaStreams,
    ) -> SquashedNoiseSignedRadixCiphertext {
        SquashedNoiseSignedRadixCiphertext {
            packed_blocks: self
                .ciphertext
                .to_squashed_noise_radix_ciphertext(streams)
                .packed_blocks,
            original_block_count: self.ciphertext.original_block_count,
        }
    }

    pub(crate) fn from_squashed_noise_signed_radix_ciphertext(
        ct: &SquashedNoiseSignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> Self {
        let lwe_size = ct
            .packed_blocks
            .first()
            .unwrap()
            .lwe_ciphertext()
            .lwe_size();
        let ciphertext_modulus = ct
            .packed_blocks
            .first()
            .unwrap()
            .lwe_ciphertext()
            .ciphertext_modulus();

        let vec_lwe = ct
            .packed_blocks
            .iter()
            .flat_map(|ct| ct.lwe_ciphertext().clone().into_container())
            .collect_vec();
        let lwe_list = LweCiphertextList::from_container(vec_lwe, lwe_size, ciphertext_modulus);
        let packed_d_blocks = CudaLweCiphertextList::from_lwe_ciphertext_list(&lwe_list, streams);

        let info = CudaRadixCiphertextInfo {
            blocks: ct
                .packed_blocks
                .iter()
                .map(|ct| CudaBlockInfo {
                    degree: ct.degree(),
                    message_modulus: ct.message_modulus(),
                    carry_modulus: ct.carry_modulus(),
                    atomic_pattern: AtomicPatternKind::KeySwitch32,
                    noise_level: NoiseLevel::NOMINAL,
                })
                .collect_vec(),
        };

        let original_block_count = ct.original_block_count;

        Self {
            ciphertext: CudaSquashedNoiseRadixCiphertext {
                packed_d_blocks,
                info,
                original_block_count,
            },
        }
    }

    pub(crate) fn duplicate(&self, streams: &CudaStreams) -> Self {
        Self {
            ciphertext: self.ciphertext.duplicate(streams),
        }
    }

    pub fn gpu_indexes(&self) -> &[GpuIndex] {
        self.ciphertext.gpu_indexes()
    }
}

impl CudaSquashedNoiseBooleanBlock {
    pub fn to_squashed_noise_boolean_block(
        &self,
        streams: &CudaStreams,
    ) -> SquashedNoiseBooleanBlock {
        SquashedNoiseBooleanBlock {
            ciphertext: self
                .ciphertext
                .to_squashed_noise_radix_ciphertext(streams)
                .packed_blocks[0]
                .clone(),
        }
    }

    pub(crate) fn from_squashed_noise_boolean_block(
        ct: &SquashedNoiseBooleanBlock,
        streams: &CudaStreams,
    ) -> Self {
        Self {
            ciphertext: CudaSquashedNoiseRadixCiphertext::from_squashed_noise_ciphertext(
                &ct.ciphertext,
                streams,
            ),
        }
    }

    pub(crate) fn duplicate(&self, streams: &CudaStreams) -> Self {
        Self {
            ciphertext: self.ciphertext.duplicate(streams),
        }
    }

    pub fn gpu_indexes(&self) -> &[GpuIndex] {
        self.ciphertext.gpu_indexes()
    }
}
