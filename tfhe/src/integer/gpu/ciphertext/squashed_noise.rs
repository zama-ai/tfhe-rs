use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{LweCiphertextCount, LweCiphertextOwned, LweSize};
use crate::integer::ciphertext::{
    SquashedNoiseBooleanBlock, SquashedNoiseRadixCiphertext, SquashedNoiseSignedRadixCiphertext,
};
use crate::integer::gpu::ciphertext::info::{CudaBlockInfo, CudaRadixCiphertextInfo};
use crate::shortint::ciphertext::{Degree, NoiseLevel, SquashedNoiseCiphertext};
use crate::shortint::parameters::CoreCiphertextModulus;
use crate::shortint::{AtomicPatternKind, CarryModulus, MessageModulus, PBSOrder};

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

    pub(crate) fn duplicate(&self, streams: &CudaStreams) -> Self {
        Self {
            ciphertext: self.ciphertext.duplicate(streams),
        }
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

    pub(crate) fn duplicate(&self, streams: &CudaStreams) -> Self {
        Self {
            ciphertext: self.ciphertext.duplicate(streams),
        }
    }
}
