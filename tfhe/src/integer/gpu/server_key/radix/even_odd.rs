use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::radix::{
    CudaBlockInfo, CudaLweCiphertextList, CudaRadixCiphertext, CudaRadixCiphertextInfo,
    LweCiphertextCount,
};
use crate::integer::gpu::server_key::CudaServerKey;
use crate::shortint::parameters::{AtomicPatternKind, Degree, NoiseLevel};

impl CudaServerKey {
    pub fn unchecked_is_even<T>(&self, ct: &T, streams: &CudaStreams) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let radix = ct.as_ref();
        let lut = self.generate_lookup_table(|block| u64::from((block & 1) == 0));
        let mut single_block = CudaRadixCiphertext {
            d_blocks: CudaLweCiphertextList::new(
                radix.d_blocks.0.lwe_dimension,
                LweCiphertextCount(1),
                radix.d_blocks.0.ciphertext_modulus,
                streams,
            ),
            info: CudaRadixCiphertextInfo {
                blocks: vec![CudaBlockInfo {
                    degree: Degree::new(1),
                    message_modulus: self.message_modulus,
                    carry_modulus: self.carry_modulus,
                    atomic_pattern: AtomicPatternKind::Standard(self.pbs_order),
                    noise_level: NoiseLevel::NOMINAL,
                }],
            },
        };
        self.apply_lookup_table(&mut single_block, radix, &lut, 0..1, streams);
        CudaBooleanBlock::from_cuda_radix_ciphertext(single_block)
    }

    pub fn is_even<T>(&self, ct: &T, streams: &CudaStreams) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        // Since the check is done on the first bit of the first block
        // no need to worry about carries
        self.unchecked_is_even(ct, streams)
    }

    pub fn unchecked_is_odd<T>(&self, ct: &T, streams: &CudaStreams) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let radix = ct.as_ref();
        let lut = self.generate_lookup_table(|block| block & 1);
        let mut single_block = CudaRadixCiphertext {
            d_blocks: CudaLweCiphertextList::new(
                radix.d_blocks.0.lwe_dimension,
                LweCiphertextCount(1),
                radix.d_blocks.0.ciphertext_modulus,
                streams,
            ),
            info: CudaRadixCiphertextInfo {
                blocks: vec![CudaBlockInfo {
                    degree: Degree::new(1),
                    message_modulus: self.message_modulus,
                    carry_modulus: self.carry_modulus,
                    atomic_pattern: AtomicPatternKind::Standard(self.pbs_order),
                    noise_level: NoiseLevel::NOMINAL,
                }],
            },
        };
        self.apply_lookup_table(&mut single_block, radix, &lut, 0..1, streams);
        CudaBooleanBlock::from_cuda_radix_ciphertext(single_block)
    }

    pub fn is_odd<T>(&self, ct: &T, streams: &CudaStreams) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        // Since the check is done on the first bit of the first block
        // no need to worry about carries
        self.unchecked_is_odd(ct, streams)
    }
}
