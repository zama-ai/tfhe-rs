use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::server_key::TwosComplementNegation;
use crate::shortint::atomic_pattern::AtomicPattern;
use crate::shortint::ciphertext::{Degree, NoiseLevel};
use crate::shortint::{CarryModulus, MessageModulus};
use itertools::Itertools;

#[derive(Clone, Copy)]
pub struct CudaBlockInfo {
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub atomic_pattern: AtomicPattern,
    pub noise_level: NoiseLevel,
}

impl CudaBlockInfo {
    pub fn carry_is_empty(&self) -> bool {
        self.degree.get() < self.message_modulus.0
    }
}

#[derive(Clone)]
pub struct CudaRadixCiphertextInfo {
    pub blocks: Vec<CudaBlockInfo>,
}

impl CudaRadixCiphertextInfo {
    pub(crate) fn boolean_info(&self, noise_level: NoiseLevel) -> Self {
        Self {
            blocks: self
                .blocks
                .iter()
                .map(|left| CudaBlockInfo {
                    degree: Degree::new(1),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    atomic_pattern: left.atomic_pattern,
                    noise_level,
                })
                .collect(),
        }
    }

    pub(crate) fn after_bitnot(&self) -> Self {
        Self {
            blocks: self
                .blocks
                .iter()
                .map(|b| CudaBlockInfo {
                    degree: Degree::new(b.message_modulus.0 - 1),
                    message_modulus: b.message_modulus,
                    carry_modulus: b.carry_modulus,
                    atomic_pattern: b.atomic_pattern,
                    noise_level: b.noise_level,
                })
                .collect(),
        }
    }
    pub(crate) fn after_scalar_bitand<T>(&self, scalar: T) -> Self
    where
        T: DecomposableInto<u8>,
    {
        let message_modulus = self.blocks.first().unwrap().message_modulus;
        let bits_in_message = message_modulus.0.ilog2();
        let decomposer = BlockDecomposer::with_early_stop_at_zero(scalar, bits_in_message)
            .iter_as::<u8>()
            .chain(std::iter::repeat(0u8));

        Self {
            blocks: self
                .blocks
                .iter()
                .zip(decomposer)
                .map(|(left, scalar_block)| CudaBlockInfo {
                    degree: left
                        .degree
                        .after_bitand(Degree::new(u64::from(scalar_block))),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    atomic_pattern: left.atomic_pattern,
                    noise_level: left.noise_level,
                })
                .collect(),
        }
    }

    pub(crate) fn after_scalar_bitor<T>(&self, scalar: T) -> Self
    where
        T: DecomposableInto<u8>,
    {
        let message_modulus = self.blocks.first().unwrap().message_modulus;
        let bits_in_message = message_modulus.0.ilog2();
        let decomposer = BlockDecomposer::with_early_stop_at_zero(scalar, bits_in_message)
            .iter_as::<u8>()
            .chain(std::iter::repeat(0u8));

        Self {
            blocks: self
                .blocks
                .iter()
                .zip(decomposer)
                .map(|(left, scalar_block)| CudaBlockInfo {
                    degree: left
                        .degree
                        .after_bitor(Degree::new(u64::from(scalar_block))),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    atomic_pattern: left.atomic_pattern,
                    noise_level: left.noise_level,
                })
                .collect(),
        }
    }

    pub(crate) fn after_scalar_bitxor<T>(&self, scalar: T) -> Self
    where
        T: DecomposableInto<u8>,
    {
        let message_modulus = self.blocks.first().unwrap().message_modulus;
        let bits_in_message = message_modulus.0.ilog2();
        let decomposer = BlockDecomposer::with_early_stop_at_zero(scalar, bits_in_message)
            .iter_as::<u8>()
            .chain(std::iter::repeat(0u8));

        Self {
            blocks: self
                .blocks
                .iter()
                .zip(decomposer)
                .map(|(left, scalar_block)| CudaBlockInfo {
                    degree: left
                        .degree
                        .after_bitxor(Degree::new(u64::from(scalar_block))),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    atomic_pattern: left.atomic_pattern,
                    noise_level: left.noise_level,
                })
                .collect(),
        }
    }

    pub(crate) fn after_extend_radix_with_trivial_zero_blocks_lsb(
        &self,
        num_blocks: usize,
    ) -> Self {
        let mut new_block_info = Self {
            blocks: Vec::with_capacity(self.blocks.len() + num_blocks),
        };
        for _ in 0..num_blocks {
            new_block_info.blocks.push(CudaBlockInfo {
                degree: Degree::new(0),
                message_modulus: self.blocks.first().unwrap().message_modulus,
                carry_modulus: self.blocks.first().unwrap().carry_modulus,
                atomic_pattern: self.blocks.first().unwrap().atomic_pattern,
                noise_level: NoiseLevel::ZERO,
            });
        }
        for &b in self.blocks.iter() {
            new_block_info.blocks.push(b);
        }
        new_block_info
    }

    pub(crate) fn after_extend_radix_with_trivial_zero_blocks_msb(
        &self,
        num_blocks: usize,
    ) -> Self {
        assert!(num_blocks > 0);

        let mut new_block_info = Self {
            blocks: Vec::with_capacity(self.blocks.len() + num_blocks),
        };
        for &b in self.blocks.iter() {
            new_block_info.blocks.push(b);
        }
        for _ in 0..num_blocks {
            new_block_info.blocks.push(CudaBlockInfo {
                degree: Degree::new(0),
                message_modulus: self.blocks.first().unwrap().message_modulus,
                carry_modulus: self.blocks.first().unwrap().carry_modulus,
                atomic_pattern: self.blocks.first().unwrap().atomic_pattern,
                noise_level: NoiseLevel::ZERO,
            });
        }
        new_block_info
    }

    pub(crate) fn after_trim_radix_blocks_lsb(&self, num_blocks: usize) -> Self {
        let mut new_block_info = Self {
            blocks: Vec::with_capacity(self.blocks.len().saturating_sub(num_blocks)),
        };
        new_block_info
            .blocks
            .extend(self.blocks[num_blocks..].iter().copied());
        new_block_info
    }

    pub(crate) fn after_trim_radix_blocks_msb(&self, num_blocks: usize) -> Self {
        assert!(num_blocks > 0);

        let mut new_block_info = Self {
            blocks: Vec::with_capacity(self.blocks.len().saturating_sub(num_blocks)),
        };
        new_block_info
            .blocks
            .extend(self.blocks[..num_blocks].iter().copied());
        new_block_info
    }
}
