use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::server_key::radix::neg::NegatedDegreeIter;
use crate::integer::server_key::TwosComplementNegation;
use crate::shortint::ciphertext::{Degree, NoiseLevel};
use crate::shortint::{CarryModulus, MessageModulus, PBSOrder};
use itertools::Itertools;

#[derive(Clone, Copy)]
pub struct CudaBlockInfo {
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub pbs_order: PBSOrder,
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
    // Creates an iterator that return decomposed blocks of the negated
    // value of `scalar`
    //
    // Returns
    // - `None` if scalar is zero
    // - `Some` if scalar is non-zero
    //
    fn create_negated_block_decomposer<T>(&self, scalar: T) -> Option<impl Iterator<Item = u8>>
    where
        T: TwosComplementNegation + DecomposableInto<u8>,
    {
        if scalar == T::ZERO {
            return None;
        }
        let message_modulus = self.blocks.first().unwrap().message_modulus;
        let bits_in_message = message_modulus.0.ilog2();
        assert!(bits_in_message <= u8::BITS);

        // The whole idea behind this iterator we construct is:
        // - to support combos of parameters and num blocks for which the total number of bits is
        //   not a multiple of T::BITS
        //
        // - Support subtraction in the case the T::BITS is lower than the target ciphertext bits.
        //   In clear rust this would require an upcast, to support that we have to do a few things

        let neg_scalar = scalar.twos_complement_negation();

        // If we had upcasted the scalar, its msb would be zeros (0)
        // then they would become ones (1) after the bitwise_not (!).
        // The only case where these msb could become 0 after the addition
        // is if scalar == T::ZERO (=> !T::ZERO == T::MAX => T::MAX + 1 == overflow),
        // but this case has been handled earlier.
        let padding_bit = 1u32; // To handle when bits is not a multiple of T::BITS
                                // All bits of message set to one
        let pad_block = (1 << bits_in_message as u8) - 1;

        let decomposer = BlockDecomposer::with_padding_bit(
            neg_scalar,
            bits_in_message,
            T::cast_from(padding_bit),
        )
        .iter_as::<u8>()
        .chain(std::iter::repeat(pad_block));
        Some(decomposer)
    }

    pub(crate) fn after_add(&self, other: &Self) -> Self {
        Self {
            blocks: self
                .blocks
                .iter()
                .zip(&other.blocks)
                .map(|(left, right)| CudaBlockInfo {
                    degree: left.degree + right.degree,
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: left.noise_level + right.noise_level,
                })
                .collect(),
        }
    }

    pub(crate) fn after_neg(&self) -> Self {
        let new_degrees_iter = NegatedDegreeIter::new(
            self.blocks
                .iter()
                .map(|block| (block.degree, block.message_modulus)),
        );

        Self {
            blocks: self
                .blocks
                .iter()
                .zip(new_degrees_iter)
                .map(|(left, d)| CudaBlockInfo {
                    degree: d,
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: left.noise_level,
                })
                .collect(),
        }
    }

    pub(crate) fn after_mul(&self) -> Self {
        Self {
            blocks: self
                .blocks
                .iter()
                .map(|left| CudaBlockInfo {
                    degree: Degree::new(left.message_modulus.0 - 1),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: left.noise_level + NoiseLevel::NOMINAL,
                })
                .collect(),
        }
    }

    pub(crate) fn after_overflowing_sub(&self, other: &Self) -> Self {
        Self {
            blocks: self
                .blocks
                .iter()
                .zip(&other.blocks)
                .map(|(left, _)| CudaBlockInfo {
                    degree: left.degree,
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: left.noise_level,
                })
                .collect(),
        }
    }
    pub(crate) fn boolean_info(&self, noise_level: NoiseLevel) -> Self {
        Self {
            blocks: self
                .blocks
                .iter()
                .map(|left| CudaBlockInfo {
                    degree: Degree::new(1),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level,
                })
                .collect(),
        }
    }

    pub(crate) fn after_scalar_add<T>(&self, scalar: T) -> Self
    where
        T: DecomposableInto<u8>,
    {
        let message_modulus = self.blocks.first().unwrap().message_modulus;
        let bits_in_message = message_modulus.0.ilog2();
        let decomposer =
            BlockDecomposer::with_early_stop_at_zero(scalar, bits_in_message).iter_as::<u8>();
        let mut scalar_composed = decomposer.collect_vec();
        scalar_composed.resize(self.blocks.len(), 0);

        Self {
            blocks: self
                .blocks
                .iter()
                .zip(scalar_composed)
                .map(|(left, scalar_block)| CudaBlockInfo {
                    degree: Degree::new(left.degree.get() + scalar_block as usize),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: left.noise_level,
                })
                .collect(),
        }
    }

    pub(crate) fn after_scalar_mul(&self) -> Self {
        Self {
            blocks: self
                .blocks
                .iter()
                .map(|info| CudaBlockInfo {
                    degree: Degree::new(info.message_modulus.0 - 1),
                    message_modulus: info.message_modulus,
                    carry_modulus: info.carry_modulus,
                    pbs_order: info.pbs_order,
                    noise_level: info.noise_level + NoiseLevel::NOMINAL,
                })
                .collect(),
        }
    }

    pub(crate) fn after_scalar_sub<T>(&self, scalar: T) -> Self
    where
        T: TwosComplementNegation + DecomposableInto<u8>,
    {
        let Some(decomposer) = self.create_negated_block_decomposer(scalar) else {
            // subtraction by zero
            return self.clone();
        };

        Self {
            blocks: self
                .blocks
                .iter()
                .zip(decomposer)
                .map(|(left, scalar_block)| CudaBlockInfo {
                    degree: Degree::new(left.degree.get() + scalar_block as usize),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: left.noise_level,
                })
                .collect(),
        }
    }

    pub(crate) fn after_bitand(&self, other: &Self) -> Self {
        Self {
            blocks: self
                .blocks
                .iter()
                .zip(&other.blocks)
                .map(|(left, right)| CudaBlockInfo {
                    degree: left.degree.after_bitand(right.degree),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: NoiseLevel::NOMINAL,
                })
                .collect(),
        }
    }

    pub(crate) fn after_bitor(&self, other: &Self) -> Self {
        Self {
            blocks: self
                .blocks
                .iter()
                .zip(&other.blocks)
                .map(|(left, right)| CudaBlockInfo {
                    degree: left.degree.after_bitor(right.degree),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: NoiseLevel::NOMINAL,
                })
                .collect(),
        }
    }

    pub(crate) fn after_bitxor(&self, other: &Self) -> Self {
        Self {
            blocks: self
                .blocks
                .iter()
                .zip(&other.blocks)
                .map(|(left, right)| CudaBlockInfo {
                    degree: left.degree.after_bitxor(right.degree),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: NoiseLevel::NOMINAL,
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
        let decomposer =
            BlockDecomposer::with_early_stop_at_zero(scalar, bits_in_message).iter_as::<u8>();
        let mut scalar_composed = decomposer.collect_vec();
        scalar_composed.resize(self.blocks.len(), 0);

        Self {
            blocks: self
                .blocks
                .iter()
                .zip(scalar_composed)
                .map(|(left, scalar_block)| CudaBlockInfo {
                    degree: left.degree.after_bitand(Degree::new(scalar_block as usize)),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
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
        let decomposer =
            BlockDecomposer::with_early_stop_at_zero(scalar, bits_in_message).iter_as::<u8>();
        let mut scalar_composed = decomposer.collect_vec();
        scalar_composed.resize(self.blocks.len(), 0);

        Self {
            blocks: self
                .blocks
                .iter()
                .zip(scalar_composed)
                .map(|(left, scalar_block)| CudaBlockInfo {
                    degree: left.degree.after_bitor(Degree::new(scalar_block as usize)),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
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
        let decomposer =
            BlockDecomposer::with_early_stop_at_zero(scalar, bits_in_message).iter_as::<u8>();
        let mut scalar_composed = decomposer.collect_vec();
        scalar_composed.resize(self.blocks.len(), 0);

        Self {
            blocks: self
                .blocks
                .iter()
                .zip(scalar_composed)
                .map(|(left, scalar_block)| CudaBlockInfo {
                    degree: left.degree.after_bitxor(Degree::new(scalar_block as usize)),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: left.noise_level,
                })
                .collect(),
        }
    }

    // eq/ne, and comparisons returns a ciphertext that encrypts a 0 or 1, so the first block
    // (least significant) has a degree of 1, the other blocks should be trivial lwe encrypting 0,
    // so degree 0
    pub(crate) fn after_eq(&self) -> Self {
        Self {
            blocks: self
                .blocks
                .iter()
                .enumerate()
                .map(|(i, block)| CudaBlockInfo {
                    degree: if i == 0 {
                        Degree::new(1)
                    } else {
                        Degree::new(0)
                    },
                    message_modulus: block.message_modulus,
                    carry_modulus: block.carry_modulus,
                    pbs_order: block.pbs_order,
                    noise_level: NoiseLevel::NOMINAL,
                })
                .collect(),
        }
    }

    pub(crate) fn after_ne(&self) -> Self {
        Self {
            blocks: self
                .blocks
                .iter()
                .enumerate()
                .map(|(i, block)| CudaBlockInfo {
                    degree: if i == 0 {
                        Degree::new(1)
                    } else {
                        Degree::new(0)
                    },
                    message_modulus: block.message_modulus,
                    carry_modulus: block.carry_modulus,
                    pbs_order: block.pbs_order,
                    noise_level: NoiseLevel::NOMINAL,
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
                pbs_order: self.blocks.first().unwrap().pbs_order,
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
                pbs_order: self.blocks.first().unwrap().pbs_order,
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
        let mut new_block_info = Self {
            blocks: Vec::with_capacity(self.blocks.len().saturating_sub(num_blocks)),
        };
        new_block_info
            .blocks
            .extend(self.blocks[..num_blocks].iter().copied());
        new_block_info
    }
}
