//! Module containing primitives pertaining to random mask generation in the context of encryption.

use super::PER_SAMPLE_TARGET_FAILURE_PROBABILITY_LOG2;
use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, CompressionSeed, Distribution, ParallelByteRandomGenerator,
    RandomGenerable, RandomGenerator, Uniform,
};
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::{
    CiphertextModulus, EncryptionMaskByteCount, EncryptionMaskSampleCount,
};
use rayon::prelude::*;
use tfhe_csprng::generators::aes_ctr::AesCtrParams;
use tfhe_csprng::generators::ForkError;
use tfhe_csprng::seeders::SeedKind;

#[derive(Clone, Copy, Debug)]
pub struct MaskRandomGeneratorForkConfig {
    children_count: usize,
    mask_byte_count_per_child: EncryptionMaskByteCount,
}

impl MaskRandomGeneratorForkConfig {
    pub fn new<Scalar, MaskDistribution>(
        children_count: usize,
        mask_element_per_child_count: EncryptionMaskSampleCount,
        mask_distribution: MaskDistribution,
        modulus: Option<Scalar>,
    ) -> Self
    where
        MaskDistribution: Distribution,
        Scalar: Copy + RandomGenerable<MaskDistribution, CustomModulus = Scalar>,
    {
        let mask_per_element_required_bytes = {
            let mask_sample_required_bytes =
                Scalar::single_sample_required_random_byte_count(mask_distribution, modulus);

            let mask_sample_success_proba =
                Scalar::single_sample_success_probability(mask_distribution, modulus);

            if mask_sample_success_proba == 1.0 {
                EncryptionMaskByteCount(mask_sample_required_bytes)
            } else {
                let mask_sample_failure_proba = 1.0 - mask_sample_success_proba;
                if mask_sample_failure_proba == 0.0 {
                    // In case of negligible failure proba, avoid taking log2 of 0
                    EncryptionMaskByteCount(mask_sample_required_bytes)
                } else {
                    let mask_sample_failure_proba_log2 = mask_sample_failure_proba.log2();
                    let min_attempts_per_sample = (PER_SAMPLE_TARGET_FAILURE_PROBABILITY_LOG2
                        / mask_sample_failure_proba_log2)
                        .ceil() as usize;

                    EncryptionMaskByteCount(mask_sample_required_bytes * min_attempts_per_sample)
                }
            }
        };

        Self {
            children_count,
            mask_byte_count_per_child: mask_element_per_child_count
                .to_mask_byte_count(mask_per_element_required_bytes),
        }
    }

    pub fn from_children_and_mask_byte_count(
        children_count: usize,
        mask_byte_count_per_child: EncryptionMaskByteCount,
    ) -> Self {
        Self {
            children_count,
            mask_byte_count_per_child,
        }
    }

    pub fn children_count(&self) -> usize {
        self.children_count
    }

    pub fn mask_byte_count_per_child(&self) -> EncryptionMaskByteCount {
        self.mask_byte_count_per_child
    }
}

/// Generator dedicated to filling masks.
///
/// This structure needs to be separate from
/// [`EncryptionRandomGenerator`](`super::EncryptionRandomGenerator`) to be usable in the context of
/// seeded entities decompression, notably parallel decompression where building an
/// [`EncryptionRandomGenerator`](`super::EncryptionRandomGenerator`) is not possible due to the
/// requirement of a [`Seeder`](`super::Seeder`) to build one to avoid misuse.
///
/// It does imply some API duplication and potentially tedious work to integrate new primitives but
/// in the context of potentially more complex mask generation algorithm (due to needing uniform
/// values for non power of 2 moduli) which may require rejection sampling, having the primitives
/// properly separate in their respective types is preferable.
pub struct MaskRandomGenerator<G: ByteRandomGenerator> {
    seed: SeedKind,
    gen: RandomGenerator<G>,
}

impl<G: ByteRandomGenerator> MaskRandomGenerator<G> {
    pub fn new(params: impl Into<AesCtrParams>) -> Self {
        let params = params.into();
        let seed = params.seed.clone();
        Self {
            gen: RandomGenerator::new(params),
            seed,
        }
    }

    pub fn remaining_bytes(&self) -> Option<usize> {
        self.gen.remaining_bytes()
    }

    pub fn current_compression_seed(&self) -> CompressionSeed {
        CompressionSeed {
            inner: AesCtrParams {
                seed: self.seed.clone(),
                first_index: self.gen.next_table_index(),
            },
        }
    }

    // Fills the slice with random uniform values, using the mask generator.
    pub(crate) fn fill_slice_with_random_uniform_mask<Scalar>(&mut self, output: &mut [Scalar])
    where
        Scalar: RandomGenerable<Uniform>,
    {
        self.gen.fill_slice_with_random_uniform(output);
    }

    // Fills the slice with random uniform values, using the mask generator
    pub(crate) fn fill_slice_with_random_uniform_mask_custom_mod<Scalar>(
        &mut self,
        output: &mut [Scalar],
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) where
        Scalar: UnsignedInteger + RandomGenerable<Uniform, CustomModulus = Scalar>,
    {
        self.gen
            .fill_slice_with_random_uniform_custom_mod(output, ciphertext_modulus);
    }

    pub(crate) fn try_fork(
        &mut self,
        n_child: usize,
        mask_bytes: EncryptionMaskByteCount,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let seed = self.seed.clone();
        let mask_iter = self.gen.try_fork(n_child, mask_bytes.0)?;

        Ok(mask_iter.map(move |gen| Self {
            seed: seed.clone(),
            gen,
        }))
    }

    pub(crate) fn try_fork_from_config(
        &mut self,
        fork_config: MaskRandomGeneratorForkConfig,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        self.try_fork(
            fork_config.children_count,
            fork_config.mask_byte_count_per_child,
        )
    }
}

impl<G: ParallelByteRandomGenerator> MaskRandomGenerator<G> {
    pub(crate) fn par_try_fork(
        &mut self,
        n_child: usize,
        mask_bytes: EncryptionMaskByteCount,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let seed = self.seed.clone();
        let mask_iter = self.gen.par_try_fork(n_child, mask_bytes.0)?;

        Ok(mask_iter.map(move |gen| Self {
            seed: seed.clone(),
            gen,
        }))
    }

    pub(crate) fn par_try_fork_from_config(
        &mut self,
        fork_config: MaskRandomGeneratorForkConfig,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        self.par_try_fork(
            fork_config.children_count,
            fork_config.mask_byte_count_per_child,
        )
    }
}
