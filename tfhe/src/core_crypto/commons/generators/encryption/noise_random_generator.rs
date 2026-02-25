//! Module containing primitives pertaining to random noise generation in the context of encryption.

use super::PER_SAMPLE_TARGET_FAILURE_PROBABILITY_LOG2;
use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, Distribution, ParallelByteRandomGenerator, RandomGenerable,
    RandomGenerator, Seeder,
};
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::{
    CiphertextModulus, EncryptionNoiseByteCount, EncryptionNoiseSampleCount,
};
use rayon::prelude::*;
use tfhe_csprng::generators::ForkError;
use tfhe_csprng::seeders::SeedKind;

#[derive(Clone, Copy, Debug)]
pub struct NoiseRandomGeneratorForkConfig {
    children_count: usize,
    noise_byte_count_per_child: EncryptionNoiseByteCount,
}

impl NoiseRandomGeneratorForkConfig {
    pub fn new<Scalar, NoiseDistribution>(
        children_count: usize,
        noise_element_per_child_count: EncryptionNoiseSampleCount,
        noise_distribution: NoiseDistribution,
        modulus: Option<Scalar>,
    ) -> Self
    where
        NoiseDistribution: Distribution,
        Scalar: Copy + RandomGenerable<NoiseDistribution, CustomModulus = Scalar>,
    {
        let noise_per_element_required_bytes = {
            let noise_sample_required_bytes =
                Scalar::single_sample_required_random_byte_count(noise_distribution, modulus);

            let noise_sample_success_proba =
                Scalar::single_sample_success_probability(noise_distribution, modulus);

            if noise_sample_success_proba == 1.0 {
                EncryptionNoiseByteCount(noise_sample_required_bytes)
            } else {
                let noise_sample_failure_proba = 1.0 - noise_sample_success_proba;
                if noise_sample_failure_proba == 0.0 {
                    // In case of negligible failure proba, avoid taking log2 of 0
                    EncryptionNoiseByteCount(noise_sample_required_bytes)
                } else {
                    let noise_sample_failure_proba_log2 = noise_sample_failure_proba.log2();
                    let min_attempts_per_sample = (PER_SAMPLE_TARGET_FAILURE_PROBABILITY_LOG2
                        / noise_sample_failure_proba_log2)
                        .ceil() as usize;

                    EncryptionNoiseByteCount(noise_sample_required_bytes * min_attempts_per_sample)
                }
            }
        };

        Self {
            children_count,
            noise_byte_count_per_child: noise_element_per_child_count
                .to_noise_byte_count(noise_per_element_required_bytes),
        }
    }

    pub fn from_children_and_noise_byte_count(
        children_count: usize,
        noise_byte_count_per_child: EncryptionNoiseByteCount,
    ) -> Self {
        Self {
            children_count,
            noise_byte_count_per_child,
        }
    }

    pub fn children_count(&self) -> usize {
        self.children_count
    }

    pub fn noise_byte_count_per_child(&self) -> EncryptionNoiseByteCount {
        self.noise_byte_count_per_child
    }
}

/// Generator dedicated to generating noise.
///
/// This structure needs to be separate from
/// [`EncryptionRandomGenerator`](`super::EncryptionRandomGenerator`) to be usable in the context of
/// seeded entities decompression, notably parallel decompression where building an
/// [`EncryptionRandomGenerator`](`super::EncryptionRandomGenerator`) is not possible due to the
/// requirement of a [`Seeder`](`super::Seeder`) to build one to avoid misuse.
///
/// It does imply some API duplication and potentially tedious work to integrate new primitives but
/// in the context noise generation algorithm which require rejection sampling, having the
/// primitives properly separate in their respective types is preferable to avoid depending on the
/// more user friendly but more inflexible
/// [`EncryptionRandomGenerator`](`super::EncryptionRandomGenerator`)
pub struct NoiseRandomGenerator<G: ByteRandomGenerator> {
    gen: RandomGenerator<G>,
}

impl<G: ByteRandomGenerator> NoiseRandomGenerator<G> {
    /// Create a new [`NoiseRandomGenerator`], using the provided [`Seeder`] to privately seed the
    /// noise generator.
    // S is ?Sized to allow Box<dyn Seeder> to be passed.
    pub fn new<S: Seeder + ?Sized>(seeder: &mut S) -> Self {
        Self {
            gen: RandomGenerator::new(seeder.seed()),
        }
    }

    pub fn from_raw_parts(gen: RandomGenerator<G>) -> Self {
        Self { gen }
    }

    /// Create a new [`NoiseRandomGenerator`], using the provided seed
    pub fn new_from_seed(seed: impl Into<SeedKind>) -> Self {
        let seed: SeedKind = seed.into();
        Self {
            gen: RandomGenerator::new(seed),
        }
    }

    pub fn remaining_bytes(&self) -> Option<usize> {
        self.gen.remaining_bytes()
    }

    // Sample a noise value, using the random generator.
    pub(crate) fn random_noise_from_distribution<D, Scalar>(&mut self, distribution: D) -> Scalar
    where
        D: Distribution,
        Scalar: RandomGenerable<D>,
    {
        self.gen.random_from_distribution(distribution)
    }

    // Sample a noise value, using the random generator.
    pub(crate) fn random_noise_from_distribution_custom_mod<D, Scalar>(
        &mut self,
        distribution: D,
        custom_modulus: CiphertextModulus<Scalar>,
    ) -> Scalar
    where
        D: Distribution,
        Scalar: UnsignedInteger + RandomGenerable<D, CustomModulus = Scalar>,
    {
        if custom_modulus.is_native_modulus() {
            self.random_noise_from_distribution(distribution)
        } else {
            self.gen
                .random_from_distribution_custom_mod(distribution, custom_modulus)
        }
    }

    // Fills the input slice with random noise, using the random generator.
    pub(crate) fn fill_slice_with_random_noise_from_distribution<D, Scalar>(
        &mut self,
        output: &mut [Scalar],
        distribution: D,
    ) where
        D: Distribution,
        Scalar: RandomGenerable<D>,
    {
        self.gen
            .fill_slice_with_random_from_distribution(output, distribution);
    }

    // Fills the input slice with random noise, using the random generator.
    pub(crate) fn fill_slice_with_random_noise_from_distribution_custom_mod<D, Scalar>(
        &mut self,
        output: &mut [Scalar],
        distribution: D,
        custom_modulus: CiphertextModulus<Scalar>,
    ) where
        D: Distribution,
        Scalar: UnsignedInteger + RandomGenerable<D, CustomModulus = Scalar>,
    {
        self.gen
            .fill_slice_with_random_from_distribution_custom_mod(
                output,
                distribution,
                custom_modulus,
            );
    }

    /// Fill a slice with random uniform binary values.
    /// This will only draw as many bytes needed from the underlying csprng to fill the slice with
    /// random bits. If the slice len is n, it will draw ceil(n/8) bytes from the csprng.
    pub(crate) fn fill_slice_with_random_uniform_binary_bits<Scalar>(
        &mut self,
        output: &mut [Scalar],
    ) where
        Scalar: UnsignedInteger,
    {
        self.gen.fill_slice_with_random_uniform_binary_bits(output)
    }

    // Adds noise on top of existing data for in place encryption
    pub(crate) fn unsigned_integer_slice_wrapping_add_random_noise_from_distribution_assign<
        D,
        Scalar,
    >(
        &mut self,
        output: &mut [Scalar],
        distribution: D,
    ) where
        D: Distribution,
        Scalar: UnsignedInteger + RandomGenerable<D>,
    {
        self.gen
            .unsigned_integer_slice_wrapping_add_random_from_distribution_assign(
                output,
                distribution,
            );
    }

    // Adds noise on top of existing data for in place encryption
    pub(crate) fn unsigned_integer_slice_wrapping_add_random_noise_from_distribution_custom_mod_assign<
        D,
        Scalar,
    >(
        &mut self,
        output: &mut [Scalar],
        distribution: D,
        custom_modulus: CiphertextModulus<Scalar>,
    ) where
        D: Distribution,
        Scalar: UnsignedInteger + RandomGenerable<D, CustomModulus = Scalar>,
    {
        self.gen
            .unsigned_integer_slice_wrapping_add_random_from_distribution_custom_mod_assign(
                output,
                distribution,
                custom_modulus,
            );
    }

    pub(crate) fn try_fork(
        &mut self,
        n_child: usize,
        noise_bytes: EncryptionNoiseByteCount,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        // We try to fork the generators
        let noise_iter = self.gen.try_fork(n_child, noise_bytes.0)?;

        // We return a proper iterator.
        Ok(noise_iter.map(|gen| Self { gen }))
    }

    pub(crate) fn try_fork_from_config(
        &mut self,
        fork_config: NoiseRandomGeneratorForkConfig,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        self.try_fork(
            fork_config.children_count,
            fork_config.noise_byte_count_per_child,
        )
    }
}

impl<G: ParallelByteRandomGenerator> NoiseRandomGenerator<G> {
    // Forks both generators into a parallel iterator.
    pub(crate) fn par_try_fork(
        &mut self,
        n_child: usize,
        noise_bytes: EncryptionNoiseByteCount,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        // We try to fork the generators
        let noise_iter = self.gen.par_try_fork(n_child, noise_bytes.0)?;

        // We return a proper iterator.
        Ok(noise_iter.map(|gen| Self { gen }))
    }

    pub(crate) fn par_try_fork_from_config(
        &mut self,
        fork_config: NoiseRandomGeneratorForkConfig,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        self.par_try_fork(
            fork_config.children_count,
            fork_config.noise_byte_count_per_child,
        )
    }
}
