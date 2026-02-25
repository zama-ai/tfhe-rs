//! Module containing primitives pertaining to random generation in the context of encryption.

pub(crate) mod mask_random_generator;
pub(crate) mod noise_random_generator;
#[cfg(test)]
mod test;

use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, Distribution, ParallelByteRandomGenerator, RandomGenerable, Seeder,
    Uniform,
};
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::{
    CiphertextModulus, EncryptionMaskByteCount, EncryptionMaskSampleCount,
    EncryptionNoiseByteCount, EncryptionNoiseSampleCount,
};
use mask_random_generator::{MaskRandomGenerator, MaskRandomGeneratorForkConfig};
use noise_random_generator::{NoiseRandomGenerator, NoiseRandomGeneratorForkConfig};
use rayon::prelude::*;
use tfhe_csprng::generators::aes_ctr::AesCtrParams;
use tfhe_csprng::generators::ForkError;

pub const PER_SAMPLE_TARGET_FAILURE_PROBABILITY_LOG2: f64 = -128.;

#[derive(Clone, Copy, Debug)]
pub struct EncryptionRandomGeneratorForkConfig {
    mask_random_generator_fork_config: MaskRandomGeneratorForkConfig,
    noise_random_generator_fork_config: NoiseRandomGeneratorForkConfig,
}

impl EncryptionRandomGeneratorForkConfig {
    pub fn new<Scalar, MaskDistribution, NoiseDistribution>(
        children_count: usize,
        mask_element_per_child_count: EncryptionMaskSampleCount,
        mask_distribution: MaskDistribution,
        noise_element_per_child_count: EncryptionNoiseSampleCount,
        noise_distribution: NoiseDistribution,
        modulus: Option<Scalar>,
    ) -> Self
    where
        MaskDistribution: Distribution,
        NoiseDistribution: Distribution,
        Scalar: Copy
            + RandomGenerable<MaskDistribution, CustomModulus = Scalar>
            + RandomGenerable<NoiseDistribution, CustomModulus = Scalar>,
    {
        let mask_random_generator_fork_config = MaskRandomGeneratorForkConfig::new(
            children_count,
            mask_element_per_child_count,
            mask_distribution,
            modulus,
        );

        let noise_random_generator_fork_config = NoiseRandomGeneratorForkConfig::new(
            children_count,
            noise_element_per_child_count,
            noise_distribution,
            modulus,
        );

        Self {
            mask_random_generator_fork_config,
            noise_random_generator_fork_config,
        }
    }

    pub fn children_count(&self) -> usize {
        self.mask_random_generator_fork_config.children_count()
    }

    pub fn mask_byte_count_per_child(&self) -> EncryptionMaskByteCount {
        self.mask_random_generator_fork_config
            .mask_byte_count_per_child()
    }

    pub fn noise_byte_count_per_child(&self) -> EncryptionNoiseByteCount {
        self.noise_random_generator_fork_config
            .noise_byte_count_per_child()
    }

    pub fn mask_random_generator_fork_config(&self) -> MaskRandomGeneratorForkConfig {
        self.mask_random_generator_fork_config
    }

    pub fn noise_random_generator_fork_config(&self) -> NoiseRandomGeneratorForkConfig {
        self.noise_random_generator_fork_config
    }
}

/// A random number generator which can be used to encrypt messages.
pub struct EncryptionRandomGenerator<G: ByteRandomGenerator> {
    // A separate mask generator, only used to generate the mask elements.
    mask: MaskRandomGenerator<G>,
    // A separate noise generator, only used to generate the noise samples.
    noise: NoiseRandomGenerator<G>,
}

impl<G: ByteRandomGenerator> EncryptionRandomGenerator<G> {
    /// Create a new [`EncryptionRandomGenerator`], using the provided seed to seed the public
    /// mask generator and using the provided [`Seeder`] to privately seed the noise generator.
    ///
    /// Accepts any type that converts to [`AesCtrParams`], including [`Seed`], [`XofSeed`],
    /// [`SeedKind`], and [`CompressionSeed`].
    ///
    /// [`Seed`]: crate::core_crypto::commons::math::random::Seed
    /// [`XofSeed`]: crate::core_crypto::commons::math::random::XofSeed
    /// [`SeedKind`]: tfhe_csprng::seeders::SeedKind
    /// [`CompressionSeed`]: crate::core_crypto::commons::math::random::CompressionSeed
    // S is ?Sized to allow Box<dyn Seeder> to be passed.
    pub fn new<S: Seeder + ?Sized>(params: impl Into<AesCtrParams>, seeder: &mut S) -> Self {
        Self {
            mask: MaskRandomGenerator::new(params),
            noise: NoiseRandomGenerator::new(seeder),
        }
    }

    #[cfg(feature = "integer")]
    pub(crate) fn from_raw_parts(
        mask: MaskRandomGenerator<G>,
        noise: NoiseRandomGenerator<G>,
    ) -> Self {
        Self { mask, noise }
    }

    /// Return the number of remaining bytes for the mask generator, if the generator is bounded.
    pub fn remaining_bytes(&self) -> Option<usize> {
        self.mask.remaining_bytes()
    }

    pub fn noise_generator_mut(&mut self) -> &mut NoiseRandomGenerator<G> {
        &mut self.noise
    }

    pub fn mask_generator(&self) -> &MaskRandomGenerator<G> {
        &self.mask
    }

    pub fn mask_generator_mut(&mut self) -> &mut MaskRandomGenerator<G> {
        &mut self.mask
    }

    pub fn try_fork_from_config(
        &mut self,
        fork_config: EncryptionRandomGeneratorForkConfig,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let EncryptionRandomGeneratorForkConfig {
            mask_random_generator_fork_config,
            noise_random_generator_fork_config,
        } = fork_config;

        let mask_iter = self
            .mask
            .try_fork_from_config(mask_random_generator_fork_config)?;
        let noise_iter = self
            .noise
            .try_fork_from_config(noise_random_generator_fork_config)?;
        Ok(mask_iter
            .zip(noise_iter)
            .map(|(mask, noise)| Self { mask, noise }))
    }

    // Fills the slice with random uniform values, using the mask generator.
    pub(crate) fn fill_slice_with_random_uniform_mask<Scalar>(&mut self, output: &mut [Scalar])
    where
        Scalar: RandomGenerable<Uniform>,
    {
        self.mask.fill_slice_with_random_uniform_mask(output);
    }

    // Fills the slice with random uniform values, using the mask generator
    pub(crate) fn fill_slice_with_random_uniform_mask_custom_mod<Scalar>(
        &mut self,
        output: &mut [Scalar],
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) where
        Scalar: UnsignedInteger + RandomGenerable<Uniform, CustomModulus = Scalar>,
    {
        self.mask
            .fill_slice_with_random_uniform_mask_custom_mod(output, ciphertext_modulus);
    }

    pub(crate) fn random_noise_from_distribution<D, Scalar>(&mut self, distribution: D) -> Scalar
    where
        D: Distribution,
        Scalar: RandomGenerable<D>,
    {
        self.noise.random_noise_from_distribution(distribution)
    }

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
            self.noise
                .random_noise_from_distribution_custom_mod(distribution, custom_modulus)
        }
    }

    // Fills the input slice with random noise, using the random generator.
    #[cfg(test)]
    pub(crate) fn fill_slice_with_random_noise_from_distribution<D, Scalar>(
        &mut self,
        output: &mut [Scalar],
        distribution: D,
    ) where
        D: Distribution,
        Scalar: RandomGenerable<D>,
    {
        self.noise
            .fill_slice_with_random_noise_from_distribution(output, distribution);
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
        self.noise
            .fill_slice_with_random_noise_from_distribution_custom_mod(
                output,
                distribution,
                custom_modulus,
            );
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
        self.noise
            .unsigned_integer_slice_wrapping_add_random_noise_from_distribution_assign(
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
        self.noise
            .unsigned_integer_slice_wrapping_add_random_noise_from_distribution_custom_mod_assign(
                output,
                distribution,
                custom_modulus,
            );
    }
}

impl<G: ParallelByteRandomGenerator> EncryptionRandomGenerator<G> {
    pub fn par_try_fork_from_config(
        &mut self,
        fork_config: EncryptionRandomGeneratorForkConfig,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let EncryptionRandomGeneratorForkConfig {
            mask_random_generator_fork_config,
            noise_random_generator_fork_config,
        } = fork_config;

        let mask_iter = self
            .mask
            .par_try_fork_from_config(mask_random_generator_fork_config)?;
        let noise_iter = self
            .noise
            .par_try_fork_from_config(noise_random_generator_fork_config)?;
        Ok(mask_iter
            .zip(noise_iter)
            .map(|(mask, noise)| Self { mask, noise }))
    }
}
