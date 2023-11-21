//! Module containing primitives pertaining to random noise generation in the context of encryption.

use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, Gaussian, ParallelByteRandomGenerator, RandomGenerable, RandomGenerator,
    Seed,
};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::{CastInto, UnsignedInteger};
use crate::core_crypto::commons::parameters::{
    CiphertextModulus, DecompositionLevelCount, FunctionalPackingKeyswitchKeyCount, GlweSize,
    LweBskGroupingFactor, LweCiphertextCount, LweDimension, LweMaskCount, LweSize, PolynomialSize,
};
use concrete_csprng::generators::ForkError;
use rayon::prelude::*;

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
    pub fn new(seed: Seed) -> Self {
        Self {
            gen: RandomGenerator::new(seed),
        }
    }

    pub fn remaining_bytes(&self) -> Option<usize> {
        self.gen.remaining_bytes()
    }

    // Sample a noise value, using the random generator.
    pub(crate) fn random_noise<Scalar>(&mut self, std: impl DispersionParameter) -> Scalar
    where
        Scalar: RandomGenerable<Gaussian<f64>>,
    {
        <Scalar>::generate_one(
            &mut self.gen,
            Gaussian {
                std: std.get_standard_dev(),
                mean: 0.,
            },
        )
    }

    // Sample a noise value, using the random generator.
    pub(crate) fn random_noise_custom_mod<Scalar>(
        &mut self,
        std: impl DispersionParameter,
        custom_modulus: CiphertextModulus<Scalar>,
    ) -> Scalar
    where
        Scalar: UnsignedInteger + RandomGenerable<Gaussian<f64>, CustomModulus = Scalar>,
    {
        if custom_modulus.is_native_modulus() {
            return self.random_noise(std);
        }

        let custom_modulus_as_scalar: Scalar = custom_modulus.get_custom_modulus().cast_into();
        Scalar::generate_one_custom_modulus(
            &mut self.gen,
            Gaussian {
                std: std.get_standard_dev(),
                mean: 0.,
            },
            custom_modulus_as_scalar,
        )
    }

    // Fills the input slice with random noise, using the random generator.
    pub(crate) fn fill_slice_with_random_noise<Scalar>(
        &mut self,
        output: &mut [Scalar],
        std: impl DispersionParameter,
    ) where
        Scalar: UnsignedTorus,
        (Scalar, Scalar): RandomGenerable<Gaussian<f64>>,
    {
        self.gen
            .fill_slice_with_random_gaussian(output, 0., std.get_standard_dev());
    }

    // Fills the input slice with random noise, using the random generator.
    pub(crate) fn fill_slice_with_random_noise_custom_mod<Scalar>(
        &mut self,
        output: &mut [Scalar],
        std: impl DispersionParameter,
        custom_modulus: CiphertextModulus<Scalar>,
    ) where
        Scalar: UnsignedTorus,
        (Scalar, Scalar): RandomGenerable<Gaussian<f64>, CustomModulus = Scalar>,
    {
        self.gen.fill_slice_with_random_gaussian_custom_mod(
            output,
            0.,
            std.get_standard_dev(),
            custom_modulus,
        );
    }

    // Adds noise on top of existing data for in place encryption
    pub(crate) fn unsigned_torus_slice_wrapping_add_random_noise_assign<Scalar>(
        &mut self,
        output: &mut [Scalar],
        std: impl DispersionParameter,
    ) where
        Scalar: UnsignedTorus,
        (Scalar, Scalar): RandomGenerable<Gaussian<f64>>,
    {
        self.gen
            .unsigned_torus_slice_wrapping_add_random_gaussian_assign(
                output,
                0.,
                std.get_standard_dev(),
            );
    }

    // Adds noise on top of existing data for in place encryption
    pub(crate) fn unsigned_torus_slice_wrapping_add_random_noise_custom_mod_assign<Scalar>(
        &mut self,
        output: &mut [Scalar],
        std: impl DispersionParameter,
        custom_modulus: CiphertextModulus<Scalar>,
    ) where
        Scalar: UnsignedTorus,
        (Scalar, Scalar): RandomGenerable<Gaussian<f64>, CustomModulus = Scalar>,
    {
        self.gen
            .unsigned_torus_slice_wrapping_add_random_gaussian_custom_mod_assign(
                output,
                0.,
                std.get_standard_dev(),
                custom_modulus,
            );
    }

    // Forks the generator, when splitting a bootstrap key into ggsw ct.
    pub(crate) fn fork_bsk_to_ggsw(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let noise_bytes = noise_bytes_per_ggsw(level, glwe_size, polynomial_size);
        self.try_fork(lwe_dimension.0, noise_bytes)
    }

    // Forks the generator, when splitting a multi_bit bootstrap key into ggsw ciphertext groups.
    pub(crate) fn fork_multi_bit_bsk_to_ggsw_group(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        grouping_factor: LweBskGroupingFactor,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let noise_bytes = noise_bytes_per_multi_bit_bsk_ggsw_group(
            level,
            glwe_size,
            polynomial_size,
            grouping_factor,
        );
        self.try_fork(lwe_dimension.0, noise_bytes)
    }

    // Forks the generator, when splitting a multi_bit bootstrap key ggsw ciphertext group into
    // individual ggsws.
    pub(crate) fn fork_multi_bit_bsk_ggsw_group_to_ggsw(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        grouping_factor: LweBskGroupingFactor,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let ggsw_count = grouping_factor.ggsw_per_multi_bit_element();
        let noise_bytes = noise_bytes_per_ggsw(level, glwe_size, polynomial_size);
        self.try_fork(ggsw_count.0, noise_bytes)
    }

    // Forks the generator, when splitting a ggsw into level matrices.
    pub(crate) fn fork_ggsw_to_ggsw_levels(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let noise_bytes = noise_bytes_per_ggsw_level(glwe_size, polynomial_size);
        self.try_fork(level.0, noise_bytes)
    }

    // Forks the generator, when splitting a ggsw level matrix to glwe.
    pub(crate) fn fork_ggsw_level_to_glwe(
        &mut self,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let noise_bytes = noise_bytes_per_glwe(polynomial_size);
        self.try_fork(glwe_size.0, noise_bytes)
    }

    // Forks the generator, when splitting a ggsw into level matrices.
    pub(crate) fn fork_gsw_to_gsw_levels(
        &mut self,
        level: DecompositionLevelCount,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let noise_bytes = noise_bytes_per_gsw_level(lwe_size);
        self.try_fork(level.0, noise_bytes)
    }

    // Forks the generator, when splitting a ggsw level matrix to glwe.
    pub(crate) fn fork_gsw_level_to_lwe(
        &mut self,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let noise_bytes = noise_bytes_per_lwe();
        self.try_fork(lwe_size.0, noise_bytes)
    }

    // Forks the generator, when splitting an lwe ciphertext list into ciphertexts.
    pub(crate) fn fork_lwe_list_to_lwe(
        &mut self,
        lwe_count: LweCiphertextCount,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let noise_bytes = noise_bytes_per_lwe();
        self.try_fork(lwe_count.0, noise_bytes)
    }

    // Forks the generator, when splitting a collection of pfpksk for cbs
    pub(crate) fn fork_cbs_pfpksk_to_pfpksk(
        &mut self,
        level: DecompositionLevelCount,
        poly_size: PolynomialSize,
        lwe_size: LweSize,
        pfpksk_count: FunctionalPackingKeyswitchKeyCount,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let noise_bytes = noise_bytes_per_pfpksk(level, poly_size, lwe_size);
        self.try_fork(pfpksk_count.0, noise_bytes)
    }

    // Forks the generator, when splitting a pfpksk into chunks
    pub(crate) fn fork_pfpksk_to_pfpksk_chunks(
        &mut self,
        level: DecompositionLevelCount,
        poly_size: PolynomialSize,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let noise_bytes = noise_bytes_per_pfpksk_chunk(level, poly_size);
        self.try_fork(lwe_size.0, noise_bytes)
    }

    pub(crate) fn fork_lwe_compact_ciphertext_list_to_bin(
        &mut self,
        lwe_mask_count: LweMaskCount,
        lwe_dimension: LweDimension,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let noise_bytes = noise_bytes_per_lwe_compact_ciphertext_bin(lwe_dimension);
        self.try_fork(lwe_mask_count.0, noise_bytes)
    }

    pub(crate) fn try_fork(
        &mut self,
        n_child: usize,
        noise_bytes: usize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        // We try to fork the generators
        let noise_iter = self.gen.try_fork(n_child, noise_bytes)?;

        // We return a proper iterator.
        Ok(noise_iter.map(|gen| Self { gen }))
    }
}

impl<G: ParallelByteRandomGenerator> NoiseRandomGenerator<G> {
    // Forks the generator into a parallel iterator, when splitting a bootstrap key into ggsw ct.
    pub(crate) fn par_fork_bsk_to_ggsw(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let noise_bytes = noise_bytes_per_ggsw(level, glwe_size, polynomial_size);
        self.par_try_fork(lwe_dimension.0, noise_bytes)
    }

    // Forks the generator, when splitting a multi_bit bootstrap key into ggsw ct.
    pub(crate) fn par_fork_multi_bit_bsk_to_ggsw_group(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        grouping_factor: LweBskGroupingFactor,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let noise_bytes = noise_bytes_per_multi_bit_bsk_ggsw_group(
            level,
            glwe_size,
            polynomial_size,
            grouping_factor,
        );
        self.par_try_fork(lwe_dimension.0, noise_bytes)
    }

    // Forks the generator, when splitting a multi_bit bootstrap key ggsw ciphertext group into
    // individual ggsws.
    pub(crate) fn par_fork_multi_bit_bsk_ggsw_group_to_ggsw(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        grouping_factor: LweBskGroupingFactor,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let ggsw_count = grouping_factor.ggsw_per_multi_bit_element();
        let noise_bytes = noise_bytes_per_ggsw(level, glwe_size, polynomial_size);
        self.par_try_fork(ggsw_count.0, noise_bytes)
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw into level matrices.
    pub(crate) fn par_fork_ggsw_to_ggsw_levels(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let noise_bytes = noise_bytes_per_ggsw_level(glwe_size, polynomial_size);
        self.par_try_fork(level.0, noise_bytes)
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw level matrix to glwe.
    pub(crate) fn par_fork_ggsw_level_to_glwe(
        &mut self,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let noise_bytes = noise_bytes_per_glwe(polynomial_size);
        self.par_try_fork(glwe_size.0, noise_bytes)
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw into level matrices.
    pub(crate) fn par_fork_gsw_to_gsw_levels(
        &mut self,
        level: DecompositionLevelCount,
        lwe_size: LweSize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let noise_bytes = noise_bytes_per_gsw_level(lwe_size);
        self.par_try_fork(level.0, noise_bytes)
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw level matrix to glwe.
    pub(crate) fn par_fork_gsw_level_to_lwe(
        &mut self,
        lwe_size: LweSize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let noise_bytes = noise_bytes_per_lwe();
        self.par_try_fork(lwe_size.0, noise_bytes)
    }

    // Forks the generator, when splitting an lwe ciphertext list into ciphertexts.
    pub(crate) fn par_fork_lwe_list_to_lwe(
        &mut self,
        lwe_count: LweCiphertextCount,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let noise_bytes = noise_bytes_per_lwe();
        self.par_try_fork(lwe_count.0, noise_bytes)
    }

    // Forks the generator, when splitting a collection of pfpksk for cbs
    pub(crate) fn par_fork_cbs_pfpksk_to_pfpksk(
        &mut self,
        level: DecompositionLevelCount,
        poly_size: PolynomialSize,
        lwe_size: LweSize,
        pfpksk_count: FunctionalPackingKeyswitchKeyCount,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let noise_bytes = noise_bytes_per_pfpksk(level, poly_size, lwe_size);
        self.par_try_fork(pfpksk_count.0, noise_bytes)
    }

    // Forks the generator, when splitting a pfpksk into chunks
    pub(crate) fn par_fork_pfpksk_to_pfpksk_chunks(
        &mut self,
        level: DecompositionLevelCount,
        poly_size: PolynomialSize,
        lwe_size: LweSize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let noise_bytes = noise_bytes_per_pfpksk_chunk(level, poly_size);
        self.par_try_fork(lwe_size.0, noise_bytes)
    }

    pub(crate) fn par_fork_lwe_compact_ciphertext_list_to_bin(
        &mut self,
        lwe_mask_count: LweMaskCount,
        lwe_dimension: LweDimension,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let noise_bytes = noise_bytes_per_lwe_compact_ciphertext_bin(lwe_dimension);
        self.par_try_fork(lwe_mask_count.0, noise_bytes)
    }

    // Forks both generators into a parallel iterator.
    pub(crate) fn par_try_fork(
        &mut self,
        n_child: usize,
        noise_bytes: usize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        // We try to fork the generators
        let noise_iter = self.gen.par_try_fork(n_child, noise_bytes)?;

        // We return a proper iterator.
        Ok(noise_iter.map(|gen| Self { gen }))
    }
}

fn noise_bytes_per_coef() -> usize {
    // We use f64 to sample the noise for every precision, and we need 4/pi inputs to generate
    // such an output (here we take 32 to keep a safety margin).
    8 * 32
}
fn noise_bytes_per_polynomial(poly_size: PolynomialSize) -> usize {
    poly_size.0 * noise_bytes_per_coef()
}

fn noise_bytes_per_glwe(poly_size: PolynomialSize) -> usize {
    noise_bytes_per_polynomial(poly_size)
}

fn noise_bytes_per_ggsw_level(glwe_size: GlweSize, poly_size: PolynomialSize) -> usize {
    glwe_size.0 * noise_bytes_per_glwe(poly_size)
}

fn noise_bytes_per_lwe() -> usize {
    // Here we take 3 to keep a safety margin
    noise_bytes_per_coef() * 3
}

fn noise_bytes_per_gsw_level(lwe_size: LweSize) -> usize {
    lwe_size.0 * noise_bytes_per_lwe()
}

fn noise_bytes_per_multi_bit_bsk_ggsw_group(
    level: DecompositionLevelCount,
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
    grouping_factor: LweBskGroupingFactor,
) -> usize {
    grouping_factor.ggsw_per_multi_bit_element().0
        * noise_bytes_per_ggsw(level, glwe_size, poly_size)
}

fn noise_bytes_per_ggsw(
    level: DecompositionLevelCount,
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
) -> usize {
    level.0 * noise_bytes_per_ggsw_level(glwe_size, poly_size)
}

fn noise_bytes_per_pfpksk_chunk(
    level: DecompositionLevelCount,
    poly_size: PolynomialSize,
) -> usize {
    level.0 * noise_bytes_per_glwe(poly_size)
}

fn noise_bytes_per_pfpksk(
    level: DecompositionLevelCount,
    poly_size: PolynomialSize,
    lwe_size: LweSize,
) -> usize {
    lwe_size.0 * noise_bytes_per_pfpksk_chunk(level, poly_size)
}

fn noise_bytes_per_lwe_compact_ciphertext_bin(lwe_dimension: LweDimension) -> usize {
    lwe_dimension.0 * noise_bytes_per_coef()
}
