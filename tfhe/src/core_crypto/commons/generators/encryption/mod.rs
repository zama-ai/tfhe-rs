//! Module containing primitives pertaining to random generation in the context of encryption.

pub(crate) mod mask_random_generator;
#[cfg(test)]
mod test;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, Gaussian, ParallelByteRandomGenerator, RandomGenerable, RandomGenerator,
    Seed, Seeder, Uniform,
};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::{CastInto, UnsignedInteger};
use crate::core_crypto::commons::parameters::{
    CiphertextModulus, DecompositionLevelCount, FunctionalPackingKeyswitchKeyCount, GlweSize,
    LweBskGroupingFactor, LweCiphertextCount, LweDimension, LweMaskCount, LweSize, PolynomialSize,
};
use concrete_csprng::generators::ForkError;
use mask_random_generator::MaskRandomGenerator;
use rayon::prelude::*;

/// A random number generator which can be used to encrypt messages.
pub struct EncryptionRandomGenerator<G: ByteRandomGenerator> {
    // A separate mask generator, only used to generate the mask elements.
    mask: MaskRandomGenerator<G>,
    // A separate noise generator, only used to generate the noise elements.
    noise: RandomGenerator<G>,
}

impl<G: ByteRandomGenerator> EncryptionRandomGenerator<G> {
    /// Create a new [`EncryptionRandomGenerator`], using the provided [`Seed`] to seed the public
    /// mask generator and using the provided [`Seeder`] to privately seed the noise generator.
    // S is ?Sized to allow Box<dyn Seeder> to be passed.
    pub fn new<S: Seeder + ?Sized>(seed: Seed, seeder: &mut S) -> EncryptionRandomGenerator<G> {
        EncryptionRandomGenerator {
            mask: MaskRandomGenerator::new(seed),
            noise: RandomGenerator::new(seeder.seed()),
        }
    }

    // Allows to seed the noise generator. For testing purpose only.
    #[cfg(test)]
    pub(crate) fn seed_noise_generator(&mut self, seed: Seed) {
        println!("WARNING: The noise generator of the encryption random generator was seeded.");
        self.noise = RandomGenerator::new(seed);
    }

    /// Return the number of remaining bytes for the mask generator, if the generator is bounded.
    pub fn remaining_bytes(&self) -> Option<usize> {
        self.mask.remaining_bytes()
    }

    // Forks the generator, when splitting a bootstrap key into ggsw ct.
    pub(crate) fn fork_bsk_to_ggsw<T: UnsignedInteger>(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_iter =
            self.mask
                .fork_bsk_to_ggsw::<T>(lwe_dimension, level, glwe_size, polynomial_size)?;
        let noise_bytes = noise_bytes_per_ggsw(level, glwe_size, polynomial_size);
        self.try_fork(lwe_dimension.0, mask_iter, noise_bytes)
    }

    // Forks the generator, when splitting a multi_bit bootstrap key into ggsw ciphertext groups.
    pub(crate) fn fork_multi_bit_bsk_to_ggsw_group<T: UnsignedInteger>(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        grouping_factor: LweBskGroupingFactor,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_iter = self.mask.fork_multi_bit_bsk_to_ggsw_group::<T>(
            lwe_dimension,
            level,
            glwe_size,
            polynomial_size,
            grouping_factor,
        )?;
        let noise_bytes = noise_bytes_per_multi_bit_bsk_ggsw_group(
            level,
            glwe_size,
            polynomial_size,
            grouping_factor,
        );
        self.try_fork(lwe_dimension.0, mask_iter, noise_bytes)
    }

    // Forks the generator, when splitting a multi_bit bootstrap key ggsw ciphertext group into
    // individual ggsws.
    pub(crate) fn fork_multi_bit_bsk_ggsw_group_to_ggsw<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        grouping_factor: LweBskGroupingFactor,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let ggsw_count = grouping_factor.ggsw_per_multi_bit_element();
        let mask_iter = self.mask.fork_multi_bit_bsk_ggsw_group_to_ggsw::<T>(
            level,
            glwe_size,
            polynomial_size,
            grouping_factor,
        )?;
        let noise_bytes = noise_bytes_per_ggsw(level, glwe_size, polynomial_size);
        self.try_fork(ggsw_count.0, mask_iter, noise_bytes)
    }

    // Forks the generator, when splitting a ggsw into level matrices.
    pub(crate) fn fork_ggsw_to_ggsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_iter =
            self.mask
                .fork_ggsw_to_ggsw_levels::<T>(level, glwe_size, polynomial_size)?;
        let noise_bytes = noise_bytes_per_ggsw_level(glwe_size, polynomial_size);
        self.try_fork(level.0, mask_iter, noise_bytes)
    }

    // Forks the generator, when splitting a ggsw level matrix to glwe.
    pub(crate) fn fork_ggsw_level_to_glwe<T: UnsignedInteger>(
        &mut self,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_iter = self
            .mask
            .fork_ggsw_level_to_glwe::<T>(glwe_size, polynomial_size)?;
        let noise_bytes = noise_bytes_per_glwe(polynomial_size);
        self.try_fork(glwe_size.0, mask_iter, noise_bytes)
    }

    // Forks the generator, when splitting a ggsw into level matrices.
    pub(crate) fn fork_gsw_to_gsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_iter = self.mask.fork_gsw_to_gsw_levels::<T>(level, lwe_size)?;
        let noise_bytes = noise_bytes_per_gsw_level(lwe_size);
        self.try_fork(level.0, mask_iter, noise_bytes)
    }

    // Forks the generator, when splitting a ggsw level matrix to glwe.
    pub(crate) fn fork_gsw_level_to_lwe<T: UnsignedInteger>(
        &mut self,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_iter = self.mask.fork_gsw_level_to_lwe::<T>(lwe_size)?;
        let noise_bytes = noise_bytes_per_lwe();
        self.try_fork(lwe_size.0, mask_iter, noise_bytes)
    }

    // Forks the generator, when splitting an lwe ciphertext list into ciphertexts.
    pub(crate) fn fork_lwe_list_to_lwe<T: UnsignedInteger>(
        &mut self,
        lwe_count: LweCiphertextCount,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_iter = self.mask.fork_lwe_list_to_lwe::<T>(lwe_count, lwe_size)?;
        let noise_bytes = noise_bytes_per_lwe();
        self.try_fork(lwe_count.0, mask_iter, noise_bytes)
    }

    // Forks the generator, when splitting a collection of pfpksk for cbs
    pub(crate) fn fork_cbs_pfpksk_to_pfpksk<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        lwe_size: LweSize,
        pfpksk_count: FunctionalPackingKeyswitchKeyCount,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_iter = self.mask.fork_cbs_pfpksk_to_pfpksk::<T>(
            level,
            glwe_size,
            poly_size,
            lwe_size,
            pfpksk_count,
        )?;
        let noise_bytes = noise_bytes_per_pfpksk(level, poly_size, lwe_size);
        self.try_fork(pfpksk_count.0, mask_iter, noise_bytes)
    }

    // Forks the generator, when splitting a pfpksk into chunks
    pub(crate) fn fork_pfpksk_to_pfpksk_chunks<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_iter = self
            .mask
            .fork_pfpksk_to_pfpksk_chunks::<T>(level, glwe_size, poly_size, lwe_size)?;
        let noise_bytes = noise_bytes_per_pfpksk_chunk(level, poly_size);
        self.try_fork(lwe_size.0, mask_iter, noise_bytes)
    }

    pub(crate) fn fork_lwe_compact_ciphertext_list_to_bin<T: UnsignedInteger>(
        &mut self,
        lwe_mask_count: LweMaskCount,
        lwe_dimension: LweDimension,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_iter = self
            .mask
            .fork_lwe_compact_ciphertext_list_to_bin::<T>(lwe_mask_count, lwe_dimension)?;
        let noise_bytes = noise_bytes_per_lwe_compact_ciphertext_bin(lwe_dimension);
        self.try_fork(lwe_mask_count.0, mask_iter, noise_bytes)
    }

    // Forks both generators into an iterator
    fn try_fork(
        &mut self,
        n_child: usize,
        mask_iter: impl Iterator<Item = MaskRandomGenerator<G>>,
        noise_bytes: usize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        // We try to fork the generators
        let noise_iter = self.noise.try_fork(n_child, noise_bytes)?;

        // We return a proper iterator.
        Ok(mask_iter
            .zip(noise_iter)
            .map(|(mask, noise)| EncryptionRandomGenerator { mask, noise }))
    }

    // Fills the slice with random uniform values, using the mask generator.
    pub(crate) fn fill_slice_with_random_mask<Scalar>(&mut self, output: &mut [Scalar])
    where
        Scalar: RandomGenerable<Uniform>,
    {
        self.mask.fill_slice_with_random_mask(output)
    }

    // Fills the slice with random uniform values, using the mask generator
    pub(crate) fn fill_slice_with_random_mask_custom_mod<Scalar>(
        &mut self,
        output: &mut [Scalar],
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) where
        Scalar: UnsignedInteger + RandomGenerable<Uniform>,
    {
        self.mask
            .fill_slice_with_random_mask_custom_mod(output, ciphertext_modulus);
    }

    // Sample a noise value, using the noise generator.
    pub(crate) fn random_noise<Scalar>(&mut self, std: impl DispersionParameter) -> Scalar
    where
        Scalar: RandomGenerable<Gaussian<f64>>,
    {
        <Scalar>::generate_one(
            &mut self.noise,
            Gaussian {
                std: std.get_standard_dev(),
                mean: 0.,
            },
        )
    }

    // Sample a noise value, using the noise generator.
    pub(crate) fn random_noise_custom_mod<Scalar>(
        &mut self,
        std: impl DispersionParameter,
        custom_modulus: CiphertextModulus<Scalar>,
    ) -> Scalar
    where
        Scalar: UnsignedInteger + RandomGenerable<Gaussian<f64>, CustomModulus = f64>,
    {
        if custom_modulus.is_native_modulus() {
            return self.random_noise(std);
        }

        let custom_modulus_f64: f64 = custom_modulus.get_custom_modulus().cast_into();
        Scalar::generate_one_custom_modulus(
            &mut self.noise,
            Gaussian {
                std: std.get_standard_dev(),
                mean: 0.,
            },
            custom_modulus_f64,
        )
    }

    // Fills the input slice with random noise, using the noise generator.
    pub(crate) fn fill_slice_with_random_noise<Scalar>(
        &mut self,
        output: &mut [Scalar],
        std: impl DispersionParameter,
    ) where
        (Scalar, Scalar): RandomGenerable<Gaussian<f64>>,
    {
        self.noise
            .fill_slice_with_random_gaussian(output, 0., std.get_standard_dev());
    }

    // Fills the input slice with random noise, using the noise generator.
    pub(crate) fn fill_slice_with_random_noise_custom_mod<Scalar>(
        &mut self,
        output: &mut [Scalar],
        std: impl DispersionParameter,
        custom_modulus: CiphertextModulus<Scalar>,
    ) where
        Scalar: UnsignedInteger,
        (Scalar, Scalar): RandomGenerable<Gaussian<f64>, CustomModulus = f64>,
    {
        self.noise.fill_slice_with_random_gaussian_custom_mod(
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
        self.noise
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
        (Scalar, Scalar): RandomGenerable<Gaussian<f64>, CustomModulus = f64>,
    {
        self.noise
            .unsigned_torus_slice_wrapping_add_random_gaussian_custom_mod_assign(
                output,
                0.,
                std.get_standard_dev(),
                custom_modulus,
            );
    }
}

impl<G: ParallelByteRandomGenerator> EncryptionRandomGenerator<G> {
    // Forks the generator into a parallel iterator, when splitting a bootstrap key into ggsw ct.
    pub(crate) fn par_fork_bsk_to_ggsw<T: UnsignedInteger>(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_iter = self.mask.par_fork_bsk_to_ggsw::<T>(
            lwe_dimension,
            level,
            glwe_size,
            polynomial_size,
        )?;
        let noise_bytes = noise_bytes_per_ggsw(level, glwe_size, polynomial_size);
        self.par_try_fork(lwe_dimension.0, mask_iter, noise_bytes)
    }

    // Forks the generator, when splitting a multi_bit bootstrap key into ggsw ct.
    pub(crate) fn par_fork_multi_bit_bsk_to_ggsw_group<T: UnsignedInteger>(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        grouping_factor: LweBskGroupingFactor,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_iter = self.mask.par_fork_multi_bit_bsk_to_ggsw_group::<T>(
            lwe_dimension,
            level,
            glwe_size,
            polynomial_size,
            grouping_factor,
        )?;
        let noise_bytes = noise_bytes_per_multi_bit_bsk_ggsw_group(
            level,
            glwe_size,
            polynomial_size,
            grouping_factor,
        );
        self.par_try_fork(lwe_dimension.0, mask_iter, noise_bytes)
    }

    // Forks the generator, when splitting a multi_bit bootstrap key ggsw ciphertext group into
    // individual ggsws.
    pub(crate) fn par_fork_multi_bit_bsk_ggsw_group_to_ggsw<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        grouping_factor: LweBskGroupingFactor,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let ggsw_count = grouping_factor.ggsw_per_multi_bit_element();
        let mask_iter = self.mask.par_fork_multi_bit_bsk_ggsw_group_to_ggsw::<T>(
            level,
            glwe_size,
            polynomial_size,
            grouping_factor,
        )?;
        let noise_bytes = noise_bytes_per_ggsw(level, glwe_size, polynomial_size);
        self.par_try_fork(ggsw_count.0, mask_iter, noise_bytes)
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw into level matrices.
    pub(crate) fn par_fork_ggsw_to_ggsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_iter =
            self.mask
                .par_fork_ggsw_to_ggsw_levels::<T>(level, glwe_size, polynomial_size)?;
        let noise_bytes = noise_bytes_per_ggsw_level(glwe_size, polynomial_size);
        self.par_try_fork(level.0, mask_iter, noise_bytes)
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw level matrix to glwe.
    pub(crate) fn par_fork_ggsw_level_to_glwe<T: UnsignedInteger>(
        &mut self,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_iter = self
            .mask
            .par_fork_ggsw_level_to_glwe::<T>(glwe_size, polynomial_size)?;
        let noise_bytes = noise_bytes_per_glwe(polynomial_size);
        self.par_try_fork(glwe_size.0, mask_iter, noise_bytes)
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw into level matrices.
    pub(crate) fn par_fork_gsw_to_gsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        lwe_size: LweSize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_iter = self.mask.par_fork_gsw_to_gsw_levels::<T>(level, lwe_size)?;
        let noise_bytes = noise_bytes_per_gsw_level(lwe_size);
        self.par_try_fork(level.0, mask_iter, noise_bytes)
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw level matrix to glwe.
    pub(crate) fn par_fork_gsw_level_to_lwe<T: UnsignedInteger>(
        &mut self,
        lwe_size: LweSize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_iter = self.mask.par_fork_gsw_level_to_lwe::<T>(lwe_size)?;
        let noise_bytes = noise_bytes_per_lwe();
        self.par_try_fork(lwe_size.0, mask_iter, noise_bytes)
    }

    // Forks the generator, when splitting an lwe ciphertext list into ciphertexts.
    pub(crate) fn par_fork_lwe_list_to_lwe<T: UnsignedInteger>(
        &mut self,
        lwe_count: LweCiphertextCount,
        lwe_size: LweSize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_iter = self
            .mask
            .par_fork_lwe_list_to_lwe::<T>(lwe_count, lwe_size)?;
        let noise_bytes = noise_bytes_per_lwe();
        self.par_try_fork(lwe_count.0, mask_iter, noise_bytes)
    }

    // Forks the generator, when splitting a collection of pfpksk for cbs
    pub(crate) fn par_fork_cbs_pfpksk_to_pfpksk<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        lwe_size: LweSize,
        pfpksk_count: FunctionalPackingKeyswitchKeyCount,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_iter = self.mask.par_fork_cbs_pfpksk_to_pfpksk::<T>(
            level,
            glwe_size,
            poly_size,
            lwe_size,
            pfpksk_count,
        )?;
        let noise_bytes = noise_bytes_per_pfpksk(level, poly_size, lwe_size);
        self.par_try_fork(pfpksk_count.0, mask_iter, noise_bytes)
    }

    // Forks the generator, when splitting a pfpksk into chunks
    pub(crate) fn par_fork_pfpksk_to_pfpksk_chunks<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        lwe_size: LweSize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_iter = self
            .mask
            .par_fork_pfpksk_to_pfpksk_chunks::<T>(level, glwe_size, poly_size, lwe_size)?;
        let noise_bytes = noise_bytes_per_pfpksk_chunk(level, poly_size);
        self.par_try_fork(lwe_size.0, mask_iter, noise_bytes)
    }

    pub(crate) fn par_fork_lwe_compact_ciphertext_list_to_bin<T: UnsignedInteger>(
        &mut self,
        lwe_mask_count: LweMaskCount,
        lwe_dimension: LweDimension,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_iter = self
            .mask
            .par_fork_lwe_compact_ciphertext_list_to_bin::<T>(lwe_mask_count, lwe_dimension)?;
        let noise_bytes = noise_bytes_per_lwe_compact_ciphertext_bin(lwe_dimension);
        self.par_try_fork(lwe_mask_count.0, mask_iter, noise_bytes)
    }

    // Forks both generators into a parallel iterator.
    fn par_try_fork(
        &mut self,
        n_child: usize,
        mask_iter: impl IndexedParallelIterator<Item = MaskRandomGenerator<G>>,
        noise_bytes: usize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        // We try to fork the generators
        let noise_iter = self.noise.par_try_fork(n_child, noise_bytes)?;

        // We return a proper iterator.
        Ok(mask_iter
            .zip(noise_iter)
            .map(|(mask, noise)| EncryptionRandomGenerator { mask, noise }))
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
