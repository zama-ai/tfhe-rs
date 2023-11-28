//! Module containing primitives pertaining to random generation in the context of encryption.

pub(crate) mod mask_random_generator;
pub(crate) mod noise_random_generator;
#[cfg(test)]
mod test;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, Gaussian, ParallelByteRandomGenerator, RandomGenerable, Seed, Seeder,
    Uniform,
};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::{
    CiphertextModulus, DecompositionLevelCount, FunctionalPackingKeyswitchKeyCount, GlweSize,
    LweBskGroupingFactor, LweCiphertextCount, LweDimension, LweMaskCount, LweSize, PolynomialSize,
};
use concrete_csprng::generators::ForkError;
use mask_random_generator::MaskRandomGenerator;
use noise_random_generator::NoiseRandomGenerator;
use rayon::prelude::*;

/// A random number generator which can be used to encrypt messages.
pub struct EncryptionRandomGenerator<G: ByteRandomGenerator> {
    // A separate mask generator, only used to generate the mask elements.
    mask: MaskRandomGenerator<G>,
    // A separate noise generator, only used to generate the noise elements.
    noise: NoiseRandomGenerator<G>,
}

impl<G: ByteRandomGenerator> EncryptionRandomGenerator<G> {
    /// Create a new [`EncryptionRandomGenerator`], using the provided [`Seed`] to seed the public
    /// mask generator and using the provided [`Seeder`] to privately seed the noise generator.
    // S is ?Sized to allow Box<dyn Seeder> to be passed.
    pub fn new<S: Seeder + ?Sized>(seed: Seed, seeder: &mut S) -> Self {
        Self {
            mask: MaskRandomGenerator::new(seed),
            noise: NoiseRandomGenerator::new(seeder.seed()),
        }
    }

    // Allows to seed the noise generator. For testing purpose only.
    #[cfg(test)]
    pub(crate) fn seed_noise_generator(&mut self, seed: Seed) {
        println!("WARNING: The noise generator of the encryption random generator was seeded.");
        self.noise = NoiseRandomGenerator::new(seed);
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
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_iter =
            self.mask
                .fork_bsk_to_ggsw::<T>(lwe_dimension, level, glwe_size, polynomial_size)?;
        let noise_iter =
            self.noise
                .fork_bsk_to_ggsw(lwe_dimension, level, glwe_size, polynomial_size)?;
        Ok(map_to_encryption_generator(mask_iter, noise_iter))
    }

    // Forks the generator, when splitting a multi_bit bootstrap key into ggsw ciphertext groups.
    pub(crate) fn fork_multi_bit_bsk_to_ggsw_group<T: UnsignedInteger>(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        grouping_factor: LweBskGroupingFactor,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_iter = self.mask.fork_multi_bit_bsk_to_ggsw_group::<T>(
            lwe_dimension,
            level,
            glwe_size,
            polynomial_size,
            grouping_factor,
        )?;
        let noise_iter = self.noise.fork_multi_bit_bsk_to_ggsw_group(
            lwe_dimension,
            level,
            glwe_size,
            polynomial_size,
            grouping_factor,
        )?;
        Ok(map_to_encryption_generator(mask_iter, noise_iter))
    }

    // Forks the generator, when splitting a multi_bit bootstrap key ggsw ciphertext group into
    // individual ggsws.
    pub(crate) fn fork_multi_bit_bsk_ggsw_group_to_ggsw<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        grouping_factor: LweBskGroupingFactor,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_iter = self.mask.fork_multi_bit_bsk_ggsw_group_to_ggsw::<T>(
            level,
            glwe_size,
            polynomial_size,
            grouping_factor,
        )?;
        let noise_iter = self.noise.fork_multi_bit_bsk_ggsw_group_to_ggsw(
            level,
            glwe_size,
            polynomial_size,
            grouping_factor,
        )?;
        Ok(map_to_encryption_generator(mask_iter, noise_iter))
    }

    // Forks the generator, when splitting a ggsw into level matrices.
    pub(crate) fn fork_ggsw_to_ggsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_iter =
            self.mask
                .fork_ggsw_to_ggsw_levels::<T>(level, glwe_size, polynomial_size)?;
        let noise_iter = self
            .noise
            .fork_ggsw_to_ggsw_levels(level, glwe_size, polynomial_size)?;
        Ok(map_to_encryption_generator(mask_iter, noise_iter))
    }

    // Forks the generator, when splitting a ggsw level matrix to glwe.
    pub(crate) fn fork_ggsw_level_to_glwe<T: UnsignedInteger>(
        &mut self,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_iter = self
            .mask
            .fork_ggsw_level_to_glwe::<T>(glwe_size, polynomial_size)?;
        let noise_iter = self
            .noise
            .fork_ggsw_level_to_glwe(glwe_size, polynomial_size)?;
        Ok(map_to_encryption_generator(mask_iter, noise_iter))
    }

    // Forks the generator, when splitting a ggsw into level matrices.
    pub(crate) fn fork_gsw_to_gsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_iter = self.mask.fork_gsw_to_gsw_levels::<T>(level, lwe_size)?;
        let noise_iter = self.noise.fork_gsw_to_gsw_levels(level, lwe_size)?;
        Ok(map_to_encryption_generator(mask_iter, noise_iter))
    }

    // Forks the generator, when splitting a ggsw level matrix to glwe.
    pub(crate) fn fork_gsw_level_to_lwe<T: UnsignedInteger>(
        &mut self,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_iter = self.mask.fork_gsw_level_to_lwe::<T>(lwe_size)?;
        let noise_iter = self.noise.fork_gsw_level_to_lwe(lwe_size)?;
        Ok(map_to_encryption_generator(mask_iter, noise_iter))
    }

    // Forks the generator, when splitting an lwe ciphertext list into ciphertexts.
    pub(crate) fn fork_lwe_list_to_lwe<T: UnsignedInteger>(
        &mut self,
        lwe_count: LweCiphertextCount,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_iter = self.mask.fork_lwe_list_to_lwe::<T>(lwe_count, lwe_size)?;
        let noise_iter = self.noise.fork_lwe_list_to_lwe(lwe_count)?;
        Ok(map_to_encryption_generator(mask_iter, noise_iter))
    }

    // Forks the generator, when splitting a collection of pfpksk for cbs
    pub(crate) fn fork_cbs_pfpksk_to_pfpksk<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        lwe_size: LweSize,
        pfpksk_count: FunctionalPackingKeyswitchKeyCount,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_iter = self.mask.fork_cbs_pfpksk_to_pfpksk::<T>(
            level,
            glwe_size,
            poly_size,
            lwe_size,
            pfpksk_count,
        )?;
        let noise_iter =
            self.noise
                .fork_cbs_pfpksk_to_pfpksk(level, poly_size, lwe_size, pfpksk_count)?;
        Ok(map_to_encryption_generator(mask_iter, noise_iter))
    }

    // Forks the generator, when splitting a pfpksk into chunks
    pub(crate) fn fork_pfpksk_to_pfpksk_chunks<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_iter = self
            .mask
            .fork_pfpksk_to_pfpksk_chunks::<T>(level, glwe_size, poly_size, lwe_size)?;
        let noise_iter = self
            .noise
            .fork_pfpksk_to_pfpksk_chunks(level, poly_size, lwe_size)?;
        Ok(map_to_encryption_generator(mask_iter, noise_iter))
    }

    pub(crate) fn fork_lwe_compact_ciphertext_list_to_bin<T: UnsignedInteger>(
        &mut self,
        lwe_mask_count: LweMaskCount,
        lwe_dimension: LweDimension,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_iter = self
            .mask
            .fork_lwe_compact_ciphertext_list_to_bin::<T>(lwe_mask_count, lwe_dimension)?;
        let noise_iter = self
            .noise
            .fork_lwe_compact_ciphertext_list_to_bin(lwe_mask_count, lwe_dimension)?;
        Ok(map_to_encryption_generator(mask_iter, noise_iter))
    }

    // Fills the slice with random uniform values, using the mask generator.
    pub(crate) fn fill_slice_with_random_mask<Scalar>(&mut self, output: &mut [Scalar])
    where
        Scalar: RandomGenerable<Uniform>,
    {
        self.mask.fill_slice_with_random_mask(output);
    }

    // Fills the slice with random uniform values, using the mask generator
    pub(crate) fn fill_slice_with_random_mask_custom_mod<Scalar>(
        &mut self,
        output: &mut [Scalar],
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) where
        Scalar: UnsignedInteger + RandomGenerable<Uniform, CustomModulus = Scalar>,
    {
        self.mask
            .fill_slice_with_random_mask_custom_mod(output, ciphertext_modulus);
    }

    // Sample a noise value, using the noise generator.
    pub(crate) fn random_noise<Scalar>(&mut self, std: impl DispersionParameter) -> Scalar
    where
        Scalar: UnsignedTorus + RandomGenerable<Gaussian<f64>>,
    {
        self.noise.random_noise(std)
    }

    // Sample a noise value, using the noise generator.
    pub(crate) fn random_noise_custom_mod<Scalar>(
        &mut self,
        std: impl DispersionParameter,
        custom_modulus: CiphertextModulus<Scalar>,
    ) -> Scalar
    where
        Scalar: UnsignedTorus + RandomGenerable<Gaussian<f64>, CustomModulus = Scalar>,
    {
        self.noise.random_noise_custom_mod(std, custom_modulus)
    }

    // Fills the input slice with random noise, using the noise generator.
    pub(crate) fn fill_slice_with_random_noise<Scalar>(
        &mut self,
        output: &mut [Scalar],
        std: impl DispersionParameter,
    ) where
        Scalar: UnsignedTorus,
        (Scalar, Scalar): RandomGenerable<Gaussian<f64>>,
    {
        self.noise.fill_slice_with_random_noise(output, std);
    }

    // Fills the input slice with random noise, using the noise generator.
    pub(crate) fn fill_slice_with_random_noise_custom_mod<Scalar>(
        &mut self,
        output: &mut [Scalar],
        std: impl DispersionParameter,
        custom_modulus: CiphertextModulus<Scalar>,
    ) where
        Scalar: UnsignedTorus,
        (Scalar, Scalar): RandomGenerable<Gaussian<f64>, CustomModulus = Scalar>,
    {
        self.noise
            .fill_slice_with_random_noise_custom_mod(output, std, custom_modulus);
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
            .unsigned_torus_slice_wrapping_add_random_noise_assign(output, std);
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
        self.noise
            .unsigned_torus_slice_wrapping_add_random_noise_custom_mod_assign(
                output,
                std,
                custom_modulus,
            );
    }
}

// Forks both generators into an iterator
fn map_to_encryption_generator<G: ByteRandomGenerator>(
    mask_iter: impl Iterator<Item = MaskRandomGenerator<G>>,
    noise_iter: impl Iterator<Item = NoiseRandomGenerator<G>>,
) -> impl Iterator<Item = EncryptionRandomGenerator<G>> {
    // We return a proper iterator.
    mask_iter
        .zip(noise_iter)
        .map(|(mask, noise)| EncryptionRandomGenerator { mask, noise })
}

impl<G: ParallelByteRandomGenerator> EncryptionRandomGenerator<G> {
    // Forks the generator into a parallel iterator, when splitting a bootstrap key into ggsw ct.
    pub(crate) fn par_fork_bsk_to_ggsw<T: UnsignedInteger>(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_iter = self.mask.par_fork_bsk_to_ggsw::<T>(
            lwe_dimension,
            level,
            glwe_size,
            polynomial_size,
        )?;
        let noise_iter =
            self.noise
                .par_fork_bsk_to_ggsw(lwe_dimension, level, glwe_size, polynomial_size)?;
        Ok(par_map_to_encryption_generator(mask_iter, noise_iter))
    }

    // Forks the generator, when splitting a multi_bit bootstrap key into ggsw ct.
    pub(crate) fn par_fork_multi_bit_bsk_to_ggsw_group<T: UnsignedInteger>(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        grouping_factor: LweBskGroupingFactor,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_iter = self.mask.par_fork_multi_bit_bsk_to_ggsw_group::<T>(
            lwe_dimension,
            level,
            glwe_size,
            polynomial_size,
            grouping_factor,
        )?;
        let noise_iter = self.noise.par_fork_multi_bit_bsk_to_ggsw_group(
            lwe_dimension,
            level,
            glwe_size,
            polynomial_size,
            grouping_factor,
        )?;
        Ok(par_map_to_encryption_generator(mask_iter, noise_iter))
    }

    // Forks the generator, when splitting a multi_bit bootstrap key ggsw ciphertext group into
    // individual ggsws.
    pub(crate) fn par_fork_multi_bit_bsk_ggsw_group_to_ggsw<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        grouping_factor: LweBskGroupingFactor,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_iter = self.mask.par_fork_multi_bit_bsk_ggsw_group_to_ggsw::<T>(
            level,
            glwe_size,
            polynomial_size,
            grouping_factor,
        )?;
        let noise_iter = self.noise.par_fork_multi_bit_bsk_ggsw_group_to_ggsw(
            level,
            glwe_size,
            polynomial_size,
            grouping_factor,
        )?;
        Ok(par_map_to_encryption_generator(mask_iter, noise_iter))
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw into level matrices.
    pub(crate) fn par_fork_ggsw_to_ggsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_iter =
            self.mask
                .par_fork_ggsw_to_ggsw_levels::<T>(level, glwe_size, polynomial_size)?;
        let noise_iter =
            self.noise
                .par_fork_ggsw_to_ggsw_levels(level, glwe_size, polynomial_size)?;
        Ok(par_map_to_encryption_generator(mask_iter, noise_iter))
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw level matrix to glwe.
    pub(crate) fn par_fork_ggsw_level_to_glwe<T: UnsignedInteger>(
        &mut self,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_iter = self
            .mask
            .par_fork_ggsw_level_to_glwe::<T>(glwe_size, polynomial_size)?;
        let noise_iter = self
            .noise
            .par_fork_ggsw_level_to_glwe(glwe_size, polynomial_size)?;
        Ok(par_map_to_encryption_generator(mask_iter, noise_iter))
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw into level matrices.
    pub(crate) fn par_fork_gsw_to_gsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        lwe_size: LweSize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_iter = self.mask.par_fork_gsw_to_gsw_levels::<T>(level, lwe_size)?;
        let noise_iter = self.noise.par_fork_gsw_to_gsw_levels(level, lwe_size)?;
        Ok(par_map_to_encryption_generator(mask_iter, noise_iter))
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw level matrix to glwe.
    pub(crate) fn par_fork_gsw_level_to_lwe<T: UnsignedInteger>(
        &mut self,
        lwe_size: LweSize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_iter = self.mask.par_fork_gsw_level_to_lwe::<T>(lwe_size)?;
        let noise_iter = self.noise.par_fork_gsw_level_to_lwe(lwe_size)?;
        Ok(par_map_to_encryption_generator(mask_iter, noise_iter))
    }

    // Forks the generator, when splitting an lwe ciphertext list into ciphertexts.
    pub(crate) fn par_fork_lwe_list_to_lwe<T: UnsignedInteger>(
        &mut self,
        lwe_count: LweCiphertextCount,
        lwe_size: LweSize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_iter = self
            .mask
            .par_fork_lwe_list_to_lwe::<T>(lwe_count, lwe_size)?;
        let noise_iter = self.noise.par_fork_lwe_list_to_lwe(lwe_count)?;
        Ok(par_map_to_encryption_generator(mask_iter, noise_iter))
    }

    // Forks the generator, when splitting a collection of pfpksk for cbs
    pub(crate) fn par_fork_cbs_pfpksk_to_pfpksk<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        lwe_size: LweSize,
        pfpksk_count: FunctionalPackingKeyswitchKeyCount,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_iter = self.mask.par_fork_cbs_pfpksk_to_pfpksk::<T>(
            level,
            glwe_size,
            poly_size,
            lwe_size,
            pfpksk_count,
        )?;
        let noise_iter =
            self.noise
                .par_fork_cbs_pfpksk_to_pfpksk(level, poly_size, lwe_size, pfpksk_count)?;
        Ok(par_map_to_encryption_generator(mask_iter, noise_iter))
    }

    // Forks the generator, when splitting a pfpksk into chunks
    pub(crate) fn par_fork_pfpksk_to_pfpksk_chunks<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        lwe_size: LweSize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_iter = self
            .mask
            .par_fork_pfpksk_to_pfpksk_chunks::<T>(level, glwe_size, poly_size, lwe_size)?;
        let noise_iter = self
            .noise
            .par_fork_pfpksk_to_pfpksk_chunks(level, poly_size, lwe_size)?;
        Ok(par_map_to_encryption_generator(mask_iter, noise_iter))
    }

    pub(crate) fn par_fork_lwe_compact_ciphertext_list_to_bin<T: UnsignedInteger>(
        &mut self,
        lwe_mask_count: LweMaskCount,
        lwe_dimension: LweDimension,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_iter = self
            .mask
            .par_fork_lwe_compact_ciphertext_list_to_bin::<T>(lwe_mask_count, lwe_dimension)?;
        let noise_iter = self
            .noise
            .par_fork_lwe_compact_ciphertext_list_to_bin(lwe_mask_count, lwe_dimension)?;
        Ok(par_map_to_encryption_generator(mask_iter, noise_iter))
    }
}

// Forks both generators into a parallel iterator.
fn par_map_to_encryption_generator<G: ParallelByteRandomGenerator>(
    mask_iter: impl IndexedParallelIterator<Item = MaskRandomGenerator<G>>,
    noise_iter: impl IndexedParallelIterator<Item = NoiseRandomGenerator<G>>,
) -> impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>> {
    // We return a proper iterator.
    mask_iter
        .zip(noise_iter)
        .map(|(mask, noise)| EncryptionRandomGenerator { mask, noise })
}
