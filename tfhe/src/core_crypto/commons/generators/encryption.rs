//! Module containing primitives pertaining to random generation in the context of encryption.

use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, Gaussian, ParallelByteRandomGenerator, RandomGenerable, RandomGenerator,
    Seed, Seeder, Uniform,
};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::{
    DecompositionLevelCount, FunctionalPackingKeyswitchKeyCount, GlweDimension, GlweSize,
    LweBskGroupingFactor, LweCiphertextCount, LweDimension, LweSize, PolynomialSize,
};
use concrete_csprng::generators::ForkError;
use rayon::prelude::*;

/// A random number generator which can be used to encrypt messages.
pub struct EncryptionRandomGenerator<G: ByteRandomGenerator> {
    // A separate mask generator, only used to generate the mask elements.
    mask: RandomGenerator<G>,
    // A separate noise generator, only used to generate the noise elements.
    noise: RandomGenerator<G>,
}

impl<G: ByteRandomGenerator> EncryptionRandomGenerator<G> {
    /// Create a new [`EncryptionRandomGenerator`], using the provided [`Seed`] to seed the public
    /// mask generator and using the provided [`Seeder`] to privately seed the noise generator.
    // S is ?Sized to allow Box<dyn Seeder> to be passed.
    pub fn new<S: Seeder + ?Sized>(seed: Seed, seeder: &mut S) -> EncryptionRandomGenerator<G> {
        EncryptionRandomGenerator {
            mask: RandomGenerator::new(seed),
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

    pub(crate) fn fork_n(
        &mut self,
        n: usize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        // We use ForkTooLarge here as what can fail is the conversion from u128 to usize
        let mask_bytes = self.mask.remaining_bytes().ok_or(ForkError::ForkTooLarge)? / n;
        let noise_bytes = self
            .noise
            .remaining_bytes()
            .ok_or(ForkError::ForkTooLarge)?
            / n;
        self.try_fork(n, mask_bytes, noise_bytes)
    }

    // Forks the generator, when splitting a bootstrap key into ggsw ct.
    pub(crate) fn fork_bsk_to_ggsw<T: UnsignedInteger>(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_ggsw::<T>(level, glwe_size, polynomial_size);
        let noise_bytes = noise_bytes_per_ggsw(level, glwe_size, polynomial_size);
        self.try_fork(lwe_dimension.0, mask_bytes, noise_bytes)
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
        let ggsw_count = grouping_factor.ggsw_per_multi_bit_element();
        let mask_bytes = ggsw_count.0 * mask_bytes_per_ggsw::<T>(level, glwe_size, polynomial_size);
        let noise_bytes = ggsw_count.0 * noise_bytes_per_ggsw(level, glwe_size, polynomial_size);
        self.try_fork(lwe_dimension.0, mask_bytes, noise_bytes)
    }

    // Forks the generator, when splitting a ggsw into level matrices.
    pub(crate) fn fork_ggsw_to_ggsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_ggsw_level::<T>(glwe_size, polynomial_size);
        let noise_bytes = noise_bytes_per_ggsw_level(glwe_size, polynomial_size);
        self.try_fork(level.0, mask_bytes, noise_bytes)
    }

    // Forks the generator, when splitting a ggsw level matrix to glwe.
    pub(crate) fn fork_ggsw_level_to_glwe<T: UnsignedInteger>(
        &mut self,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_glwe::<T>(glwe_size.to_glwe_dimension(), polynomial_size);
        let noise_bytes = noise_bytes_per_glwe(polynomial_size);
        self.try_fork(glwe_size.0, mask_bytes, noise_bytes)
    }

    // Forks the generator, when splitting a ggsw into level matrices.
    pub(crate) fn fork_gsw_to_gsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_gsw_level::<T>(lwe_size);
        let noise_bytes = noise_bytes_per_gsw_level(lwe_size);
        self.try_fork(level.0, mask_bytes, noise_bytes)
    }

    // Forks the generator, when splitting a ggsw level matrix to glwe.
    pub(crate) fn fork_gsw_level_to_lwe<T: UnsignedInteger>(
        &mut self,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_lwe::<T>(lwe_size.to_lwe_dimension());
        let noise_bytes = noise_bytes_per_lwe();
        self.try_fork(lwe_size.0, mask_bytes, noise_bytes)
    }

    // Forks the generator, when splitting an lwe ciphertext list into ciphertexts.
    pub(crate) fn fork_lwe_list_to_lwe<T: UnsignedInteger>(
        &mut self,
        lwe_count: LweCiphertextCount,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_lwe::<T>(lwe_size.to_lwe_dimension());
        let noise_bytes = noise_bytes_per_lwe();
        self.try_fork(lwe_count.0, mask_bytes, noise_bytes)
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
        let mask_bytes = mask_bytes_per_pfpksk::<T>(level, glwe_size, poly_size, lwe_size);
        let noise_bytes = noise_bytes_per_pfpksk(level, poly_size, lwe_size);
        self.try_fork(pfpksk_count.0, mask_bytes, noise_bytes)
    }

    // Forks the generator, when splitting a pfpksk into chunks
    pub(crate) fn fork_pfpksk_to_pfpksk_chunks<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_pfpksk_chunk::<T>(level, glwe_size, poly_size);
        let noise_bytes = noise_bytes_per_pfpksk_chunk(level, poly_size);
        self.try_fork(lwe_size.0, mask_bytes, noise_bytes)
    }

    // Forks both generators into an iterator
    fn try_fork(
        &mut self,
        n_child: usize,
        mask_bytes: usize,
        noise_bytes: usize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        // We try to fork the generators
        let mask_iter = self.mask.try_fork(n_child, mask_bytes)?;
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
        self.mask.fill_slice_with_random_uniform(output)
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
}

impl<G: ParallelByteRandomGenerator> EncryptionRandomGenerator<G> {
    pub(crate) fn par_fork_n(
        &mut self,
        n: usize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = self.mask.remaining_bytes().unwrap() / n;
        let noise_bytes = self.noise.remaining_bytes().unwrap() / n;
        self.par_try_fork(n, mask_bytes, noise_bytes)
    }

    // Forks the generator into a parallel iterator, when splitting a bootstrap key into ggsw ct.
    pub(crate) fn par_fork_bsk_to_ggsw<T: UnsignedInteger>(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_ggsw::<T>(level, glwe_size, polynomial_size);
        let noise_bytes = noise_bytes_per_ggsw(level, glwe_size, polynomial_size);
        self.par_try_fork(lwe_dimension.0, mask_bytes, noise_bytes)
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
        let ggsw_count = grouping_factor.ggsw_per_multi_bit_element();
        let mask_bytes = ggsw_count.0 * mask_bytes_per_ggsw::<T>(level, glwe_size, polynomial_size);
        let noise_bytes = ggsw_count.0 * noise_bytes_per_ggsw(level, glwe_size, polynomial_size);
        self.par_try_fork(lwe_dimension.0, mask_bytes, noise_bytes)
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw into level matrices.
    pub(crate) fn par_fork_ggsw_to_ggsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_ggsw_level::<T>(glwe_size, polynomial_size);
        let noise_bytes = noise_bytes_per_ggsw_level(glwe_size, polynomial_size);
        self.par_try_fork(level.0, mask_bytes, noise_bytes)
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw level matrix to glwe.
    pub(crate) fn par_fork_ggsw_level_to_glwe<T: UnsignedInteger>(
        &mut self,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_glwe::<T>(glwe_size.to_glwe_dimension(), polynomial_size);
        let noise_bytes = noise_bytes_per_glwe(polynomial_size);
        self.par_try_fork(glwe_size.0, mask_bytes, noise_bytes)
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw into level matrices.
    pub(crate) fn par_fork_gsw_to_gsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        lwe_size: LweSize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_gsw_level::<T>(lwe_size);
        let noise_bytes = noise_bytes_per_gsw_level(lwe_size);
        self.par_try_fork(level.0, mask_bytes, noise_bytes)
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw level matrix to glwe.
    pub(crate) fn par_fork_gsw_level_to_lwe<T: UnsignedInteger>(
        &mut self,
        lwe_size: LweSize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_lwe::<T>(lwe_size.to_lwe_dimension());
        let noise_bytes = noise_bytes_per_lwe();
        self.par_try_fork(lwe_size.0, mask_bytes, noise_bytes)
    }

    // Forks the generator, when splitting an lwe ciphertext list into ciphertexts.
    pub(crate) fn par_fork_lwe_list_to_lwe<T: UnsignedInteger>(
        &mut self,
        lwe_count: LweCiphertextCount,
        lwe_size: LweSize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_lwe::<T>(lwe_size.to_lwe_dimension());
        let noise_bytes = noise_bytes_per_lwe();
        self.par_try_fork(lwe_count.0, mask_bytes, noise_bytes)
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
        let mask_bytes = mask_bytes_per_pfpksk::<T>(level, glwe_size, poly_size, lwe_size);
        let noise_bytes = noise_bytes_per_pfpksk(level, poly_size, lwe_size);
        self.par_try_fork(pfpksk_count.0, mask_bytes, noise_bytes)
    }

    // Forks the generator, when splitting a pfpksk into chunks
    pub(crate) fn par_fork_pfpksk_to_pfpksk_chunks<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        lwe_size: LweSize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_pfpksk_chunk::<T>(level, glwe_size, poly_size);
        let noise_bytes = noise_bytes_per_pfpksk_chunk(level, poly_size);
        self.par_try_fork(lwe_size.0, mask_bytes, noise_bytes)
    }

    // Forks both generators into a parallel iterator.
    fn par_try_fork(
        &mut self,
        n_child: usize,
        mask_bytes: usize,
        noise_bytes: usize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        // We try to fork the generators
        let mask_iter = self.mask.par_try_fork(n_child, mask_bytes)?;
        let noise_iter = self.noise.par_try_fork(n_child, noise_bytes)?;

        // We return a proper iterator.
        Ok(mask_iter
            .zip(noise_iter)
            .map(|(mask, noise)| EncryptionRandomGenerator { mask, noise }))
    }
}

fn mask_bytes_per_coef<T: UnsignedInteger>() -> usize {
    T::BITS / 8
}

fn mask_bytes_per_polynomial<T: UnsignedInteger>(poly_size: PolynomialSize) -> usize {
    poly_size.0 * mask_bytes_per_coef::<T>()
}

fn mask_bytes_per_glwe<T: UnsignedInteger>(
    glwe_dimension: GlweDimension,
    poly_size: PolynomialSize,
) -> usize {
    glwe_dimension.0 * mask_bytes_per_polynomial::<T>(poly_size)
}

fn mask_bytes_per_ggsw_level<T: UnsignedInteger>(
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
) -> usize {
    glwe_size.0 * mask_bytes_per_glwe::<T>(glwe_size.to_glwe_dimension(), poly_size)
}

fn mask_bytes_per_lwe<T: UnsignedInteger>(lwe_dimension: LweDimension) -> usize {
    lwe_dimension.0 * mask_bytes_per_coef::<T>()
}

fn mask_bytes_per_gsw_level<T: UnsignedInteger>(lwe_size: LweSize) -> usize {
    lwe_size.0 * mask_bytes_per_lwe::<T>(lwe_size.to_lwe_dimension())
}

fn mask_bytes_per_ggsw<T: UnsignedInteger>(
    level: DecompositionLevelCount,
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
) -> usize {
    level.0 * mask_bytes_per_ggsw_level::<T>(glwe_size, poly_size)
}

fn mask_bytes_per_pfpksk_chunk<T: UnsignedInteger>(
    level: DecompositionLevelCount,
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
) -> usize {
    level.0 * mask_bytes_per_glwe::<T>(glwe_size.to_glwe_dimension(), poly_size)
}

fn mask_bytes_per_pfpksk<T: UnsignedInteger>(
    level: DecompositionLevelCount,
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
    lwe_size: LweSize,
) -> usize {
    lwe_size.0 * mask_bytes_per_pfpksk_chunk::<T>(level, glwe_size, poly_size)
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

#[cfg(test)]
mod test {
    use crate::core_crypto::algorithms::*;
    use crate::core_crypto::commons::dispersion::Variance;
    use crate::core_crypto::commons::parameters::{
        DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    };
    use crate::core_crypto::commons::test_tools::{
        new_encryption_random_generator, new_secret_random_generator,
    };

    #[test]
    fn test_gaussian_sampling_margin_factor_does_not_panic() {
        struct Params {
            glwe_size: GlweSize,
            poly_size: PolynomialSize,
            dec_level_count: DecompositionLevelCount,
            dec_base_log: DecompositionBaseLog,
            lwe_dim: LweDimension,
        }
        let params = Params {
            glwe_size: GlweSize(2),
            poly_size: PolynomialSize(1),
            dec_level_count: DecompositionLevelCount(1),
            dec_base_log: DecompositionBaseLog(4),
            lwe_dim: LweDimension(17000),
        };
        let mut enc_generator = new_encryption_random_generator();
        let mut sec_generator = new_secret_random_generator();
        let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key::<u64, _>(
            params.lwe_dim,
            &mut sec_generator,
        );
        let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
            params.glwe_size.to_glwe_dimension(),
            params.poly_size,
            &mut sec_generator,
        );
        let _bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
            &lwe_sk,
            &glwe_sk,
            params.dec_base_log,
            params.dec_level_count,
            Variance(0.),
            &mut enc_generator,
        );
    }
}
