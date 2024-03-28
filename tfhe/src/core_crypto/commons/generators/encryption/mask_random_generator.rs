//! Module containing primitives pertaining to random mask generation in the context of encryption.

use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, ParallelByteRandomGenerator, RandomGenerable, RandomGenerator, Seed,
    Uniform,
};
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::{
    CiphertextModulus, DecompositionLevelCount, FunctionalPackingKeyswitchKeyCount, GlweDimension,
    GlweSize, LweBskGroupingFactor, LweCiphertextCount, LweDimension, LweMaskCount, LweSize,
    PolynomialSize,
};
use concrete_csprng::generators::ForkError;
use rayon::prelude::*;

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
    gen: RandomGenerator<G>,
}

impl<G: ByteRandomGenerator> MaskRandomGenerator<G> {
    pub fn new(seed: Seed) -> Self {
        Self {
            gen: RandomGenerator::new(seed),
        }
    }

    pub fn remaining_bytes(&self) -> Option<usize> {
        self.gen.remaining_bytes()
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

    // Forks the generator, when splitting a bootstrap key into ggsw ct.
    pub(crate) fn fork_bsk_to_ggsw<T: UnsignedInteger>(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_bytes = mask_elements_per_ggsw(level, glwe_size, polynomial_size)
            .to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.try_fork(lwe_dimension.0, mask_bytes)
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
        let mask_bytes = mask_elements_per_multi_bit_bsk_ggsw_group(
            level,
            glwe_size,
            polynomial_size,
            grouping_factor,
        )
        .to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.try_fork(lwe_dimension.0, mask_bytes)
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
        let ggsw_count = grouping_factor.ggsw_per_multi_bit_element();
        let mask_bytes = mask_elements_per_ggsw(level, glwe_size, polynomial_size)
            .to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.try_fork(ggsw_count.0, mask_bytes)
    }

    // Forks the generator, when splitting a ggsw into level matrices.
    pub(crate) fn fork_ggsw_to_ggsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_bytes = mask_elements_per_ggsw_level(glwe_size, polynomial_size)
            .to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.try_fork(level.0, mask_bytes)
    }

    // Forks the generator, when splitting a ggsw level matrix to glwe.
    pub(crate) fn fork_ggsw_level_to_glwe<T: UnsignedInteger>(
        &mut self,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_bytes = mask_elements_per_glwe(glwe_size.to_glwe_dimension(), polynomial_size)
            .to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.try_fork(glwe_size.0, mask_bytes)
    }

    // Forks the generator, when splitting a ggsw into level matrices.
    pub(crate) fn fork_gsw_to_gsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_bytes =
            mask_elements_per_gsw_level(lwe_size).to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.try_fork(level.0, mask_bytes)
    }

    // Forks the generator, when splitting a ggsw level matrix to glwe.
    pub(crate) fn fork_gsw_level_to_lwe<T: UnsignedInteger>(
        &mut self,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_bytes = mask_elements_per_lwe(lwe_size.to_lwe_dimension())
            .to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.try_fork(lwe_size.0, mask_bytes)
    }

    // Forks the generator, when splitting an lwe ciphertext list into ciphertexts.
    pub(crate) fn fork_lwe_list_to_lwe<T: UnsignedInteger>(
        &mut self,
        lwe_count: LweCiphertextCount,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_bytes = mask_elements_per_lwe(lwe_size.to_lwe_dimension())
            .to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.try_fork(lwe_count.0, mask_bytes)
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
        let mask_bytes = mask_elements_per_pfpksk(level, glwe_size, poly_size, lwe_size)
            .to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.try_fork(pfpksk_count.0, mask_bytes)
    }

    // Forks the generator, when splitting a pfpksk into chunks
    pub(crate) fn fork_pfpksk_to_pfpksk_chunks<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_bytes = mask_elements_per_pfpksk_chunk(level, glwe_size, poly_size)
            .to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.try_fork(lwe_size.0, mask_bytes)
    }

    pub(crate) fn fork_lwe_compact_ciphertext_list_to_bin<T: UnsignedInteger>(
        &mut self,
        lwe_mask_count: LweMaskCount,
        lwe_dimension: LweDimension,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_bytes = mask_elements_per_lwe_compact_ciphertext_bin(lwe_dimension)
            .to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.try_fork(lwe_mask_count.0, mask_bytes)
    }

    pub(crate) fn try_fork(
        &mut self,
        n_child: usize,
        mask_bytes: MaskByteCount,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        // We try to fork the generators
        let mask_iter = self.gen.try_fork(n_child, mask_bytes.0)?;

        // We return a proper iterator.
        Ok(mask_iter.map(|gen| Self { gen }))
    }
}

impl<G: ParallelByteRandomGenerator> MaskRandomGenerator<G> {
    // Forks the generator into a parallel iterator, when splitting a bootstrap key into ggsw ct.
    pub(crate) fn par_fork_bsk_to_ggsw<T: UnsignedInteger>(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_bytes = mask_elements_per_ggsw(level, glwe_size, polynomial_size)
            .to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.par_try_fork(lwe_dimension.0, mask_bytes)
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
        let mask_bytes = mask_elements_per_multi_bit_bsk_ggsw_group(
            level,
            glwe_size,
            polynomial_size,
            grouping_factor,
        )
        .to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.par_try_fork(lwe_dimension.0, mask_bytes)
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
        let ggsw_count = grouping_factor.ggsw_per_multi_bit_element();
        let mask_bytes = mask_elements_per_ggsw(level, glwe_size, polynomial_size)
            .to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.par_try_fork(ggsw_count.0, mask_bytes)
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw into level matrices.
    pub(crate) fn par_fork_ggsw_to_ggsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_bytes = mask_elements_per_ggsw_level(glwe_size, polynomial_size)
            .to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.par_try_fork(level.0, mask_bytes)
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw level matrix to glwe.
    pub(crate) fn par_fork_ggsw_level_to_glwe<T: UnsignedInteger>(
        &mut self,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_bytes = mask_elements_per_glwe(glwe_size.to_glwe_dimension(), polynomial_size)
            .to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.par_try_fork(glwe_size.0, mask_bytes)
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw into level matrices.
    pub(crate) fn par_fork_gsw_to_gsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        lwe_size: LweSize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_bytes =
            mask_elements_per_gsw_level(lwe_size).to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.par_try_fork(level.0, mask_bytes)
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw level matrix to glwe.
    pub(crate) fn par_fork_gsw_level_to_lwe<T: UnsignedInteger>(
        &mut self,
        lwe_size: LweSize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_bytes = mask_elements_per_lwe(lwe_size.to_lwe_dimension())
            .to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.par_try_fork(lwe_size.0, mask_bytes)
    }

    // Forks the generator, when splitting an lwe ciphertext list into ciphertexts.
    pub(crate) fn par_fork_lwe_list_to_lwe<T: UnsignedInteger>(
        &mut self,
        lwe_count: LweCiphertextCount,
        lwe_size: LweSize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_bytes = mask_elements_per_lwe(lwe_size.to_lwe_dimension())
            .to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.par_try_fork(lwe_count.0, mask_bytes)
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
        let mask_bytes = mask_elements_per_pfpksk(level, glwe_size, poly_size, lwe_size)
            .to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.par_try_fork(pfpksk_count.0, mask_bytes)
    }

    // Forks the generator, when splitting a pfpksk into chunks
    pub(crate) fn par_fork_pfpksk_to_pfpksk_chunks<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        lwe_size: LweSize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_bytes = mask_elements_per_pfpksk_chunk(level, glwe_size, poly_size)
            .to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.par_try_fork(lwe_size.0, mask_bytes)
    }

    pub(crate) fn par_fork_lwe_compact_ciphertext_list_to_bin<T: UnsignedInteger>(
        &mut self,
        lwe_mask_count: LweMaskCount,
        lwe_dimension: LweDimension,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_bytes = mask_elements_per_lwe_compact_ciphertext_bin(lwe_dimension)
            .to_mask_byte_count(mask_bytes_per_coef::<T>());
        self.par_try_fork(lwe_mask_count.0, mask_bytes)
    }

    // Forks both generators into a parallel iterator.
    pub(crate) fn par_try_fork(
        &mut self,
        n_child: usize,
        mask_bytes: MaskByteCount,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        // We try to fork the generators
        let mask_iter = self.gen.par_try_fork(n_child, mask_bytes.0)?;

        // We return a proper iterator.
        Ok(mask_iter.map(|gen| Self { gen }))
    }
}

/// A quantity representing a number of scalar used for mask generation.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(crate) struct MaskElementCount(pub usize);

impl MaskElementCount {
    pub(crate) fn to_mask_byte_count(self, mask_byte_per_scalar: MaskByteCount) -> MaskByteCount {
        MaskByteCount(self.0 * mask_byte_per_scalar.0)
    }
}

/// A quantity representing a number of bytes used for mask generation.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(crate) struct MaskByteCount(pub usize);

fn mask_bytes_per_coef<T: UnsignedInteger>() -> MaskByteCount {
    MaskByteCount(T::BITS / 8)
}

fn mask_elements_per_polynomial(poly_size: PolynomialSize) -> MaskElementCount {
    MaskElementCount(poly_size.0)
}

fn mask_elements_per_glwe(
    glwe_dimension: GlweDimension,
    poly_size: PolynomialSize,
) -> MaskElementCount {
    MaskElementCount(glwe_dimension.0 * mask_elements_per_polynomial(poly_size).0)
}

fn mask_elements_per_ggsw_level(
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
) -> MaskElementCount {
    MaskElementCount(
        glwe_size.0 * mask_elements_per_glwe(glwe_size.to_glwe_dimension(), poly_size).0,
    )
}

fn mask_elements_per_lwe(lwe_dimension: LweDimension) -> MaskElementCount {
    MaskElementCount(lwe_dimension.0)
}

fn mask_elements_per_gsw_level(lwe_size: LweSize) -> MaskElementCount {
    MaskElementCount(lwe_size.0 * mask_elements_per_lwe(lwe_size.to_lwe_dimension()).0)
}

fn mask_elements_per_multi_bit_bsk_ggsw_group(
    level: DecompositionLevelCount,
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
    grouping_factor: LweBskGroupingFactor,
) -> MaskElementCount {
    MaskElementCount(
        grouping_factor.ggsw_per_multi_bit_element().0
            * mask_elements_per_ggsw(level, glwe_size, poly_size).0,
    )
}

fn mask_elements_per_ggsw(
    level: DecompositionLevelCount,
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
) -> MaskElementCount {
    MaskElementCount(level.0 * mask_elements_per_ggsw_level(glwe_size, poly_size).0)
}

fn mask_elements_per_pfpksk_chunk(
    level: DecompositionLevelCount,
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
) -> MaskElementCount {
    MaskElementCount(level.0 * mask_elements_per_glwe(glwe_size.to_glwe_dimension(), poly_size).0)
}

fn mask_elements_per_pfpksk(
    level: DecompositionLevelCount,
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
    lwe_size: LweSize,
) -> MaskElementCount {
    MaskElementCount(lwe_size.0 * mask_elements_per_pfpksk_chunk(level, glwe_size, poly_size).0)
}

fn mask_elements_per_lwe_compact_ciphertext_bin(lwe_dimension: LweDimension) -> MaskElementCount {
    MaskElementCount(lwe_dimension.0)
}

#[cfg(feature = "experimental")]
mod experimental {
    use super::*;
    impl<G: ByteRandomGenerator> MaskRandomGenerator<G> {
        // Forks the generator, when splitting a ggsw into level matrices.
        pub(crate) fn fork_pseudo_ggsw_to_ggsw_levels<T: UnsignedInteger>(
            &mut self,
            level: DecompositionLevelCount,
            glwe_size_in: GlweSize,
            glwe_size_out: GlweSize,
            polynomial_size: PolynomialSize,
        ) -> Result<impl Iterator<Item = Self>, ForkError> {
            let mask_bytes =
                mask_elements_per_pseudo_ggsw_level(glwe_size_in, glwe_size_out, polynomial_size)
                    .to_mask_byte_count(mask_bytes_per_coef::<T>());
            self.try_fork(level.0, mask_bytes)
        }

        // Forks the generator, when splitting a pseudo ggsw level matrix to glwe.
        pub(crate) fn fork_pseudo_ggsw_level_to_glwe<T: UnsignedInteger>(
            &mut self,
            glwe_size_in: GlweSize,
            glwe_size_out: GlweSize,
            polynomial_size: PolynomialSize,
        ) -> Result<impl Iterator<Item = Self>, ForkError> {
            let mask_bytes =
                mask_elements_per_glwe(glwe_size_out.to_glwe_dimension(), polynomial_size)
                    .to_mask_byte_count(mask_bytes_per_coef::<T>());
            self.try_fork(glwe_size_in.to_glwe_dimension().0, mask_bytes)
        }
    }

    fn mask_elements_per_pseudo_ggsw_level(
        glwe_size_in: GlweSize,
        glwe_size_out: GlweSize,
        poly_size: PolynomialSize,
    ) -> MaskElementCount {
        MaskElementCount(
            glwe_size_in.to_glwe_dimension().0
                * mask_elements_per_glwe(glwe_size_out.to_glwe_dimension(), poly_size).0,
        )
    }
}
