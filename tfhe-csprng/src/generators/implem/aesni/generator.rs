use crate::generators::aes_ctr::{AesCtrGenerator, ChildrenIterator};
use crate::generators::implem::aesni::block_cipher::AesniBlockCipher;
use crate::generators::{ByteCount, BytesPerChild, ChildrenCount, ForkError, RandomGenerator};
use crate::seeders::SeedKind;

/// A random number generator using the `aesni` instructions.
pub struct AesniRandomGenerator(pub(super) AesCtrGenerator<AesniBlockCipher>);

/// The children iterator used by [`AesniRandomGenerator`].
///
/// Outputs children generators one by one.
pub struct AesniChildrenIterator(ChildrenIterator<AesniBlockCipher>);

impl Iterator for AesniChildrenIterator {
    type Item = AesniRandomGenerator;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(AesniRandomGenerator)
    }
}

impl RandomGenerator for AesniRandomGenerator {
    type ChildrenIter = AesniChildrenIterator;
    fn new(seed: impl Into<SeedKind>) -> Self {
        AesniRandomGenerator(AesCtrGenerator::from_seed(seed))
    }
    fn remaining_bytes(&self) -> ByteCount {
        self.0.remaining_bytes()
    }
    fn try_fork(
        &mut self,
        n_children: ChildrenCount,
        n_bytes: BytesPerChild,
    ) -> Result<Self::ChildrenIter, ForkError> {
        self.0
            .try_fork(n_children, n_bytes)
            .map(AesniChildrenIterator)
    }
}

impl Iterator for AesniRandomGenerator {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

#[cfg(test)]
mod test {
    use crate::generators::aes_ctr::aes_ctr_generic_test;
    use crate::generators::implem::aesni::block_cipher::AesniBlockCipher;
    use crate::generators::{generator_generic_test, AesniRandomGenerator};

    #[test]
    fn prop_fork_first_state_table_index() {
        aes_ctr_generic_test::prop_fork_first_state_table_index::<AesniBlockCipher>();
    }

    #[test]
    fn prop_fork_last_bound_table_index() {
        aes_ctr_generic_test::prop_fork_last_bound_table_index::<AesniBlockCipher>();
    }

    #[test]
    fn prop_fork_parent_bound_table_index() {
        aes_ctr_generic_test::prop_fork_parent_bound_table_index::<AesniBlockCipher>();
    }

    #[test]
    fn prop_fork_parent_state_table_index() {
        aes_ctr_generic_test::prop_fork_parent_state_table_index::<AesniBlockCipher>();
    }

    #[test]
    fn prop_fork() {
        aes_ctr_generic_test::prop_fork::<AesniBlockCipher>();
    }

    #[test]
    fn prop_fork_with_parent_continuation() {
        aes_ctr_generic_test::prop_fork_with_parent_continuation::<AesniBlockCipher>();
    }

    #[test]
    fn prop_fork_children_remaining_bytes() {
        aes_ctr_generic_test::prop_fork_children_remaining_bytes::<AesniBlockCipher>();
    }

    #[test]
    fn prop_fork_parent_remaining_bytes() {
        aes_ctr_generic_test::prop_fork_parent_remaining_bytes::<AesniBlockCipher>();
    }

    #[test]
    fn test_roughly_uniform() {
        generator_generic_test::test_roughly_uniform::<AesniRandomGenerator>();
    }

    #[test]
    fn test_generator_determinism() {
        generator_generic_test::test_generator_determinism::<AesniRandomGenerator>();
    }

    #[test]
    fn test_fork() {
        generator_generic_test::test_fork_children::<AesniRandomGenerator>();
    }

    #[test]
    #[should_panic(expected = "expected test panic")]
    fn test_bounded_panic() {
        generator_generic_test::test_bounded_none_should_panic::<AesniRandomGenerator>();
    }

    #[test]
    fn test_vector() {
        generator_generic_test::test_vectors::<AesniRandomGenerator>();
    }

    #[test]
    fn test_vector_xof_seed() {
        generator_generic_test::test_vectors_xof_seed::<AesniRandomGenerator>();
    }

    #[test]
    fn test_vector_xof_seed_bytes() {
        generator_generic_test::test_vectors_xof_seed_bytes::<AesniRandomGenerator>();
    }
}
