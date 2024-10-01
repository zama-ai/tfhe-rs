use crate::generators::aes_ctr::{AesCtrGenerator, AesKey, ChildrenIterator};
use crate::generators::implem::soft::block_cipher::SoftwareBlockCipher;
use crate::generators::{ByteCount, BytesPerChild, ChildrenCount, ForkError, RandomGenerator};
use crate::seeders::Seed;

/// A random number generator using a software implementation.
pub struct SoftwareRandomGenerator(pub(super) AesCtrGenerator<SoftwareBlockCipher>);

/// The children iterator used by [`SoftwareRandomGenerator`].
///
/// Outputs children generators one by one.
pub struct SoftwareChildrenIterator(ChildrenIterator<SoftwareBlockCipher>);

impl Iterator for SoftwareChildrenIterator {
    type Item = SoftwareRandomGenerator;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(SoftwareRandomGenerator)
    }
}

impl RandomGenerator for SoftwareRandomGenerator {
    type ChildrenIter = SoftwareChildrenIterator;
    fn new(seed: Seed) -> Self {
        SoftwareRandomGenerator(AesCtrGenerator::new(AesKey(seed.0), None, None))
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
            .map(SoftwareChildrenIterator)
    }
}

impl Iterator for SoftwareRandomGenerator {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::generators::aes_ctr::aes_ctr_generic_test;
    use crate::generators::generator_generic_test;

    #[test]
    fn prop_fork_first_state_table_index() {
        aes_ctr_generic_test::prop_fork_first_state_table_index::<SoftwareBlockCipher>();
    }

    #[test]
    fn prop_fork_last_bound_table_index() {
        aes_ctr_generic_test::prop_fork_last_bound_table_index::<SoftwareBlockCipher>();
    }

    #[test]
    fn prop_fork_parent_bound_table_index() {
        aes_ctr_generic_test::prop_fork_parent_bound_table_index::<SoftwareBlockCipher>();
    }

    #[test]
    fn prop_fork_parent_state_table_index() {
        aes_ctr_generic_test::prop_fork_parent_state_table_index::<SoftwareBlockCipher>();
    }

    #[test]
    fn prop_fork() {
        aes_ctr_generic_test::prop_fork::<SoftwareBlockCipher>();
    }

    #[test]
    fn prop_fork_children_remaining_bytes() {
        aes_ctr_generic_test::prop_fork_children_remaining_bytes::<SoftwareBlockCipher>();
    }

    #[test]
    fn prop_fork_parent_remaining_bytes() {
        aes_ctr_generic_test::prop_fork_parent_remaining_bytes::<SoftwareBlockCipher>();
    }

    #[test]
    fn test_roughly_uniform() {
        generator_generic_test::test_roughly_uniform::<SoftwareRandomGenerator>();
    }

    #[test]
    fn test_fork() {
        generator_generic_test::test_fork_children::<SoftwareRandomGenerator>();
    }

    #[test]
    fn test_generator_determinism() {
        generator_generic_test::test_generator_determinism::<SoftwareRandomGenerator>();
    }

    #[test]
    #[should_panic(expected = "expected test panic")]
    fn test_bounded_panic() {
        generator_generic_test::test_bounded_none_should_panic::<SoftwareRandomGenerator>();
    }
}
