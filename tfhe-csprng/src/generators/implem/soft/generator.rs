use crate::generators::aes_ctr::{AesCtrGenerator, ChildrenIterator};
use crate::generators::implem::soft::block_cipher::SoftwareBlockCipher;
use crate::generators::{ByteCount, BytesPerChild, ChildrenCount, ForkError, RandomGenerator};
use crate::seeders::SeedKind;

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
    fn new(seed: impl Into<SeedKind>) -> Self {
        SoftwareRandomGenerator(AesCtrGenerator::from_seed(seed))
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

    // We use powerpc64 as the target to test behavior on big-endian
    // However, we run these tests using an emulator. Thus, these get really slow
    // so we skip them
    #[cfg(not(target_arch = "powerpc64"))]
    mod fork_tests {
        use super::*;

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
        fn prop_fork_with_parent_continuation() {
            aes_ctr_generic_test::prop_fork_with_parent_continuation::<SoftwareBlockCipher>();
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
        fn test_fork() {
            generator_generic_test::test_fork_children::<SoftwareRandomGenerator>();
        }

        #[test]
        fn test_roughly_uniform() {
            generator_generic_test::test_roughly_uniform::<SoftwareRandomGenerator>();
        }
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

    #[test]
    fn test_vector() {
        generator_generic_test::test_vectors::<SoftwareRandomGenerator>();
    }

    #[test]
    fn test_vector_xof_seed() {
        generator_generic_test::test_vectors_xof_seed::<SoftwareRandomGenerator>();
    }

    #[test]
    fn test_vector_xof_seed_bytes() {
        generator_generic_test::test_vectors_xof_seed_bytes::<SoftwareRandomGenerator>();
    }
}
