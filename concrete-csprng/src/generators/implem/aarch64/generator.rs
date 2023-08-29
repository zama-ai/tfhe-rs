use crate::generators::aes_ctr::{AesCtrGenerator, AesKey, ChildrenIterator};
use crate::generators::implem::aarch64::block_cipher::ArmAesBlockCipher;
use crate::generators::{ByteCount, BytesPerChild, ChildrenCount, ForkError, RandomGenerator};
use crate::seeders::Seed;

/// A random number generator using the `aesni` instructions.
pub struct NeonAesRandomGenerator(pub(super) AesCtrGenerator<ArmAesBlockCipher>);

/// The children iterator used by [`NeonAesRandomGenerator`].
///
/// Outputs children generators one by one.
pub struct ArmAesChildrenIterator(ChildrenIterator<ArmAesBlockCipher>);

impl Iterator for ArmAesChildrenIterator {
    type Item = NeonAesRandomGenerator;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(NeonAesRandomGenerator)
    }
}

impl RandomGenerator for NeonAesRandomGenerator {
    type ChildrenIter = ArmAesChildrenIterator;
    fn new(seed: Seed) -> Self {
        NeonAesRandomGenerator(AesCtrGenerator::new(AesKey(seed.0), None, None))
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
            .map(ArmAesChildrenIterator)
    }
}

impl Iterator for NeonAesRandomGenerator {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

#[cfg(test)]
mod test {
    use crate::generators::aes_ctr::aes_ctr_generic_test;
    use crate::generators::implem::aarch64::block_cipher::ArmAesBlockCipher;
    use crate::generators::{generator_generic_test, NeonAesRandomGenerator};

    #[test]
    fn prop_fork_first_state_table_index() {
        aes_ctr_generic_test::prop_fork_first_state_table_index::<ArmAesBlockCipher>();
    }

    #[test]
    fn prop_fork_last_bound_table_index() {
        aes_ctr_generic_test::prop_fork_last_bound_table_index::<ArmAesBlockCipher>();
    }

    #[test]
    fn prop_fork_parent_bound_table_index() {
        aes_ctr_generic_test::prop_fork_parent_bound_table_index::<ArmAesBlockCipher>();
    }

    #[test]
    fn prop_fork_parent_state_table_index() {
        aes_ctr_generic_test::prop_fork_parent_state_table_index::<ArmAesBlockCipher>();
    }

    #[test]
    fn prop_fork() {
        aes_ctr_generic_test::prop_fork::<ArmAesBlockCipher>();
    }

    #[test]
    fn prop_fork_children_remaining_bytes() {
        aes_ctr_generic_test::prop_fork_children_remaining_bytes::<ArmAesBlockCipher>();
    }

    #[test]
    fn prop_fork_parent_remaining_bytes() {
        aes_ctr_generic_test::prop_fork_parent_remaining_bytes::<ArmAesBlockCipher>();
    }

    #[test]
    fn test_roughly_uniform() {
        generator_generic_test::test_roughly_uniform::<NeonAesRandomGenerator>();
    }

    #[test]
    fn test_generator_determinism() {
        generator_generic_test::test_generator_determinism::<NeonAesRandomGenerator>();
    }

    #[test]
    fn test_fork() {
        generator_generic_test::test_fork_children::<NeonAesRandomGenerator>();
    }

    #[test]
    #[should_panic(expected = "expected test panic")]
    fn test_bounded_panic() {
        generator_generic_test::test_bounded_none_should_panic::<NeonAesRandomGenerator>();
    }
}
