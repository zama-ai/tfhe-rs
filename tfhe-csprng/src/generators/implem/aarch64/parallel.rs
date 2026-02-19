use super::*;
use crate::generators::aes_ctr::{AesCtrGenerator, ParallelChildrenIterator};
use crate::generators::implem::aarch64::block_cipher::ArmAesBlockCipher;
use crate::generators::{BytesPerChild, ChildrenCount, ForkError, ParallelRandomGenerator};
use rayon::iter::plumbing::{Consumer, ProducerCallback, UnindexedConsumer};
use rayon::prelude::*;

/// The parallel children iterator used by [`NeonAesRandomGenerator`].
///
/// Outputs the children generators one by one.
#[allow(clippy::type_complexity)]
pub struct ParallelArmAesChildrenIterator(
    rayon::iter::Map<
        ParallelChildrenIterator<ArmAesBlockCipher>,
        fn(AesCtrGenerator<ArmAesBlockCipher>) -> NeonAesRandomGenerator,
    >,
);

impl ParallelIterator for ParallelArmAesChildrenIterator {
    type Item = NeonAesRandomGenerator;
    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: UnindexedConsumer<Self::Item>,
    {
        self.0.drive_unindexed(consumer)
    }
}

impl IndexedParallelIterator for ParallelArmAesChildrenIterator {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn drive<C: Consumer<Self::Item>>(self, consumer: C) -> C::Result {
        self.0.drive(consumer)
    }
    fn with_producer<CB: ProducerCallback<Self::Item>>(self, callback: CB) -> CB::Output {
        self.0.with_producer(callback)
    }
}

impl ParallelRandomGenerator for NeonAesRandomGenerator {
    type ParChildrenIter = ParallelArmAesChildrenIterator;

    fn par_try_fork(
        &mut self,
        n_children: ChildrenCount,
        n_bytes: BytesPerChild,
    ) -> Result<Self::ParChildrenIter, ForkError> {
        self.0
            .par_try_fork(n_children, n_bytes)
            .map(|iterator| ParallelArmAesChildrenIterator(iterator.map(NeonAesRandomGenerator)))
    }
}

#[cfg(test)]
mod test {
    use crate::generators::aes_ctr::aes_ctr_parallel_generic_tests;
    use crate::generators::implem::aarch64::block_cipher::ArmAesBlockCipher;

    #[test]
    fn prop_fork_first_state_table_index() {
        aes_ctr_parallel_generic_tests::prop_fork_first_state_table_index::<ArmAesBlockCipher>();
    }

    #[test]
    fn prop_fork_last_bound_table_index() {
        aes_ctr_parallel_generic_tests::prop_fork_last_bound_table_index::<ArmAesBlockCipher>();
    }

    #[test]
    fn prop_fork_parent_bound_table_index() {
        aes_ctr_parallel_generic_tests::prop_fork_parent_bound_table_index::<ArmAesBlockCipher>();
    }

    #[test]
    fn prop_fork_parent_state_table_index() {
        aes_ctr_parallel_generic_tests::prop_fork_parent_state_table_index::<ArmAesBlockCipher>();
    }

    #[test]
    fn prop_fork_ttt() {
        aes_ctr_parallel_generic_tests::prop_fork::<ArmAesBlockCipher>();
    }

    #[test]
    fn prop_fork_children_remaining_bytes() {
        aes_ctr_parallel_generic_tests::prop_fork_children_remaining_bytes::<ArmAesBlockCipher>();
    }

    #[test]
    fn prop_fork_parent_remaining_bytes() {
        aes_ctr_parallel_generic_tests::prop_fork_parent_remaining_bytes::<ArmAesBlockCipher>();
    }

    #[test]
    fn prop_fork_with_parent_continuation() {
        aes_ctr_parallel_generic_tests::prop_fork_with_parent_continuation::<ArmAesBlockCipher>();
    }

    #[test]
    fn test_forking_conformance_with_ctr_crate() {
        aes_ctr_parallel_generic_tests::test_forking_conformance_with_ctr_crate::<ArmAesBlockCipher>(
        );
    }
}
