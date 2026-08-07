use super::*;
use crate::generators::aes_ctr::{AesCtrGenerator, ParallelChildrenIterator};
use crate::generators::{
    AnyAesBlockCipher, BytesPerChild, ChildrenCount, ForkError, ParallelRandomGenerator,
};
use rayon::iter::plumbing::{Consumer, ProducerCallback, UnindexedConsumer};
use rayon::prelude::*;

/// The parallel children iterator used by [`SoftwareRandomGenerator`].
///
/// Outputs the children generators one by one.
#[allow(clippy::type_complexity)]
pub struct ParallelSoftwareChildrenIterator(
    rayon::iter::Map<
        ParallelChildrenIterator<AnyAesBlockCipher<Software>>,
        fn(AesCtrGenerator<AnyAesBlockCipher<Software>>) -> SoftwareRandomGenerator,
    >,
);

impl ParallelIterator for ParallelSoftwareChildrenIterator {
    type Item = SoftwareRandomGenerator;
    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: UnindexedConsumer<Self::Item>,
    {
        self.0.drive_unindexed(consumer)
    }
}

impl IndexedParallelIterator for ParallelSoftwareChildrenIterator {
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

impl ParallelRandomGenerator for SoftwareRandomGenerator {
    type ParChildrenIter = ParallelSoftwareChildrenIterator;

    fn par_try_fork(
        &mut self,
        n_children: ChildrenCount,
        n_bytes: BytesPerChild,
    ) -> Result<Self::ParChildrenIter, ForkError> {
        self.0
            .par_try_fork(n_children, n_bytes)
            .map(|iterator| ParallelSoftwareChildrenIterator(iterator.map(SoftwareRandomGenerator)))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::generators::aes_ctr::aes_ctr_parallel_generic_tests;

    #[test]
    fn prop_fork_first_state_table_index() {
        aes_ctr_parallel_generic_tests::prop_fork_first_state_table_index::<Software128BlockCipher>(
        );
    }

    #[test]
    fn prop_fork_last_bound_table_index() {
        aes_ctr_parallel_generic_tests::prop_fork_last_bound_table_index::<Software128BlockCipher>(
        );
    }

    #[test]
    fn prop_fork_parent_bound_table_index() {
        aes_ctr_parallel_generic_tests::prop_fork_parent_bound_table_index::<Software128BlockCipher>(
        );
    }

    #[test]
    fn prop_fork_parent_state_table_index() {
        aes_ctr_parallel_generic_tests::prop_fork_parent_state_table_index::<Software128BlockCipher>(
        );
    }

    #[test]
    fn prop_fork() {
        aes_ctr_parallel_generic_tests::prop_fork::<Software128BlockCipher>();
    }

    #[test]
    fn prop_fork_children_remaining_bytes() {
        aes_ctr_parallel_generic_tests::prop_fork_children_remaining_bytes::<Software128BlockCipher>(
        );
    }

    #[test]
    fn prop_fork_parent_remaining_bytes() {
        aes_ctr_parallel_generic_tests::prop_fork_parent_remaining_bytes::<Software128BlockCipher>(
        );
    }

    #[test]
    fn prop_fork_with_parent_continuation() {
        aes_ctr_parallel_generic_tests::prop_fork_with_parent_continuation::<Software128BlockCipher>(
        );
    }

    #[test]
    fn test_forking_conformance_with_ctr_crate() {
        aes_ctr_parallel_generic_tests::test_forking_conformance_with_ctr_crate::<
            Software128BlockCipher,
        >();
    }
}
