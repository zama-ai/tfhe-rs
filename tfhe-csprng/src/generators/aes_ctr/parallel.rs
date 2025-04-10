use crate::generators::aes_ctr::states::State;
use crate::generators::aes_ctr::{AesBlockCipher, AesCtrGenerator, ChildrenClosure, TableIndex};
use crate::generators::{BytesPerChild, ChildrenCount, ForkError};

/// A type alias for the parallel children iterator type.
pub type ParallelChildrenIterator<BlockCipher> = rayon::iter::Map<
    rayon::iter::Zip<
        rayon::range::Iter<usize>,
        rayon::iter::RepeatN<(Box<BlockCipher>, TableIndex, BytesPerChild)>,
    >,
    fn((usize, (Box<BlockCipher>, TableIndex, BytesPerChild))) -> AesCtrGenerator<BlockCipher>,
>;

impl<BlockCipher: AesBlockCipher> AesCtrGenerator<BlockCipher> {
    /// Tries to fork the current generator into `n_child` generators each able to output
    /// `child_bytes` random bytes as a parallel iterator.
    ///
    /// # Notes
    ///
    /// This method necessitate the "multithread" feature.
    pub fn par_try_fork(
        &mut self,
        n_children: ChildrenCount,
        n_bytes: BytesPerChild,
    ) -> Result<ParallelChildrenIterator<BlockCipher>, ForkError>
    where
        BlockCipher: Send + Sync,
    {
        use rayon::prelude::*;

        if n_children.0 == 0 {
            return Err(ForkError::ZeroChildrenCount);
        }
        if n_bytes.0 == 0 {
            return Err(ForkError::ZeroBytesPerChild);
        }
        if !self.is_fork_in_bound(n_children, n_bytes) {
            return Err(ForkError::ForkTooLarge);
        }

        // The state currently stored in the parent generator points to the table index of the last
        // generated byte. The first index to be generated is the next one :
        let first_index = self.state.table_index().incremented();
        let output = (0..n_children.0)
            .into_par_iter()
            .zip(rayon::iter::repeatn(
                (self.block_cipher.clone(), first_index, n_bytes),
                n_children.0,
            ))
            .map(
                // This map is a little weird because we need to cast the closure to a fn pointer
                // that matches the signature of `ChildrenIterator<BlockCipher>`. Unfortunately,
                // the compiler does not manage to coerce this one automatically.
                (|(i, (block_cipher, first_index, n_bytes))| {
                    // The first index to be outputted by the child is the `first_index` shifted by
                    // the proper amount of `child_bytes`.
                    let child_first_index = first_index.increased(n_bytes.0 * i);
                    // The bound of the child is the first index of its next sibling.
                    let child_bound_index = first_index.increased(n_bytes.0 * (i + 1));
                    AesCtrGenerator::from_block_cipher(
                        block_cipher,
                        child_first_index,
                        child_bound_index,
                    )
                }) as ChildrenClosure<BlockCipher>,
            );
        // The parent next index is the bound of the last child.
        let next_index = first_index.increased(n_bytes.0 * n_children.0);
        self.state = State::new(next_index);

        Ok(output)
    }
}

#[cfg(test)]
pub mod aes_ctr_parallel_generic_tests {

    use super::*;
    use crate::generators::aes_ctr::aes_ctr_generic_test::{any_key, any_valid_fork};
    use rayon::prelude::*;

    const REPEATS: usize = 1_000_000;

    /// Check the property:
    ///     On a valid fork, the table index of the first child is the same as the table index of
    ///     the parent before the fork.
    pub fn prop_fork_first_state_table_index<G: AesBlockCipher>() {
        for _ in 0..REPEATS {
            let (t, nc, nb, i) = any_valid_fork().next().unwrap();
            let k = any_key().next().unwrap();
            let original_generator =
                AesCtrGenerator::<G>::new(k, Some(t), Some(t.increased(nc.0 * nb.0 + i)));
            let mut forked_generator = original_generator.clone();
            let first_child = forked_generator
                .par_try_fork(nc, nb)
                .unwrap()
                .find_first(|_| true)
                .unwrap();
            assert_eq!(original_generator.table_index(), first_child.table_index());
        }
    }

    /// Check the property:
    ///     On a valid fork, the table index of the first byte outputted by the parent after the
    ///     fork, is the bound of the last child of the fork.
    pub fn prop_fork_last_bound_table_index<G: AesBlockCipher>() {
        for _ in 0..REPEATS {
            let (t, nc, nb, i) = any_valid_fork().next().unwrap();
            let k = any_key().next().unwrap();
            let mut parent_generator =
                AesCtrGenerator::<G>::new(k, Some(t), Some(t.increased(nc.0 * nb.0 + i)));
            let last_child = parent_generator
                .par_try_fork(nc, nb)
                .unwrap()
                .find_last(|_| true)
                .unwrap();
            assert_eq!(
                parent_generator.table_index().incremented(),
                last_child.get_bound()
            );
        }
    }

    /// Check the property:
    ///     On a valid fork, the bound of the parent does not change.
    pub fn prop_fork_parent_bound_table_index<G: AesBlockCipher>() {
        for _ in 0..REPEATS {
            let (t, nc, nb, i) = any_valid_fork().next().unwrap();
            let k = any_key().next().unwrap();
            let original_generator =
                AesCtrGenerator::<G>::new(k, Some(t), Some(t.increased(nc.0 * nb.0 + i)));
            let mut forked_generator = original_generator.clone();
            forked_generator
                .par_try_fork(nc, nb)
                .unwrap()
                .find_last(|_| true)
                .unwrap();
            assert_eq!(original_generator.get_bound(), forked_generator.get_bound());
        }
    }

    /// Check the property:
    ///     On a valid fork, the parent table index is increased of the number of children
    ///     multiplied by the number of bytes per child.
    pub fn prop_fork_parent_state_table_index<G: AesBlockCipher>() {
        for _ in 0..REPEATS {
            let (t, nc, nb, i) = any_valid_fork().next().unwrap();
            let k = any_key().next().unwrap();
            let original_generator =
                AesCtrGenerator::<G>::new(k, Some(t), Some(t.increased(nc.0 * nb.0 + i)));
            let mut forked_generator = original_generator.clone();
            forked_generator
                .par_try_fork(nc, nb)
                .unwrap()
                .find_last(|_| true)
                .unwrap();
            assert_eq!(
                forked_generator.table_index(),
                // Decrement accounts for the fact that the table index stored is the previous one
                t.increased(nc.0 * nb.0).decremented()
            );
        }
    }

    /// Check the property:
    ///     On a valid fork, the bytes outputted by the children in the fork order form the same
    ///     sequence the parent would have had outputted no fork had happened.
    pub fn prop_fork<G: AesBlockCipher>() {
        for _ in 0..1000 {
            let (t, nc, nb, i) = any_valid_fork().next().unwrap();
            let k = any_key().next().unwrap();
            let bytes_to_go = nc.0 * nb.0;
            let original_generator =
                AesCtrGenerator::<G>::new(k, Some(t), Some(t.increased(nc.0 * nb.0 + i)));
            let mut forked_generator = original_generator.clone();
            let initial_output: Vec<u8> = original_generator.take(bytes_to_go).collect();
            let forked_output: Vec<u8> = forked_generator
                .par_try_fork(nc, nb)
                .unwrap()
                .flat_map(|child| child.collect::<Vec<_>>())
                .collect();
            assert_eq!(initial_output, forked_output);
        }
    }

    /// Check the property:
    ///     On a valid fork, all children got a number of remaining bytes equals to the number of
    ///     bytes per child given as fork input.
    pub fn prop_fork_children_remaining_bytes<G: AesBlockCipher>() {
        for _ in 0..REPEATS {
            let (t, nc, nb, i) = any_valid_fork().next().unwrap();
            let k = any_key().next().unwrap();
            let mut generator =
                AesCtrGenerator::<G>::new(k, Some(t), Some(t.increased(nc.0 * nb.0 + i)));
            assert!(generator
                .par_try_fork(nc, nb)
                .unwrap()
                .all(|c| c.remaining_bytes().0 == nb.0 as u128));
        }
    }

    /// Check the property:
    ///     On a valid fork, the number of remaining bytes of the parent is reduced by the
    ///     number of children multiplied by the number of bytes per child.
    pub fn prop_fork_parent_remaining_bytes<G: AesBlockCipher>() {
        for _ in 0..REPEATS {
            let (t, nc, nb, i) = any_valid_fork().next().unwrap();
            let k = any_key().next().unwrap();
            let bytes_to_go = nc.0 * nb.0;
            let mut generator =
                AesCtrGenerator::<G>::new(k, Some(t), Some(t.increased(nc.0 * nb.0 + i)));
            let before_remaining_bytes = generator.remaining_bytes();
            let _ = generator.par_try_fork(nc, nb).unwrap();
            let after_remaining_bytes = generator.remaining_bytes();
            assert_eq!(
                before_remaining_bytes.0 - after_remaining_bytes.0,
                bytes_to_go as u128
            );
        }
    }
}
