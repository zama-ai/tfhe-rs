use crate::generators::aes_ctr::block_cipher::{AesBlockCipher, AesKey};
use crate::generators::aes_ctr::index::TableIndex;
use crate::generators::aes_ctr::states::{BufferPointer, ShiftAction, State};
use crate::generators::aes_ctr::{AesIndex, BYTES_PER_BATCH};
use crate::generators::{widening_mul, ByteCount, BytesPerChild, ChildrenCount, ForkError};
use crate::seeders::SeedKind;

// Usually, to work with iterators and parallel iterators, we would use opaque types such as
// `impl Iterator<..>`. Unfortunately, it is not yet possible to return existential types in
// traits, which we would need for `RandomGenerator`. For this reason, we have to use the
// full type name where needed. Hence the following type aliases definition:

/// A type alias for the children iterator closure type.
pub type ChildrenClosure<BlockCipher> = fn(
    (u64, (Box<BlockCipher>, TableIndex, BytesPerChild, AesIndex)),
) -> AesCtrGenerator<BlockCipher>;

/// A type alias for the children iterator type.
pub type ChildrenIterator<BlockCipher> = std::iter::Map<
    std::iter::Zip<
        std::ops::Range<u64>,
        std::iter::Repeat<(Box<BlockCipher>, TableIndex, BytesPerChild, AesIndex)>,
    >,
    ChildrenClosure<BlockCipher>,
>;

/// A type implementing the `RandomGenerator` api using the AES block cipher in counter mode.
#[derive(Clone)]
pub struct AesCtrGenerator<BlockCipher: AesBlockCipher> {
    // The block cipher used in the background
    pub(crate) block_cipher: Box<BlockCipher>,
    // The state corresponding to the latest outputted byte.
    pub(crate) state: State,
    // The last legal index. This makes bound check faster.
    pub(crate) last: TableIndex,
    // The buffer containing the current batch of aes calls.
    pub(crate) buffer: [u8; BYTES_PER_BATCH],
}

#[allow(unused)] // to please clippy when tests are not activated
impl<BlockCipher: AesBlockCipher> AesCtrGenerator<BlockCipher> {
    /// Generates a new csprng.
    ///
    /// Note :
    /// ------
    ///
    /// The `start_index` given as input, points to the first byte that will be outputted by the
    /// generator. If not given, this one is automatically set to the second table index. The
    /// first table index is not used to prevent an edge case from happening: since `state` is
    /// supposed to contain the index of the previous byte, the initial value must be decremented.
    /// Using the second value prevents wrapping to the max index, which would make the bound
    /// checking fail.
    ///
    /// The `bound_index` given as input, points to the first byte that can __not__ be legally
    /// outputted by the generator. If not given, the bound is automatically set to the last
    /// table index.
    pub fn new(
        key: AesKey,
        start_index: Option<TableIndex>,
        bound_index: Option<TableIndex>,
        offset: Option<AesIndex>,
    ) -> AesCtrGenerator<BlockCipher> {
        AesCtrGenerator::from_block_cipher(
            Box::new(BlockCipher::new(key)),
            start_index.unwrap_or(TableIndex::SECOND),
            bound_index.unwrap_or(TableIndex::LAST),
            offset.unwrap_or(AesIndex(0)),
        )
    }

    /// Generates a csprng from an existing block cipher.
    pub fn from_block_cipher(
        block_cipher: Box<BlockCipher>,
        start_index: TableIndex,
        bound_index: TableIndex,
        offset: AesIndex,
    ) -> AesCtrGenerator<BlockCipher> {
        assert!(start_index < bound_index);
        let last = bound_index.decremented();
        let buffer = [0u8; BYTES_PER_BATCH];
        let state = State::with_offset(start_index, offset);
        AesCtrGenerator {
            block_cipher,
            state,
            last,
            buffer,
        }
    }

    pub(crate) fn from_seed(seed: impl Into<SeedKind>) -> Self {
        match seed.into() {
            SeedKind::Ctr(seed) => {
                // AesKey has an unspoken requirement to have bytes in an order independent of
                // platform endianness, problem is the Seed(u128) has an endianness, meaning
                // 1u128 == [1, 0, ..., 0] for little endian
                // but
                // 1u128 == [0, ..., 0, 1] for big endian
                let seed_u128 = u128::from_le(seed.0);
                Self::new(AesKey(seed_u128), None, None, None)
            }
            SeedKind::Xof(seed) => {
                let (key, init_index) = super::xof_init(seed);
                Self::new(key, None, None, Some(init_index))
            }
        }
    }

    /// Returns the table index related to the previous random byte.
    pub fn table_index(&self) -> TableIndex {
        self.state.table_index()
    }

    /// Returns the bound of the generator if any.
    ///
    /// The bound is the table index of the first byte that can not be outputted by the generator.
    pub fn get_bound(&self) -> TableIndex {
        self.last.incremented()
    }

    /// Returns whether the generator is bounded or not.
    pub fn is_bounded(&self) -> bool {
        self.get_bound() != TableIndex::LAST
    }

    /// Computes the number of bytes that can still be outputted by the generator.
    ///
    /// Note :
    /// ------
    ///
    /// Note that `ByteCount` uses the `u128` datatype to store the byte count. Unfortunately, the
    /// number of remaining bytes is in ⟦0;2¹³² -1⟧. When the number is greater than 2¹²⁸ - 1,
    /// we saturate the count at 2¹²⁸ - 1.
    pub fn remaining_bytes(&self) -> ByteCount {
        TableIndex::distance(&self.last, &self.state.table_index()).unwrap()
    }

    /// Outputs the next random byte.
    pub fn generate_next(&mut self) -> u8 {
        self.next()
            .expect("Tried to generate a byte after the bound.")
    }

    /// Tries to fork the current generator into `n_child` generators each able to output
    /// `child_bytes` random bytes.
    pub fn try_fork(
        &mut self,
        n_children: ChildrenCount,
        n_bytes: BytesPerChild,
    ) -> Result<ChildrenIterator<BlockCipher>, ForkError> {
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
        // generated byte. The first index to be generated is the next one:
        let first_index = self.state.table_index().incremented();
        let output = (0..n_children.0)
            .zip(std::iter::repeat((
                self.block_cipher.clone(),
                first_index,
                n_bytes,
                self.state.offset(),
            )))
            .map(
                // This map is a little weird because we need to cast the closure to a fn pointer
                // that matches the signature of `ChildrenIterator<BlockCipher>`.
                // Unfortunately, the compiler does not manage to coerce this one
                // automatically.
                (|(i, (block_cipher, first_index, n_bytes, offset))| {
                    // The first index to be outputted by the child is the `first_index` shifted by
                    // the proper amount of `child_bytes`.
                    let child_first_index = first_index.increased(widening_mul(n_bytes.0, i));
                    // The bound of the child is the first index of its next sibling.
                    let child_bound_index = first_index.increased(widening_mul(n_bytes.0, (i + 1)));
                    AesCtrGenerator::from_block_cipher(
                        block_cipher,
                        child_first_index,
                        child_bound_index,
                        offset,
                    )
                }) as ChildrenClosure<BlockCipher>,
            );
        // The parent next index is the bound of the last child.
        let child_bytes = widening_mul(n_bytes.0, n_children.0);
        if let ShiftAction::RefreshBatchAndOutputByte(aes_index, _ptr) =
            self.state.increase(child_bytes)
        {
            let aes_inputs = core::array::from_fn(|i| aes_index.0.wrapping_add(i as u128).to_le());
            self.buffer = self.block_cipher.generate_batch(aes_inputs);
        }

        Ok(output)
    }

    pub(crate) fn is_fork_in_bound(
        &self,
        n_child: ChildrenCount,
        child_bytes: BytesPerChild,
    ) -> bool {
        let mut end = self.state.table_index();
        end.increase(widening_mul(n_child.0, child_bytes.0));
        end <= self.last
    }
}

impl<BlockCipher: AesBlockCipher> Iterator for AesCtrGenerator<BlockCipher> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.state.table_index() >= self.last {
            None
        } else {
            match self.state.increment() {
                ShiftAction::OutputByte(BufferPointer(ptr)) => Some(self.buffer[ptr]),
                ShiftAction::RefreshBatchAndOutputByte(aes_index, BufferPointer(ptr)) => {
                    let aes_inputs =
                        core::array::from_fn(|i| aes_index.0.wrapping_add(i as u128).to_le());
                    self.buffer = self.block_cipher.generate_batch(aes_inputs);
                    Some(self.buffer[ptr])
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(unused)] // to please clippy when tests are not activated
pub mod aes_ctr_generic_test {

    use super::*;
    use crate::generators::aes_ctr::index::{AesIndex, ByteIndex};
    use crate::generators::aes_ctr::BYTES_PER_AES_CALL;
    use rand::{thread_rng, Rng};

    const REPEATS: usize = 1_000_000;

    pub fn any_table_index() -> impl Iterator<Item = TableIndex> {
        std::iter::repeat_with(|| {
            TableIndex::new(
                AesIndex(thread_rng().gen()),
                ByteIndex(thread_rng().gen::<usize>() % BYTES_PER_AES_CALL),
            )
        })
    }

    pub fn any_u128() -> impl Iterator<Item = u128> {
        std::iter::repeat_with(|| thread_rng().gen())
    }

    pub fn any_children_count() -> impl Iterator<Item = ChildrenCount> {
        std::iter::repeat_with(|| ChildrenCount(thread_rng().gen::<u64>() % 2048 + 1))
    }

    pub fn any_bytes_per_child() -> impl Iterator<Item = BytesPerChild> {
        std::iter::repeat_with(|| BytesPerChild(thread_rng().gen::<u64>() % 2048 + 1))
    }

    pub fn any_key() -> impl Iterator<Item = AesKey> {
        std::iter::repeat_with(|| AesKey(thread_rng().gen()))
    }

    /// Output a valid fork:
    ///     a table index t,
    ///     a number of children nc,
    ///     a number of bytes per children nb
    ///     and a positive integer i such that:
    ///         increase(t, nc*nb+i) < MAX with MAX the largest table index.
    ///
    /// Put differently, if we initialize a parent generator at t and fork it with (nc, nb), our
    /// parent generator current index gets shifted to an index, distant of at least i bytes of
    /// the max index.
    pub fn any_valid_fork() -> impl Iterator<Item = (TableIndex, ChildrenCount, BytesPerChild, u128)>
    {
        any_table_index()
            .zip(any_children_count())
            .zip(any_bytes_per_child())
            .zip(any_u128())
            .map(|(((t, nc), nb), i)| (t, nc, nb, i))
            .filter(|(t, nc, nb, i)| {
                TableIndex::distance(&TableIndex::LAST, t).unwrap().0 > widening_mul(nc.0, nb.0) + i
            })
    }

    /// Check the property:
    ///     On a valid fork, the table index of the first child is the same as the table index of
    ///     the parent before the fork.
    pub fn prop_fork_first_state_table_index<G: AesBlockCipher>() {
        for _ in 0..REPEATS {
            let (t, nc, nb, i) = any_valid_fork().next().unwrap();
            let k = any_key().next().unwrap();
            let offset = Some(AesIndex(rand::random()));
            let original_generator = AesCtrGenerator::<G>::new(
                k,
                Some(t),
                Some(t.increased(widening_mul(nc.0, nb.0) + i)),
                offset,
            );
            let mut forked_generator = original_generator.clone();
            let first_child = forked_generator.try_fork(nc, nb).unwrap().next().unwrap();
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
            let offset = Some(AesIndex(rand::random()));
            let mut parent_generator = AesCtrGenerator::<G>::new(
                k,
                Some(t),
                Some(t.increased(widening_mul(nc.0, nb.0) + i)),
                offset,
            );
            let last_child = parent_generator.try_fork(nc, nb).unwrap().last().unwrap();
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
            let offset = Some(AesIndex(rand::random()));
            let original_generator = AesCtrGenerator::<G>::new(
                k,
                Some(t),
                Some(t.increased(widening_mul(nc.0, nb.0) + i)),
                offset,
            );
            let mut forked_generator = original_generator.clone();
            forked_generator.try_fork(nc, nb).unwrap().last().unwrap();
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
            let offset = Some(AesIndex(rand::random()));
            let original_generator = AesCtrGenerator::<G>::new(
                k,
                Some(t),
                Some(t.increased(widening_mul(nc.0, nb.0) + i)),
                offset,
            );
            let mut forked_generator = original_generator.clone();
            forked_generator.try_fork(nc, nb).unwrap().last().unwrap();
            assert_eq!(
                forked_generator.table_index(),
                // Decrement accounts for the fact that the table index stored is the previous one
                t.increased(widening_mul(nc.0, nb.0)).decremented()
            );
        }
    }

    /// Check the property:
    ///     On a valid fork, the bytes outputted by the children in the fork order form the same
    ///     sequence the parent would have had yielded no fork had happened.
    pub fn prop_fork<G: AesBlockCipher>() {
        for _ in 0..1000 {
            let (t, nc, nb, i) = any_valid_fork().next().unwrap();
            let offset = Some(AesIndex(rand::random()));
            let k = any_key().next().unwrap();
            let bytes_to_go = nc.0 * nb.0;
            let original_generator = AesCtrGenerator::<G>::new(
                k,
                Some(t),
                Some(t.increased(widening_mul(nc.0, nb.0) + i)),
                offset,
            );
            let mut forked_generator = original_generator.clone();
            let initial_output: Vec<u8> = original_generator
                .take(usize::try_from(bytes_to_go).unwrap())
                .collect();
            let forked_output: Vec<u8> = forked_generator
                .try_fork(nc, nb)
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
            let offset = Some(AesIndex(rand::random()));
            let mut generator = AesCtrGenerator::<G>::new(
                k,
                Some(t),
                Some(t.increased(widening_mul(nc.0, nb.0) + i)),
                offset,
            );
            assert!(generator
                .try_fork(nc, nb)
                .unwrap()
                .all(|c| c.remaining_bytes().0 == nb.0 as u128));
        }
    }

    /// Check the property:
    ///     On a valid fork, the number of remaining bybtes of the parent is reduced by the number
    ///     of children multiplied by the number of bytes per child.
    pub fn prop_fork_parent_remaining_bytes<G: AesBlockCipher>() {
        for _ in 0..REPEATS {
            let (t, nc, nb, i) = any_valid_fork().next().unwrap();
            let k = any_key().next().unwrap();
            let offset = Some(AesIndex(rand::random()));
            let bytes_to_go = nc.0 * nb.0;
            let mut generator = AesCtrGenerator::<G>::new(
                k,
                Some(t),
                Some(t.increased(widening_mul(nc.0, nb.0) + i)),
                offset,
            );
            let before_remaining_bytes = generator.remaining_bytes();
            let _ = generator.try_fork(nc, nb).unwrap();
            let after_remaining_bytes = generator.remaining_bytes();
            assert_eq!(
                before_remaining_bytes.0 - after_remaining_bytes.0,
                bytes_to_go as u128
            );
        }
    }

    /// Check the property:
    ///     On a valid fork, the bytes outputted by the children in fork order, followed by the
    ///     remaining parent bytes, form the same sequence the parent would have yielded had no
    ///     fork happened.
    pub fn prop_fork_with_parent_continuation<G: AesBlockCipher>() {
        const MAX_BYTES_GEN: u128 = u16::MAX as u128;

        let mut rng = rand::thread_rng();
        for _ in 0..10_000 {
            let (t, nc, nb, num_extra_bytes) = any_valid_fork().next().unwrap();
            let k = any_key().next().unwrap();
            let fork_bytes = widening_mul(nc.0, nb.0);
            let total_bytes = fork_bytes.saturating_add(num_extra_bytes);

            let first_consumed_amount = rng.gen_range(1..num_extra_bytes.min(MAX_BYTES_GEN));

            let offset = Some(AesIndex(rand::random()));
            let mut gen1 =
                AesCtrGenerator::<G>::new(k, Some(t), Some(t.increased(total_bytes)), offset);
            let mut forked_gen = gen1.clone();

            let num_extra_bytes = (num_extra_bytes - first_consumed_amount).min(u16::MAX as u128);

            for i in 0..first_consumed_amount {
                let byte = forked_gen.next().unwrap();
                let expected_byte = gen1.next().unwrap();
                assert_eq!(
                    byte, expected_byte,
                    "pre-fork bytes are not equal (byte index {i})"
                );
            }

            for child in forked_gen.try_fork(nc, nb).unwrap() {
                for byte in child {
                    let expected_byte = gen1.next().unwrap();
                    assert_eq!(byte, expected_byte);
                }
            }

            for i in 0..num_extra_bytes {
                let byte = forked_gen.next().unwrap();
                let expected_byte = gen1.next().unwrap();
                assert_eq!(byte, expected_byte, "post-fork bytes are not equal (byte index {i}), got {byte}, expected {expected_byte}");
            }
        }
    }
}
