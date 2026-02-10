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

    use std::ops::Div;

    use super::*;
    use crate::generators::aes_ctr::index::{AesIndex, ByteIndex};
    use crate::generators::aes_ctr::BYTES_PER_AES_CALL;
    use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    use aes::Aes128;
    use ctr::Ctr128LE;
    use rand::rngs::ThreadRng;
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

    // checks than when pulling `num_bytes` from `gen` they
    // match with the next `num_bytes` of 0 encrypted by `cipher`
    pub(crate) fn assert_generator_matches_cipher(
        gen: &mut impl Iterator<Item = u8>,
        cipher: &mut (impl StreamCipher + StreamCipherSeek),
        num_bytes: usize,
        msg: &str,
    ) {
        let mut truth_buffer = [0u8; 16];
        let mut buffer = [0u8; 16];
        for i in 0..num_bytes.div_ceil(buffer.len()) {
            truth_buffer.fill(0);
            let mut valid = 0;
            for (out, b) in buffer.iter_mut().zip(gen.by_ref()) {
                *out = b;
                valid += 1;
            }
            cipher.apply_keystream(&mut truth_buffer[..valid]);
            assert_eq!(&buffer[..valid], &truth_buffer[..valid], "{msg} #{i}");
        }
    }

    // Builds an AesCtrGenerator and a Ctr128LE using parameters
    // such that they should produce same outputs
    pub(crate) fn make_ctr_pair<G: AesBlockCipher>(
        key: AesKey,
        aes_idx: u128,
        byte_idx: usize,
        offset: u128,
    ) -> (AesCtrGenerator<G>, Ctr128LE<Aes128>) {
        let key_bytes = key.0.to_ne_bytes();
        let counter = aes_idx.wrapping_add(offset);
        let nonce_bytes = counter.to_le_bytes();
        let mut cipher = Ctr128LE::<Aes128>::new_from_slices(&key_bytes, &nonce_bytes).unwrap();

        let mut start = TableIndex::new(AesIndex(aes_idx), ByteIndex(byte_idx));
        if start == TableIndex::FIRST {
            start = TableIndex::SECOND;
            cipher.seek(1); // because we have a bug
        } else {
            cipher.seek(byte_idx);
        }

        let gen = AesCtrGenerator::<G>::new(key, Some(start), None, Some(AesIndex(offset)));
        (gen, cipher)
    }

    /// Check that our AesCtrGenerator produces the same keystream as `Ctr128LE<Aes128>` from
    /// the RustCrypto `ctr` crate. CTR mode XORs plaintext with AES keystream, so encrypting
    /// zeros gives the raw keystream for comparison.
    pub fn test_conformance_with_ctr_crate<G: AesBlockCipher>() {
        let mut rng = thread_rng();

        for _ in 0..1_000 {
            let key = AesKey(rng.gen());
            let aes_idx: u128 = rng.gen_range(0..u128::MAX);
            let offset: u128 = rng.gen();

            for byte_idx in 0..BYTES_PER_AES_CALL {
                let (mut gen, mut cipher) = make_ctr_pair::<G>(key, aes_idx, byte_idx, offset);

                let remaining_bytes = gen.remaining_bytes().0.min(u128::from(u16::MAX)) as usize;

                assert_generator_matches_cipher(
                    &mut gen,
                    &mut cipher,
                    remaining_bytes,
                    "invalid bytes buffer",
                );
            }
        }
    }

    /// Check that our AesCtrGenerator produces the same keystream as `Ctr128LE<Aes128>` from
    /// the RustCrypto `ctr` crate. CTR mode XORs plaintext with AES keystream, so encrypting
    /// zeros gives the raw keystream for comparison.
    pub fn test_forking_conformance_with_ctr_crate<G: AesBlockCipher>() {
        let mut rng = thread_rng();

        fn random_tuple_that_equals(rng: &mut ThreadRng, x: u64) -> (u64, u64) {
            loop {
                let a: u64 = rng.gen_range(1..=x);
                if x.is_multiple_of(a) {
                    let b = x / a;
                    return (a, b);
                }
            }
        }

        for _ in 0..1_000 {
            let key = AesKey(rng.gen());
            let aes_idx: u128 = rng.gen_range(0..u128::MAX);
            let offset: u128 = rng.gen();

            for byte_idx in 0..BYTES_PER_AES_CALL {
                let (mut gen, mut cipher) = make_ctr_pair::<G>(key, aes_idx, byte_idx, offset);

                let bytes = gen.remaining_bytes().0.min(u128::from(u16::MAX));
                let bytes_per_parts = (bytes / 3) as usize;

                // First pull without fork
                assert_generator_matches_cipher(
                    &mut gen,
                    &mut cipher,
                    bytes_per_parts,
                    "invalid bytes pre-fork buffer",
                );

                if gen.remaining_bytes().0 == 0 {
                    // just in case
                    continue;
                }

                // pull from fork
                let (nc, nb) = random_tuple_that_equals(&mut rng, bytes_per_parts as u64);
                for (child_i, mut child) in gen
                    .try_fork(ChildrenCount(nc), BytesPerChild(nb))
                    .unwrap()
                    .enumerate()
                {
                    assert_generator_matches_cipher(
                        &mut child,
                        &mut cipher,
                        nb as usize,
                        &format!("invalid bytes child #{child_i} buffer"),
                    );
                }

                // now pull again from parent
                assert_generator_matches_cipher(
                    &mut gen,
                    &mut cipher,
                    bytes_per_parts,
                    "invalid bytes post-fork buffer",
                );
            }
        }
    }

    /// Check the property:
    ///     On a valid fork, the bytes outputted by the children in fork order, followed by the
    ///     remaining parent bytes, form the same sequence the parent would have yielded had no
    ///     fork happened.
    pub fn prop_fork_with_parent_continuation<G: AesBlockCipher>() {
        for _ in 0..10_000 {
            let (t, nc, nb, num_extra_bytes) = any_valid_fork().next().unwrap();
            let k = any_key().next().unwrap();
            let fork_bytes = widening_mul(nc.0, nb.0);
            let total_bytes = fork_bytes.saturating_add(num_extra_bytes);

            let offset = Some(AesIndex(rand::random()));
            let mut gen1 =
                AesCtrGenerator::<G>::new(k, Some(t), Some(t.increased(total_bytes)), offset);
            let mut forked_gen = gen1.clone();

            let bytes = gen1.remaining_bytes().0.min(u128::from(u16::MAX));
            // Non forked amounts of bytes to pull before and after
            let bytes_per_parts = (bytes / 2) as usize;

            for i in 0..bytes_per_parts {
                let byte = forked_gen.next().unwrap();
                let expected_byte = gen1.next().unwrap();
                assert_eq!(
                    byte, expected_byte,
                    "pre-fork bytes are not equal (byte index {i})"
                );
            }

            for (child_i, child) in forked_gen.try_fork(nc, nb).unwrap().enumerate() {
                for (i, byte) in child.enumerate() {
                    let expected_byte = gen1.next().unwrap();
                    assert_eq!(
                        byte, expected_byte,
                        "invalid byte at index {i} for child {child_i}"
                    );
                }
            }

            for i in 0..bytes_per_parts {
                let byte = forked_gen.next().unwrap();
                let expected_byte = gen1.next().unwrap();
                assert_eq!(byte, expected_byte, "post-fork bytes are not equal (byte index {i}), got {byte}, expected {expected_byte}");
            }
        }
    }

    pub fn prop_different_offset_means_different_output<G: AesBlockCipher>() {
        for _ in 0..10_000 {
            let (t, nc, nb, num_extra_bytes) = any_valid_fork().next().unwrap();
            let k = any_key().next().unwrap();
            let fork_bytes = widening_mul(nc.0, nb.0);
            let total_bytes = fork_bytes.saturating_add(num_extra_bytes);

            let offset1 = Some(AesIndex(rand::random()));
            let mut gen1 =
                AesCtrGenerator::<G>::new(k, Some(t), Some(t.increased(total_bytes)), offset1);

            let offset2 = loop {
                let offset2 = Some(AesIndex(rand::random()));
                if offset1 != offset2 {
                    break offset2;
                }
            };
            let mut gen2 =
                AesCtrGenerator::<G>::new(k, Some(t), Some(t.increased(total_bytes)), offset2);

            let bytes = gen1.remaining_bytes().0.min(u128::from(u16::MAX));
            // Non forked amounts of bytes to pull before and after
            let bytes_per_parts = (bytes / 2) as usize;

            let mut slice1 = [0u8; 1024];
            let mut slice2 = [0u8; 1024];

            let n = bytes_per_parts.div_ceil(slice1.len());
            let rest = bytes_per_parts % slice1.len();
            for i in 0..n {
                if i == n - 1 && rest == 1 {
                    // There is only one byte in the slice, the probability of them being equal is
                    // too high
                    continue;
                }

                slice1.fill(0);
                slice2.fill(0);

                for (o, b) in slice1.iter_mut().zip(gen1.by_ref()) {
                    *o = b;
                }
                for (o, b) in slice2.iter_mut().zip(gen2.by_ref()) {
                    *o = b;
                }
                assert_ne!(
                    slice1, slice2,
                    "pre-fork bytes slices are equal but they should not (slice index {i})"
                );
            }

            for (mut child_1, mut child_2) in gen1
                .try_fork(nc, nb)
                .unwrap()
                .zip(gen2.try_fork(nc, nb).unwrap())
            {
                let n = nb.0.div_ceil(slice1.len() as u64);
                let rest = nb.0 % (slice1.len() as u64);
                for i in 0..nb.0.div_ceil(slice1.len() as u64) {
                    if i == n - 1 && rest == 1 {
                        // There is only one byte in the slice, the probability of them being equal
                        // is too high
                        continue;
                    }
                    slice1.fill(0);
                    slice2.fill(0);
                    for (o, b) in slice1.iter_mut().zip(child_1.by_ref()) {
                        *o = b;
                    }
                    for (o, b) in slice2.iter_mut().zip(child_2.by_ref()) {
                        *o = b;
                    }
                    assert_ne!(
                        slice1, slice2,
                        "child bytes slices are equal but they should not (slice index {i})"
                    );
                }
            }

            let n = bytes_per_parts.div_ceil(slice1.len());
            let rest = bytes_per_parts % slice1.len();
            for i in 0..n {
                if i == n - 1 && rest == 1 {
                    // There is only one byte in the slice, the probability of them being equal is
                    // too high
                    continue;
                }

                slice1.fill(0);
                slice2.fill(0);

                for (o, b) in slice1.iter_mut().zip(gen1.by_ref()) {
                    *o = b;
                }
                for (o, b) in slice2.iter_mut().zip(gen2.by_ref()) {
                    *o = b;
                }
                assert_ne!(
                    slice1, slice2,
                    "post-fork bytes slices are equal but they should not (slice index {i})"
                );
            }
        }
    }
}
