use crate::generators::aes_ctr::index::{AesIndex, TableIndex};
use crate::generators::aes_ctr::BYTES_PER_BATCH;
use crate::generators::{widening_mul, ByteCount, BytesPerChild, ChildrenCount, ForkError};

/// A pointer to the next byte to be outputted by the generator.
#[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct BufferPointer(pub usize);

/// State from which we can at least generate 1 byte
#[derive(Clone, Copy, Debug)]
pub(crate) struct Consumable {
    table_index: TableIndex,
    last: TableIndex,
    buffer_pointer: BufferPointer,
    offset: AesIndex,
}

impl Consumable {
    fn increment(&mut self) -> ShiftAction {
        self.table_index.increment();
        self.compute_shift_action(1)
    }

    #[cfg(test)]
    fn skip_bytes(&mut self, amount: ByteCount) {
        self.table_index.increase(amount.0);
        let new_ptr = (self.buffer_pointer.0 as u128).saturating_add(amount.0);
        self.buffer_pointer.0 = new_ptr.min(BYTES_PER_BATCH as u128) as usize;
    }

    #[inline]
    fn compute_shift_action(&mut self, shift: u128) -> ShiftAction {
        if shift >= self.left_in_buffer() as u128 {
            self.buffer_pointer.0 = self.table_index.byte_index.0;
            let index = AesIndex(self.table_index.aes_index.0.wrapping_add(self.offset.0));
            ShiftAction::RefreshBatchAndOutputByte(index, self.buffer_pointer)
        } else {
            self.buffer_pointer.0 += shift as usize;
            ShiftAction::OutputByte(self.buffer_pointer)
        }
    }

    fn left_in_buffer(&self) -> usize {
        BYTES_PER_BATCH - self.buffer_pointer.0
    }
}

/// The current state of a generator using the batched AES-CTR approach.
// Due to wrapping behavior, we need a separation between consumable and consumed state
// as FIRST-1=LAST, LAST+1=FIRST.
#[derive(Debug, Clone, Copy)]
pub(crate) enum State {
    /// The generator is fully consumed
    Consumed { last: TableIndex },
    /// The generator can produce at least 1 more byte
    NotConsumed(Consumable),
}

/// A structure representing the action to be taken by the generator after shifting its state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShiftAction {
    /// All the bytes that could be generated were generated,
    /// there are no more bytes.
    NoOutput,
    /// Outputs the byte pointed to by the 0-th field.
    OutputByte(BufferPointer),
    /// Refresh the buffer using the AES index, then output the byte at the buffer
    /// pointer
    RefreshBatchAndOutputByte(AesIndex, BufferPointer),
}

impl State {
    /// Creates a new state that will generate bytes from `next_table_index` through `last`
    /// (inclusive), i.e., the State generates bytes in range `next_table_index..=last`
    ///
    /// The `offset` AesIndex is applied to all AES encryption: AES(Key, counter + offset).
    /// This allows starting the AES counter at a specific value.
    ///
    /// If `next_table_index > last`, the state is immediately `Consumed`.
    pub(crate) fn new(next_table_index: TableIndex, last: TableIndex, offset: AesIndex) -> Self {
        // Strict `>` is correct: `next_table_index == last` means one byte remains (at `last`).
        if next_table_index > last {
            State::Consumed { last }
        } else {
            State::NotConsumed(Consumable {
                table_index: next_table_index.decremented(),
                last,
                buffer_pointer: BufferPointer(BYTES_PER_BATCH),
                offset,
            })
        }
    }

    pub(crate) fn next(&mut self) -> ShiftAction {
        match self {
            State::Consumed { .. } => ShiftAction::NoOutput,
            State::NotConsumed(consumable) => {
                let action = consumable.increment();
                if consumable.table_index == consumable.last {
                    *self = State::Consumed {
                        last: consumable.last,
                    };
                }
                action
            }
        }
    }

    pub(crate) fn next_table_index(&self) -> Option<TableIndex> {
        match self {
            State::Consumed { .. } => None,
            State::NotConsumed(consumable) => Some(consumable.table_index.incremented()),
        }
    }

    pub(crate) fn remaining_bytes(self) -> ByteCount {
        match self {
            State::Consumed { .. } => ByteCount(0),
            State::NotConsumed(state) => {
                let next = state.table_index.incremented();
                let dist = TableIndex::distance(&state.last, &next)
                    .expect("NotConsumed state has next_table_index past last");
                ByteCount(dist.0.saturating_add(1))
            }
        }
    }

    pub(crate) fn check_fork(
        &self,
        n_children: ChildrenCount,
        n_bytes: BytesPerChild,
    ) -> Result<(TableIndex, AesIndex, Self), ForkError> {
        if n_children.0 == 0 {
            return Err(ForkError::ZeroChildrenCount);
        }
        if n_bytes.0 == 0 {
            return Err(ForkError::ZeroBytesPerChild);
        }
        match self {
            State::Consumed { .. } => Err(ForkError::ForkTooLarge),
            State::NotConsumed(consumable) => {
                let end = consumable
                    .table_index
                    .increased(widening_mul(n_children.0, n_bytes.0));
                if end <= consumable.last {
                    let first_index = consumable.table_index.incremented();
                    let child_bytes = widening_mul(n_bytes.0, n_children.0);
                    let new_parent_state = State::new(
                        first_index.increased(child_bytes),
                        consumable.last,
                        consumable.offset,
                    );
                    Ok((first_index, consumable.offset, new_parent_state))
                } else {
                    Err(ForkError::ForkTooLarge)
                }
            }
        }
    }

    pub(crate) fn bound(&self) -> TableIndex {
        match self {
            State::Consumed { last } => last.incremented(),
            State::NotConsumed(consumable) => consumable.last.incremented(),
        }
    }

    #[cfg(test)]
    fn skip_bytes(&mut self, amount: ByteCount) {
        if let State::NotConsumed(state) = self {
            state.skip_bytes(amount);
            if state.table_index >= state.last {
                *self = State::Consumed { last: state.last };
            }
        }
    }

    /// Advances by `n` positions: skips `n - 1` bytes, then returns the nth.
    #[cfg(test)]
    fn advance(&mut self, n: ByteCount) -> ShiftAction {
        assert!(n.0 > 0, "advance(0) is not meaningful");
        self.skip_bytes(ByteCount(n.0 - 1));
        self.next()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::generators::aes_ctr::index::ByteIndex;
    use crate::generators::aes_ctr::BYTES_PER_AES_CALL;
    use rand::{thread_rng, Rng};

    const REPEATS: usize = 1_000_000;
    const SMALLER_REPEATS: usize = 10_000;

    fn any_table_index() -> impl Iterator<Item = TableIndex> {
        std::iter::repeat_with(|| {
            TableIndex::new(
                AesIndex(thread_rng().gen()),
                ByteIndex(thread_rng().gen::<usize>() % BYTES_PER_AES_CALL),
            )
        })
    }

    fn any_usize() -> impl Iterator<Item = usize> {
        std::iter::repeat_with(|| thread_rng().gen())
    }

    fn any_u128() -> impl Iterator<Item = u128> {
        std::iter::repeat_with(|| thread_rng().gen())
    }

    fn any_aes_index() -> impl Iterator<Item = AesIndex> {
        std::iter::repeat_with(|| AesIndex(thread_rng().gen()))
    }

    #[test]
    /// Check the property:
    ///     For all table indices t and offsets,
    ///         State::new(t, LAST, offset).next()
    ///             = RefreshBatchAndOutputByte(t.aes_index + offset, t.byte_index)
    fn prop_state_new_increment() {
        for _ in 0..REPEATS {
            let (t, mut s, offset) = any_table_index()
                .zip(any_aes_index())
                .map(|(t, offset)| (t, State::new(t, TableIndex::LAST, offset), offset))
                .next()
                .unwrap();
            assert!(matches!(
                s.next(),
                ShiftAction::RefreshBatchAndOutputByte(t_, BufferPointer(p_))
                    if t_ == AesIndex(t.aes_index.0.wrapping_add(offset.0)) && p_ == t.byte_index.0
            ))
        }
    }

    #[test]
    /// Check the property:
    ///     For all table indices t, offsets, and positive integers i,
    ///         if s = State::new(t, LAST, offset), then after skipping i bytes,
    ///         s.next_table_index() == t.increased(i).
    fn prop_state_increase_table_index() {
        for _ in 0..REPEATS {
            let (t, mut s, i) = any_table_index()
                .zip(any_u128())
                .zip(any_aes_index())
                .map(|((t, i), offset)| (t, State::new(t, TableIndex::LAST, offset), i))
                .next()
                .unwrap();
            s.skip_bytes(ByteCount(i));
            assert_eq!(s.next_table_index().unwrap(), t.increased(i))
        }
    }

    #[test]
    /// Check the property:
    ///     For all table indices t, positive integer i such that
    ///     t.byte_index + i < BYTES_PER_BATCH - 1,
    ///         if s = State::new(t, LAST, offset), and s.next() was called,
    ///         s.advance(i) = OutputByte(t.byte_index + i).
    fn prop_state_increase_small() {
        for _ in 0..REPEATS {
            let (t, mut s, i, offset) = any_table_index()
                .zip(any_usize())
                .zip(any_aes_index())
                .map(|((t, i), offset)| {
                    (
                        t,
                        State::new(t, TableIndex::LAST, offset),
                        i % BYTES_PER_BATCH,
                        offset,
                    )
                })
                .find(|(t, _, i, _)| *i > 0 && t.byte_index.0 + i < BYTES_PER_BATCH - 1)
                .unwrap();
            assert!(matches!(
                    s.next(),
                    ShiftAction::RefreshBatchAndOutputByte(index, BufferPointer(p))
                    if index == AesIndex(t.aes_index.0.wrapping_add(offset.0)) && p == t.byte_index.0 ));
            let action = s.advance(ByteCount(i as u128));
            assert!(
                matches!(
                action,
                ShiftAction::OutputByte(BufferPointer(p_)) if p_ == t.byte_index.0 + i),
                "Action is {action:?}, expected ShiftAction::OutputByte(BufferPointer({:?}))",
                t.byte_index.0 + i
            );
        }
    }
    #[test]
    /// Check the property:
    ///     For all table indices t,
    ///     positive integer i such that t.byte_index + i >= BYTES_PER_BATCH - 1,
    ///         if s = State::new(t, LAST, offset), and s.next() was called,
    ///         s.advance(i) = RefreshBatchAndOutputByte(
    ///             t.increased(i).aes_index + offset, t.increased(i).byte_index).
    fn prop_state_increase_large() {
        for _ in 0..REPEATS {
            let (t, mut s, i, offset) = any_table_index()
                .zip(any_usize())
                .zip(any_aes_index())
                .map(|((t, i), offset)| (t, State::new(t, TableIndex::LAST, offset), i, offset))
                .find(|(t, _, i, _)| *i > 0 && t.byte_index.0 + i >= BYTES_PER_BATCH - 1)
                .unwrap();
            s.next();
            let expected_index = t.increased(i as u128);
            let action = s.advance(ByteCount(i as u128));
            assert!(
                matches!(
                    action,
                    ShiftAction::RefreshBatchAndOutputByte(t_, BufferPointer(p_))
                        if t_ == AesIndex(expected_index.aes_index.0.wrapping_add(offset.0))
                            && p_ == expected_index.byte_index.0
                ),
                "Action is {action:?}, expected RefreshBatchAndOutputByte(AesIndex({:?}), BufferPointer({:?}))",
                expected_index.aes_index.0.wrapping_add(offset.0),
                expected_index.byte_index.0
            );
        }
    }

    #[test]
    fn prop_state_first_is_last() {
        for (first, offset) in any_table_index().zip(any_aes_index()).take(REPEATS) {
            let last = first;
            let mut s = State::new(first, last, offset);

            assert_eq!(s.remaining_bytes().0, 1);
            assert_ne!(s.next(), ShiftAction::NoOutput, "Expected a byte");
            assert_eq!(
                s.next(),
                ShiftAction::NoOutput,
                "Expected state to be consumed"
            );
        }
    }

    #[test]
    /// Check the property: For a state starting at FIRST and ending
    /// at LAST=FIRST+n, the state is consumed after outputting n+1 bytes.
    fn prop_state_consumed_from_first() {
        let mut rng = rand::thread_rng();
        for offset in any_aes_index().take(SMALLER_REPEATS) {
            let n = rng.gen_range(0..=u16::MAX) as u128;

            let first = TableIndex::FIRST;
            let last = first.increased(n);
            let mut s = State::new(first, last, offset);

            assert_eq!(s.remaining_bytes().0, n + 1);

            for i in 0..n + 1 {
                assert_ne!(
                    s.next(),
                    ShiftAction::NoOutput,
                    "State returned NoOutput at call {i}/{n}"
                );
            }
            assert_eq!(
                s.next(),
                ShiftAction::NoOutput,
                "State should be consumed after {n} calls"
            );
        }
    }

    #[test]
    /// Check the property:
    ///     For all table indices first, n in 0..=u16::MAX,
    ///         a state spanning n+1 bytes from first to first.increased(n)
    ///         is exhausted after exactly n+1 calls to next().
    fn prop_state_consumed_from_random() {
        let mut rng = rand::thread_rng();
        for (first_index, offset) in any_table_index().zip(any_aes_index()).take(SMALLER_REPEATS) {
            let distance_to_last = TableIndex::distance(&TableIndex::LAST, &first_index)
                .unwrap()
                .0
                .saturating_add(1);

            let n = distance_to_last.min(rng.gen_range(0..=u16::MAX as u128));

            let last = first_index.increased(n as u128);
            let mut s = State::new(first_index, last, offset);
            for i in 0..n + 1 {
                assert_ne!(
                    s.next(),
                    ShiftAction::NoOutput,
                    "State returned NoOutput at call {i}/{n}"
                );
            }
            assert_eq!(
                s.next(),
                ShiftAction::NoOutput,
                "State should be consumed after {n} calls"
            );
        }
    }

    #[test]
    /// Check the property:
    ///     For a full-range state, after skipping so that exactly n
    ///     bytes remain, the state is exhausted after n calls to next().
    fn prop_state_consumed_skip_to_end() {
        let mut rng = rand::thread_rng();
        for offset in any_aes_index().take(SMALLER_REPEATS) {
            let n = rng.gen_range(0..=u16::MAX) as u128;

            let mut s = State::new(TableIndex::FIRST, TableIndex::LAST, offset);

            // Internal table_index starts at FIRST.decremented() == LAST (wrapping).
            // We want table_index == LAST.decreased(n) after skipping, so that
            // n calls to next() bring it to LAST.
            // Forward distance from LAST to LAST.decreased(n) wrapping
            // the full 2^132 table is 2^132 - n bytes.
            // We split into u128-sized chunks since ByteCount holds u128.
            // 2^132 = 16 * 2^128, so 2^132 - n = (16 * 2^128) - n
            // = (16 * 2^128-1) + 16 - n
            if n < BYTES_PER_AES_CALL as u128 {
                for _ in 0..BYTES_PER_AES_CALL {
                    s.skip_bytes(ByteCount(u128::MAX));
                }
                s.skip_bytes(ByteCount(BYTES_PER_AES_CALL as u128 - n));
            } else {
                for _ in 0..(BYTES_PER_AES_CALL - 1) {
                    s.skip_bytes(ByteCount(u128::MAX));
                }
                s.skip_bytes(ByteCount(u128::MAX - (n - BYTES_PER_AES_CALL as u128)));
            }

            for i in 0..n {
                assert_ne!(
                    s.next(),
                    ShiftAction::NoOutput,
                    "State returned NoOutput at call {i}/{n}"
                );
            }
            assert_eq!(
                s.next(),
                ShiftAction::NoOutput,
                "State should be consumed after {n} calls"
            );
        }
    }
}
