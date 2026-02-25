use std::ops::Bound;

use crate::generators::aes_ctr::index::{AesIndex, TableIndex};
use crate::generators::aes_ctr::BYTES_PER_BATCH;
use crate::generators::{widening_mul, ByteCount, BytesPerChild, ChildrenCount, ForkError};

/// A pointer to the next byte to be outputted by the generator.
#[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct BufferPointer(pub usize);

// We don't use std::ops::Bound as it's the case for State::new
// because the Unbounded variant is never used. And as this is an
// internal type it's ok
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum AesBound {
    Included(TableIndex),
    Excluded(TableIndex),
}

/// State from which we can at least generate 1 byte
#[derive(Clone, Copy, Debug)]
pub(crate) struct Consumable {
    // Stores the index preceding the index of the value
    // to be generated on the next call to next
    table_index: TableIndex,
    // **INCLUSIVE** last valid index
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
        let (mut increased, overflowed) = self.table_index.overflowing_increased(amount.0);

        // Saturate the increased value
        if overflowed {
            increased = TableIndex::LAST;
        } else if increased > self.last {
            increased = self.last;
        }

        let new_ptr = (self.buffer_pointer.0 as u128).saturating_add(amount.0);
        self.buffer_pointer.0 = new_ptr.min(BYTES_PER_BATCH as u128) as usize;
        self.table_index = increased;
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
    Consumed { bound: AesBound },
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
    /// Creates a new state that will generate bytes starting from `next_table_index`
    /// up to the given `end` bound.
    ///
    /// - `Bound::Included(x)` — last valid byte is at `x`
    /// - `Bound::Excluded(x)` — last valid byte is at `x.decremented()`
    /// - `Bound::Unbounded` — last valid byte is at `TableIndex::LAST`
    ///
    /// The `offset` AesIndex is applied to all AES encryption: AES(Key, counter + offset).
    pub(crate) fn new(
        next_table_index: TableIndex,
        end: Bound<TableIndex>,
        offset: AesIndex,
    ) -> Self {
        let last = match end {
            Bound::Included(x) => x,
            Bound::Excluded(x) => {
                // Excluded(FIRST) means the range is empty, no matter next_table_index
                // we cant just decrement it as it would wrap to LAST, leading to an Unbounded
                // range
                if x == TableIndex::FIRST {
                    return Self::Consumed {
                        bound: AesBound::Excluded(x),
                    };
                }
                x.decremented()
            }
            Bound::Unbounded => TableIndex::LAST,
        };
        // Strict `>` is correct: `next_table_index == last` means one byte remains (at `last`).
        if next_table_index > last {
            State::Consumed {
                bound: AesBound::Included(last),
            }
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
                        bound: AesBound::Included(consumable.last),
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
                // Always valid (no overflow) as NotConsumed guarantees at least one byte remains
                let first_index = consumable.table_index.incremented();

                // Children occupy [first_index, first_index + fork_amount).
                // `increased` uses wrapping arithmetic on aes_index, so this may wrap past LAST
                // back to [FIRST, first_index). The overflow is detected below.
                // If no wrap, the result is in (first_index, LAST].
                let children_excluded_bound =
                    first_index.increased(widening_mul(n_children.0, n_bytes.0));

                // Convert excluded bound to inclusive last. If children_excluded_bound == FIRST
                // (the fork wrapped exactly to the start), FIRST.decremented() == LAST, which
                // correctly represents the last included byte of the children's range.
                //
                // The fork amount is non-zero (both n_children and n_bytes are >= 1), so the
                // minimum fork is 1 byte, giving children_included_last >= first_index at worst
                let children_included_last = children_excluded_bound.decremented();

                // Overflow detection: if children_included_last < first_index, the excluded
                // bound wrapped past LAST.
                //
                // This check has no false negatives: a wrap cannot land back at or past
                // first_index because the fork amount (u64 * u64 < 2^128) is strictly less
                // than the table index cycle (2^132 values). A full cycle would require
                // a shift >= 2^132, which is impossible with a < 2^128 fork amount (it is even
                // impossible with a TableIndex value as its max representable value is (2^132 -1))
                //
                // We use `increased` + some checks instead of `overflowing_increased` because
                // the latter would still need correction for the excluded-to-inclusive
                // conversion (e.g., excluded bound overflows to FIRST, inclusive last is LAST).
                if children_included_last < first_index || children_included_last > consumable.last
                {
                    return Err(ForkError::ForkTooLarge);
                }

                // Children may consume all parent bytes (parent becomes Consumed)
                let new_parent_state = if children_included_last == consumable.last {
                    // Cannot call Self::new with children_included_last.incremented() here:
                    // if last == LAST, incrementing wraps to FIRST, and Self::new would create
                    // a fresh iterator over the entire space instead of an empty one.
                    State::Consumed {
                        bound: AesBound::Included(consumable.last),
                    }
                } else {
                    let parent_first_index = children_included_last.incremented();
                    Self::new(
                        parent_first_index,
                        Bound::Included(consumable.last),
                        consumable.offset,
                    )
                };
                let first_index = consumable.table_index.incremented();
                Ok((first_index, consumable.offset, new_parent_state))
            }
        }
    }

    pub(crate) fn bound(&self) -> AesBound {
        match self {
            State::Consumed { bound } => *bound,
            State::NotConsumed(consumable) => AesBound::Included(consumable.last),
        }
    }

    #[cfg(test)]
    fn skip_bytes(&mut self, amount: ByteCount) {
        if let State::NotConsumed(state) = self {
            state.skip_bytes(amount);
            if state.table_index >= state.last {
                *self = State::Consumed {
                    bound: AesBound::Included(state.last),
                };
            }
        }
    }

    /// Advances by `n` positions: skips `n` bytes, then returns the next.
    /// Matches `Iterator::nth` semantics: nth(0) returns the next element.
    #[cfg(test)]
    fn nth(&mut self, n: ByteCount) -> ShiftAction {
        self.skip_bytes(ByteCount(n.0));
        self.next()
    }
}

#[cfg(test)]
mod test {
    use std::ops::Bound;

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
                .map(|(t, offset)| {
                    (
                        t,
                        State::new(t, Bound::Included(TableIndex::LAST), offset),
                        offset,
                    )
                })
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
                .map(|((t, i), offset)| {
                    (
                        t,
                        State::new(t, Bound::Included(TableIndex::LAST), offset),
                        i,
                    )
                })
                .next()
                .unwrap();
            s.skip_bytes(ByteCount(i));
            match s.next_table_index() {
                // The increase is in range
                Some(idx) => assert_eq!(idx, t.increased(i)),
                // No next index means the state is consumed
                // Since the bound is LAST is means there was an overflow
                None => assert!(t.overflowing_increased(i).1),
            }
        }
    }

    #[test]
    /// For all table indices t, offsets, and non-negative integers i,
    ///     State::new(t, LAST, offset).nth(i)
    ///         = RefreshBatchAndOutputByte(
    ///             t.increased(i).aes_index + offset,
    ///             t.increased(i).byte_index)
    fn prop_state_nth() {
        for _ in 0..REPEATS {
            let (t, mut s, i, offset) = any_table_index()
                .zip(any_usize())
                .zip(any_aes_index())
                .map(|((t, i), offset)| {
                    (
                        t,
                        State::new(t, Bound::Included(TableIndex::LAST), offset),
                        i,
                        offset,
                    )
                })
                .next()
                .unwrap();
            let expected = t.increased(i as u128);
            let action = s.nth(ByteCount(i as u128));
            assert!(
                matches!(
                    action,
                    ShiftAction::RefreshBatchAndOutputByte(idx, BufferPointer(p))
                        if idx == AesIndex(expected.aes_index.0.wrapping_add(offset.0))
                            && p == expected.byte_index.0
                ),
                "nth({i}): got {action:?}, expected RefreshBatch at {expected:?}+{offset:?}",
            );
        }
    }

    #[test]
    fn prop_state_first_is_last() {
        for (first, offset) in any_table_index().zip(any_aes_index()).take(REPEATS) {
            let last = first;
            let mut s = State::new(first, Bound::Included(last), offset);

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
            let mut s = State::new(first, Bound::Included(last), offset);

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
            let mut s = State::new(first_index, Bound::Included(last), offset);
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
    ///     For a state spanning exactly u128::MAX+1 bytes near the end of the
    ///     table, after skipping so that exactly n+1 bytes remain, the state is
    ///     exhausted after n+1 calls to next().
    fn prop_state_consumed_skip_to_end() {
        let mut rng = rand::thread_rng();
        for offset in any_aes_index().take(SMALLER_REPEATS) {
            let n = rng.gen_range(0..=u16::MAX) as u128;

            // Range of exactly u128::MAX+1 bytes: [LAST - u128::MAX, LAST]
            let first = TableIndex::LAST.decreased(u128::MAX);
            let mut s = State::new(first, Bound::Unbounded, offset);

            // Single skip: u128::MAX - n leaves n+1 bytes remaining
            s.skip_bytes(ByteCount(u128::MAX - n));

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
                "State should be consumed after {} calls",
                n + 1,
            );
        }
    }

    #[test]
    fn test_excluded_first_is_immediately_consumed() {
        for first in any_table_index().take(10) {
            let s = State::new(
                first,
                Bound::Excluded(TableIndex::FIRST),
                AesIndex(rand::random()),
            );
            assert!(matches!(s, State::Consumed { .. }));
            assert_eq!(s.remaining_bytes().0, 0);
        }
    }

    #[test]
    fn test_start_past_end_is_immediately_consumed() {
        let mut rng = rand::thread_rng();
        for (offset, last) in any_aes_index().zip(any_table_index()).take(SMALLER_REPEATS) {
            let gap = rng.gen_range(1..=u16::MAX) as u128;
            let (first, overflowed) = last.overflowing_increased(gap);
            if overflowed {
                continue;
            }

            let s = State::new(first, Bound::Included(last), offset);
            assert!(matches!(s, State::Consumed { .. }));
            assert_eq!(s.remaining_bytes().0, 0);
        }
    }

    #[test]
    fn test_check_fork_on_consumed_state() {
        for offset in any_aes_index().take(SMALLER_REPEATS) {
            let s = State::new(
                TableIndex::FIRST,
                Bound::Excluded(TableIndex::FIRST),
                offset,
            );
            assert!(matches!(s, State::Consumed { .. }));
            assert!(matches!(
                s.check_fork(ChildrenCount(1), BytesPerChild(1)),
                Err(ForkError::ForkTooLarge),
            ));
        }
    }

    #[test]
    fn test_check_fork_zero_children_or_bytes() {
        for offset in any_aes_index().take(SMALLER_REPEATS) {
            let s = State::new(TableIndex::FIRST, Bound::Unbounded, offset);
            assert!(matches!(
                s.check_fork(ChildrenCount(0), BytesPerChild(1)),
                Err(ForkError::ZeroChildrenCount),
            ));
            assert!(matches!(
                s.check_fork(ChildrenCount(1), BytesPerChild(0)),
                Err(ForkError::ZeroBytesPerChild),
            ));
        }
    }

    #[test]
    fn test_check_fork_boundary() {
        let mut rng = rand::thread_rng();

        // Test where first=FIRST and last=FIRST+something
        for offset in any_aes_index().take(SMALLER_REPEATS) {
            let n_children = rng.gen_range(1..=16_u64);
            let n_bytes = rng.gen_range(1..=16_u64);
            let total = widening_mul(n_children, n_bytes);

            let first = TableIndex::FIRST;

            {
                // State with exactly total+1 bytes: fork takes `total`, parent keeps 1
                let last = first.increased(total);
                let s = State::new(first, Bound::Included(last), offset);
                assert_eq!(s.remaining_bytes().0, total + 1);

                let result = s.check_fork(ChildrenCount(n_children), BytesPerChild(n_bytes));
                assert!(result.is_ok(), "Fork leaving 1 parent byte should succeed");
                let (fork_first, _, parent_state) = result.unwrap();
                assert_eq!(fork_first, first);
                assert_eq!(parent_state.remaining_bytes().0, 1);
            }

            {
                // State with exactly total bytes: fork takes all, no parent bytes left
                let last = first.increased(total - 1);
                let s = State::new(first, Bound::Included(last), offset);
                assert_eq!(s.remaining_bytes().0, total);

                let result = s.check_fork(ChildrenCount(n_children), BytesPerChild(n_bytes));
                assert!(
                    result.is_ok(),
                    "Fork consuming all parent bytes should be ok"
                );
                let (ret_first_index, ret_offset, new_parent_state) = result.unwrap();
                assert_eq!(ret_first_index, first);
                assert_eq!(ret_offset, offset);
                assert!(matches!(
                    new_parent_state,
                    State::Consumed {
                        bound: AesBound::Included(l)
                    } if l == last
                ));
            }

            {
                // Another way to express fork takes all
                let last = first.increased(total);
                let s = State::new(first, Bound::Excluded(last), offset);
                assert_eq!(s.remaining_bytes().0, total);

                let result = s.check_fork(ChildrenCount(n_children), BytesPerChild(n_bytes));
                assert!(
                    result.is_ok(),
                    "Fork consuming all parent bytes should be ok"
                );
                let (ret_first_index, ret_offset, new_parent_state) = result.unwrap();
                assert_eq!(ret_first_index, first);
                assert_eq!(ret_offset, offset);
                assert!(matches!(
                    new_parent_state,
                    State::Consumed {
                        bound: AesBound::Included(l)
                    } if l == last.decremented()
                ));
            }
        }

        // Test where last=LAST and first=LAST-something (exercises wrapping in increased())
        for offset in any_aes_index().take(SMALLER_REPEATS) {
            let n_children = rng.gen_range(1..=16_u64);
            let n_bytes = rng.gen_range(1..=16_u64);
            let total = widening_mul(n_children, n_bytes);

            let last = TableIndex::LAST;

            {
                let first = last.decreased(total);
                let s = State::new(first, Bound::Included(last), offset);
                assert_eq!(s.remaining_bytes().0, total + 1);

                let result = s.check_fork(ChildrenCount(n_children), BytesPerChild(n_bytes));
                assert!(result.is_ok(), "Fork leaving 1 parent byte should succeed");
                let (fork_first, _, parent_state) = result.unwrap();
                assert_eq!(fork_first, first);
                assert_eq!(parent_state.remaining_bytes().0, 1);
            }

            {
                // State with exactly total bytes: fork takes all, no parent bytes left
                let first = last.decreased(total - 1);
                let s = State::new(first, Bound::Included(last), offset);
                assert_eq!(s.remaining_bytes().0, total);

                let result = s.check_fork(ChildrenCount(n_children), BytesPerChild(n_bytes));
                assert!(
                    result.is_ok(),
                    "Fork consuming all parent bytes should be ok"
                );
                let (ret_first_index, ret_offset, new_parent_state) = result.unwrap();
                assert_eq!(ret_first_index, first);
                assert_eq!(ret_offset, offset);
                assert!(matches!(
                    new_parent_state,
                    State::Consumed {
                        bound: AesBound::Included(l)
                    } if l == last
                ));
            }

            {
                // Another way to express fork takes all
                let first = last.decreased(total);
                let s = State::new(first, Bound::Excluded(last), offset);
                assert_eq!(s.remaining_bytes().0, total);

                let result = s.check_fork(ChildrenCount(n_children), BytesPerChild(n_bytes));
                assert!(
                    result.is_ok(),
                    "Fork consuming all parent bytes should be ok"
                );
                let (ret_first_index, ret_offset, new_parent_state) = result.unwrap();
                assert_eq!(ret_first_index, first);
                assert_eq!(ret_offset, offset);
                assert!(matches!(
                    new_parent_state,
                    State::Consumed {
                        bound: AesBound::Included(l)
                    } if l == last.decremented()
                ));
            }
        }
    }

    #[test]
    fn test_check_fork_overflow() {
        for offset in any_aes_index().take(SMALLER_REPEATS) {
            let s = State::new(TableIndex::LAST, Bound::Unbounded, offset);
            assert_eq!(s.remaining_bytes().0, 1);

            // 2 children * u64::MAX bytes each overflows the table index space
            assert!(matches!(
                s.check_fork(ChildrenCount(2), BytesPerChild(u64::MAX)),
                Err(ForkError::ForkTooLarge),
            ));
        }
    }

    // Test that skipping by an amount >= than the number of bytes possible
    // saturates and more importantly, consumes the state
    #[test]
    fn prop_state_skip_saturates() {
        let mut rng = rand::thread_rng();
        for offset in any_aes_index().take(SMALLER_REPEATS) {
            let n = rng.gen_range(0..=u128::MAX - 1) as u128;

            // Check when the end is unbounded, as this relies on overflow detection
            {
                // to create a state with n+1 bytes remaining
                let first = TableIndex::LAST.decreased(n);

                let mut s = State::new(first, Bound::Unbounded, offset);
                s.skip_bytes(ByteCount(n));
                assert_ne!(s.next(), ShiftAction::NoOutput); // One valid byte
                assert_eq!(s.next(), ShiftAction::NoOutput);

                let mut s = State::new(first, Bound::Unbounded, offset);
                s.skip_bytes(ByteCount(n + 1));
                assert_eq!(s.next(), ShiftAction::NoOutput); // Not even one valid byte

                let mut s = State::new(first, Bound::Unbounded, offset);
                let skip = rng.gen_range(n + 1..=u128::MAX);
                s.skip_bytes(ByteCount(skip));
                assert_eq!(s.next(), ShiftAction::NoOutput); // Not even one valid byte
            }

            // Test with a bounded (Inclusive)
            {
                // to create a state with n+1 bytes remaining
                let last = TableIndex::LAST.decreased(n);
                let first = last.decreased(n);

                let mut s = State::new(first, Bound::Included(last), offset);
                s.skip_bytes(ByteCount(n));
                assert_ne!(s.next(), ShiftAction::NoOutput); // One valid byte
                assert_eq!(s.next(), ShiftAction::NoOutput);

                let mut s = State::new(first, Bound::Included(last), offset);
                s.skip_bytes(ByteCount(n + 1));
                assert_eq!(s.next(), ShiftAction::NoOutput); // Not even one valid byte

                let mut s = State::new(first, Bound::Included(last), offset);
                let skip = rng.gen_range(n + 1..=u128::MAX);
                s.skip_bytes(ByteCount(skip));
                assert_eq!(s.next(), ShiftAction::NoOutput); // Not even one valid byte
            }

            // Test with a bounded (Exclusive)
            {
                // to create a state with n+1 bytes remaining
                let last = TableIndex::LAST.decreased(n);
                let first = last.decreased(n);

                let mut s = State::new(first, Bound::Excluded(last), offset);
                s.skip_bytes(ByteCount(n));
                assert_eq!(s.next(), ShiftAction::NoOutput); // Not even one valid byte

                let mut s = State::new(first, Bound::Excluded(last), offset);
                s.skip_bytes(ByteCount(n + 1));
                assert_eq!(s.next(), ShiftAction::NoOutput); // Not even one valid byte

                let mut s = State::new(first, Bound::Excluded(last), offset);
                let skip = rng.gen_range(n + 1..=u128::MAX);
                s.skip_bytes(ByteCount(skip));
                assert_eq!(s.next(), ShiftAction::NoOutput); // Not even one valid byte
            }
        }
    }
}
