use crate::generators::aes_ctr::index::{AesIndex, TableIndex};
use crate::generators::aes_ctr::BYTES_PER_BATCH;

/// A pointer to the next byte to be outputted by the generator.
#[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct BufferPointer(pub usize);

/// A structure representing the current state of generator using batched aes-ctr approach.
#[derive(Debug, Clone, Copy)]
pub struct State {
    table_index: TableIndex,
    buffer_pointer: BufferPointer,
    offset: AesIndex,
}

/// A structure representing the action to be taken by the generator after shifting its state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShiftAction {
    /// Outputs the byte pointed to by the 0-th field.
    OutputByte(BufferPointer),
    /// Refresh the buffer starting from the 0-th field, and output the byte pointed to by the 0-th
    /// field.
    RefreshBatchAndOutputByte(AesIndex, BufferPointer),
}

impl State {
    /// Creates a new state from the initial table index and offset
    ///
    /// The `offset` AesIndex will be applied to all AES encryption.
    /// AES(Key, counter + offset).
    /// This is to be used when one wants to start the AES
    /// counter at a specific value but still output all the (2^128-1) values
    ///
    /// Note:
    /// ------
    ///
    /// The `table_index` input is the __first__ table index that will be outputted on the next
    /// call to `increment`. Put differently, the current table index of the newly created state
    /// is the predecessor of this one.
    pub fn new(table_index: TableIndex, offset: AesIndex) -> Self {
        // We ensure that the table index is not the first one, to prevent wrapping on `decrement`,
        // and outputting `RefreshBatchAndOutputByte(AesIndex::MAX, ...)` on the first increment
        // (which would lead to loading a non-continuous batch).
        assert_ne!(table_index, TableIndex::FIRST);
        Self {
            // To ensure that the first outputted table index is the proper one, we decrement the
            // table index.
            table_index: table_index.decremented(),
            // To ensure that the first `ShiftAction` will be a `RefreshBatchAndOutputByte`, we set
            // the buffer to the last allowed value.
            buffer_pointer: BufferPointer(BYTES_PER_BATCH - 1),
            offset,
        }
    }

    /// Shifts the state forward of `shift` bytes.
    pub fn increase(&mut self, shift: u128) -> ShiftAction {
        self.table_index.increase(shift);
        let total_batch_index = self.buffer_pointer.0 as u128 + shift;
        if total_batch_index > BYTES_PER_BATCH as u128 - 1 {
            self.buffer_pointer.0 = self.table_index.byte_index.0;
            let index = AesIndex(self.table_index.aes_index.0.wrapping_add(self.offset.0));
            ShiftAction::RefreshBatchAndOutputByte(index, self.buffer_pointer)
        } else {
            // Ok to unwrap because total_batch_index <= BYTES_PER_BATCH < usize::MAX
            self.buffer_pointer.0 = usize::try_from(total_batch_index).unwrap();
            ShiftAction::OutputByte(self.buffer_pointer)
        }
    }

    /// Shifts the state forward of one byte.
    pub fn increment(&mut self) -> ShiftAction {
        self.increase(1)
    }

    /// Returns the current table index.
    pub fn table_index(&self) -> TableIndex {
        self.table_index
    }

    pub fn offset(&self) -> AesIndex {
        self.offset
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::generators::aes_ctr::index::ByteIndex;
    use crate::generators::aes_ctr::BYTES_PER_AES_CALL;
    use rand::{thread_rng, Rng};

    const REPEATS: usize = 1_000_000;

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
    ///     For all table indices t,
    ///         State::new(t).increment() = RefreshBatchAndOutputByte(t.aes_index, t.byte_index)
    fn prop_state_new_increment() {
        for _ in 0..REPEATS {
            let (t, mut s, offset) = any_table_index()
                .zip(any_aes_index())
                .map(|(t, offset)| (t, State::new(t, offset), offset))
                .next()
                .unwrap();
            assert!(matches!(
                s.increment(),
                ShiftAction::RefreshBatchAndOutputByte(t_, BufferPointer(p_))
                    if t_ == AesIndex(t.aes_index.0.wrapping_add(offset.0)) && p_ == t.byte_index.0
            ))
        }
    }

    #[test]
    /// Check the property:
    ///     For all states s, table indices t, positive integer i
    ///         if s = State::new(t), then t.increased(i) = s.increased(i-1).table_index().
    fn prop_state_increase_table_index() {
        for _ in 0..REPEATS {
            let (t, mut s, i) = any_table_index()
                .zip(any_u128())
                .zip(any_aes_index())
                .map(|((t, i), offset)| (t, State::new(t, offset), i))
                .next()
                .unwrap();
            s.increase(i);
            assert_eq!(s.table_index(), t.increased(i - 1))
        }
    }

    #[test]
    /// Check the property:
    ///     For all table indices t, positive integer i such as t.byte_index + i < 127,
    ///         if s = State::new(t), and s.increment() was executed, then
    ///         s.increase(i) = OutputByte(t.byte_index + i).
    fn prop_state_increase_small() {
        for _ in 0..REPEATS {
            let (t, mut s, i) = any_table_index()
                .zip(any_usize())
                .zip(any_aes_index())
                .map(|((t, i), offset)| (t, State::new(t, offset), i % BYTES_PER_BATCH))
                .find(|(t, _, i)| t.byte_index.0 + i < BYTES_PER_BATCH - 1)
                .unwrap();
            s.increment();
            assert!(matches!(
                s.increase(i as u128),
                ShiftAction::OutputByte(BufferPointer(p_)) if p_ == t.byte_index.0 + i
            ));
        }
    }

    #[test]
    /// Check the property:
    ///     For all table indices t, positive integer i such as t.byte_index + i >= 127,
    ///         if s = State::new(t), and s.increment() was executed, then
    ///         s.increase(i) = RefreshBatchAndOutputByte(
    ///             t.increased(i).aes_index,
    ///             t.increased(i).byte_index).
    fn prop_state_increase_large() {
        for _ in 0..REPEATS {
            let (t, mut s, i, offset) = any_table_index()
                .zip(any_usize())
                .zip(any_aes_index())
                .map(|((t, i), offset)| (t, State::new(t, offset), i, offset))
                .find(|(t, _, i, _)| t.byte_index.0 + i >= BYTES_PER_BATCH - 1)
                .unwrap();
            s.increment();
            assert!(matches!(
                s.increase(i as u128),
                ShiftAction::RefreshBatchAndOutputByte(t_, BufferPointer(p_))
                    if t_ == AesIndex(t.increased(i as u128).aes_index.0.wrapping_add(offset.0))
                        && p_ == t.increased(i as u128).byte_index.0
            ));
        }
    }
}
