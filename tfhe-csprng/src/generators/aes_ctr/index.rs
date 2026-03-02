use crate::generators::aes_ctr::BYTES_PER_AES_CALL;
use crate::generators::backward_compatibility::{
    AesIndexVersions, ByteIndexVersions, TableIndexVersions,
};
use crate::generators::ByteCount;
use std::cmp::Ordering;
use tfhe_versionable::Versionize;

/// A structure representing an [aes index](#coarse-grained-pseudo-random-table-lookup).
#[derive(
    Clone,
    Copy,
    Debug,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    Versionize,
)]
#[versionize(AesIndexVersions)]
pub struct AesIndex(pub u128);

/// A structure representing a [byte index](#fine-grained-pseudo-random-table-lookup).
#[derive(
    Clone,
    Copy,
    Debug,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    Versionize,
)]
#[versionize(ByteIndexVersions)]
pub struct ByteIndex(pub usize);

/// A structure representing a [table index](#fine-grained-pseudo-random-table-lookup)
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(TableIndexVersions)]
pub struct TableIndex {
    pub(crate) aes_index: AesIndex,
    pub(crate) byte_index: ByteIndex,
}

impl TableIndex {
    /// The first table index.
    pub const FIRST: TableIndex = TableIndex {
        aes_index: AesIndex(0),
        byte_index: ByteIndex(0),
    };

    /// The second table index.
    pub const SECOND: TableIndex = TableIndex {
        aes_index: AesIndex(0),
        byte_index: ByteIndex(1),
    };

    /// The last table index.
    pub const LAST: TableIndex = TableIndex {
        aes_index: AesIndex(u128::MAX),
        byte_index: ByteIndex(BYTES_PER_AES_CALL - 1),
    };

    /// Creates a table index from an aes index and a byte index.
    #[allow(unused)] // to please clippy when tests are not activated
    pub fn new(aes_index: AesIndex, byte_index: ByteIndex) -> Self {
        assert!(byte_index.0 < BYTES_PER_AES_CALL);
        TableIndex {
            aes_index,
            byte_index,
        }
    }

    /// Shifts the table index forward of `shift` bytes.
    pub fn increase(&mut self, shift: u128) {
        // Compute full shifts to avoid overflows
        let full_aes_shifts = shift / BYTES_PER_AES_CALL as u128;
        let shift_remainder = (shift % BYTES_PER_AES_CALL as u128) as usize;

        // Get the additional shift if any
        let new_byte_index = self.byte_index.0 + shift_remainder;
        let full_aes_shifts = full_aes_shifts + (new_byte_index / BYTES_PER_AES_CALL) as u128;

        // Store the remainder in the byte index
        self.byte_index.0 = new_byte_index % BYTES_PER_AES_CALL;

        self.aes_index.0 = self.aes_index.0.wrapping_add(full_aes_shifts);
    }

    /// Shifts the table index backward of `shift` bytes.
    pub fn decrease(&mut self, shift: u128) {
        let remainder = (shift % BYTES_PER_AES_CALL as u128) as usize;
        if remainder <= self.byte_index.0 {
            self.aes_index.0 = self
                .aes_index
                .0
                .wrapping_sub(shift / BYTES_PER_AES_CALL as u128);
            self.byte_index.0 -= remainder;
        } else {
            self.aes_index.0 = self
                .aes_index
                .0
                .wrapping_sub((shift / BYTES_PER_AES_CALL as u128) + 1);
            self.byte_index.0 += BYTES_PER_AES_CALL - remainder;
        }
    }

    /// Shifts the table index forward of one byte.
    pub fn increment(&mut self) {
        self.increase(1)
    }

    /// Shifts the table index backward of one byte.
    pub fn decrement(&mut self) {
        self.decrease(1)
    }

    /// Returns the table index shifted forward by `shift` bytes.
    pub fn increased(mut self, shift: u128) -> Self {
        self.increase(shift);
        self
    }

    /// Returns the table index shifted backward by `shift` bytes.
    #[allow(unused)] // to please clippy when tests are not activated
    pub fn decreased(mut self, shift: u128) -> Self {
        self.decrease(shift);
        self
    }

    /// Returns the table index to the next byte.
    pub fn incremented(mut self) -> Self {
        self.increment();
        self
    }

    /// Returns the table index to the previous byte.
    pub fn decremented(mut self) -> Self {
        self.decrement();
        self
    }

    /// Returns the distance between two table indices in bytes.
    ///
    /// Note:
    /// -----
    ///
    /// This method assumes that the `larger` input is, well, larger than the `smaller` input. If
    /// this is not the case, the method returns `None`. Also, note that `ByteCount` uses the
    /// `u128` datatype to store the byte count. Unfortunately, the number of bytes between two
    /// table indices is in ⟦0;2¹³² -1⟧. When the distance is greater than 2¹²⁸ - 1, we saturate
    /// the count at 2¹²⁸ - 1.
    pub fn distance(larger: &Self, smaller: &Self) -> Option<ByteCount> {
        match std::cmp::Ord::cmp(larger, smaller) {
            Ordering::Less => None,
            Ordering::Equal => Some(ByteCount(0)),
            Ordering::Greater => {
                let mut result = larger.aes_index.0 - smaller.aes_index.0;
                result = result.saturating_mul(BYTES_PER_AES_CALL as u128);
                result = result.saturating_add(larger.byte_index.0 as u128);
                result = result.saturating_sub(smaller.byte_index.0 as u128);
                Some(ByteCount(result))
            }
        }
    }
}

impl Eq for TableIndex {}

impl PartialEq<Self> for TableIndex {
    fn eq(&self, other: &Self) -> bool {
        matches!(self.partial_cmp(other), Some(Ordering::Equal))
    }
}

impl PartialOrd<Self> for TableIndex {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TableIndex {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.aes_index.cmp(&other.aes_index) {
            Ordering::Equal => self.byte_index.cmp(&other.byte_index),
            other => other,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
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

    fn any_u128() -> impl Iterator<Item = u128> {
        std::iter::repeat_with(|| thread_rng().gen())
    }

    #[test]
    #[should_panic]
    /// Verifies that the constructor of `TableIndex` panics when the byte index is too large.
    fn test_table_index_new_panic() {
        TableIndex::new(AesIndex(12), ByteIndex(144));
    }

    #[test]
    /// Verifies that the `TableIndex` wraps nicely with predecessor
    fn test_table_index_predecessor_edge() {
        assert_eq!(TableIndex::FIRST.decremented(), TableIndex::LAST);
    }

    #[test]
    /// Verifies that the `TableIndex` wraps nicely with successor
    fn test_table_index_successor_edge() {
        assert_eq!(TableIndex::LAST.incremented(), TableIndex::FIRST);
    }

    #[test]
    /// Check that the table index distance saturates nicely.
    fn prop_table_index_distance_saturates() {
        assert_eq!(
            TableIndex::distance(&TableIndex::LAST, &TableIndex::FIRST)
                .unwrap()
                .0,
            u128::MAX
        )
    }

    #[test]
    /// Check the property:
    ///     For all table indices t,
    ///         distance(t, t) = Some(0).
    fn prop_table_index_distance_zero() {
        for _ in 0..REPEATS {
            let t = any_table_index().next().unwrap();
            assert_eq!(TableIndex::distance(&t, &t), Some(ByteCount(0)));
        }
    }

    #[test]
    /// Check the property:
    ///     For all table indices t1, t2 such that t1 < t2,
    ///         distance(t1, t2) = None.
    fn prop_table_index_distance_wrong_order_none() {
        for _ in 0..REPEATS {
            let (t1, t2) = any_table_index()
                .zip(any_table_index())
                .find(|(t1, t2)| t1 < t2)
                .unwrap();
            assert_eq!(TableIndex::distance(&t1, &t2), None);
        }
    }

    #[test]
    /// Check the property:
    ///     For all table indices t1, t2 such that t1 > t2,
    ///         distance(t1, t2) = Some(v) where v is strictly positive.
    fn prop_table_index_distance_some_positive() {
        for _ in 0..REPEATS {
            let (t1, t2) = any_table_index()
                .zip(any_table_index())
                .find(|(t1, t2)| t1 > t2)
                .unwrap();
            assert!(matches!(TableIndex::distance(&t1, &t2), Some(ByteCount(v)) if v > 0));
        }
    }

    #[test]
    /// Check the property:
    ///     For all table indices t, positive i such that i < distance (MAX, t) with MAX the largest
    ///     table index,
    ///         distance(t.increased(i), t) = Some(i).
    fn prop_table_index_distance_increase() {
        for _ in 0..REPEATS {
            let (t, inc) = any_table_index()
                .zip(any_u128())
                .find(|(t, inc)| (*inc) < TableIndex::distance(&TableIndex::LAST, t).unwrap().0)
                .unwrap();
            assert_eq!(TableIndex::distance(&t.increased(inc), &t).unwrap().0, inc);
        }
    }

    #[test]
    /// Check the property:
    ///     For all table indices t, t =? t = true.
    fn prop_table_index_equality() {
        for _ in 0..REPEATS {
            let t = any_table_index().next().unwrap();
            assert_eq!(
                std::cmp::PartialOrd::partial_cmp(&t, &t),
                Some(std::cmp::Ordering::Equal)
            );
        }
    }

    #[test]
    /// Check the property:
    ///     For all table indices t, positive i such that i < distance (MAX, t) with MAX the largest
    ///     table index,
    ///         t.increased(i) >? t = true.
    fn prop_table_index_greater() {
        for _ in 0..REPEATS {
            let (t, inc) = any_table_index()
                .zip(any_u128())
                .find(|(t, inc)| *inc < TableIndex::distance(&TableIndex::LAST, t).unwrap().0)
                .unwrap();
            assert_eq!(
                std::cmp::PartialOrd::partial_cmp(&t.increased(inc), &t),
                Some(std::cmp::Ordering::Greater),
            );
        }
    }

    #[test]
    /// Check the property:
    ///     For all table indices t, positive i such that i < distance (t, 0) with MAX the largest
    ///     table index,
    ///         t.decreased(i) <? t = true.
    fn prop_table_index_less() {
        for _ in 0..REPEATS {
            let (t, inc) = any_table_index()
                .zip(any_u128())
                .find(|(t, inc)| *inc < TableIndex::distance(t, &TableIndex::FIRST).unwrap().0)
                .unwrap();
            assert_eq!(
                std::cmp::PartialOrd::partial_cmp(&t.decreased(inc), &t),
                Some(std::cmp::Ordering::Less)
            );
        }
    }

    #[test]
    /// Check the property:
    ///     For all table indices t,
    ///         successor(predecessor(t)) = t.
    fn prop_table_index_decrement_increment() {
        for _ in 0..REPEATS {
            let t = any_table_index().next().unwrap();
            assert_eq!(t.decremented().incremented(), t);
        }
    }

    #[test]
    /// Check the property:
    ///     For all table indices t,
    ///         predecessor(successor(t)) = t.
    fn prop_table_index_increment_decrement() {
        for _ in 0..REPEATS {
            let t = any_table_index().next().unwrap();
            assert_eq!(t.incremented().decremented(), t);
        }
    }

    #[test]
    /// Check the property:
    ///     For all table indices t, positive integer i,
    ///         decrease(increase(t, i), i) = t.
    fn prop_table_index_increase_decrease() {
        for _ in 0..REPEATS {
            let (t, i) = any_table_index().zip(any_u128()).next().unwrap();
            assert_eq!(t.increased(i).decreased(i), t);
        }
    }

    #[test]
    /// Check the property:
    ///     For all table indices t, positive integer i,
    ///         increase(decrease(t, i), i) = t.
    fn prop_table_index_decrease_increase() {
        for _ in 0..REPEATS {
            let (t, i) = any_table_index().zip(any_u128()).next().unwrap();
            assert_eq!(t.decreased(i).increased(i), t);
        }
    }

    #[test]
    /// Check that a big increase does not overflow
    fn prop_table_increase_max_no_overflow() {
        let first = TableIndex::FIRST;
        // Increase so that ByteIndex is at 1usize
        let second = first.increased(1);

        // Now increase by usize::MAX, as the underlying byte index stores a usize this may overflow
        // depending on implementation, ensure it does not overflow
        let big_increase = second.increased(usize::MAX as u128);
        let total_full_aes_shifts = (1u128 + usize::MAX as u128) / BYTES_PER_AES_CALL as u128;

        assert_eq!(
            big_increase,
            TableIndex::new(AesIndex(total_full_aes_shifts), ByteIndex(0))
        );
    }
}
