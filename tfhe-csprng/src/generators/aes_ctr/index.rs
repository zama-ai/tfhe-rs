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
#[derive(
    Clone,
    Copy,
    Debug,
    serde::Serialize,
    serde::Deserialize,
    Versionize,
    PartialEq,
    PartialOrd,
    Eq,
    Ord,
)]
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

    /// Shifts the table index forward of `shift` bytes.
    pub fn overflowing_increased(&self, shift: u128) -> (Self, bool) {
        // Compute full shifts to avoid overflows
        let full_aes_shifts = shift / BYTES_PER_AES_CALL as u128;
        let shift_remainder = (shift % BYTES_PER_AES_CALL as u128) as usize;

        // Get the additional shift if any
        let new_byte_index = self.byte_index.0 + shift_remainder;
        let full_aes_shifts = full_aes_shifts + (new_byte_index / BYTES_PER_AES_CALL) as u128;

        let (new_index, overflowed) = self.aes_index.0.overflowing_add(full_aes_shifts);

        (
            Self {
                aes_index: AesIndex(new_index),
                byte_index: ByteIndex(new_byte_index % BYTES_PER_AES_CALL),
            },
            overflowed,
        )
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
        self.byte_index.0 += 1;
        if self.byte_index.0 == BYTES_PER_AES_CALL {
            self.byte_index.0 = 0;
            self.aes_index.0 = self.aes_index.0.wrapping_add(1);
        }
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
        match larger.aes_index.cmp(&smaller.aes_index) {
            Ordering::Equal => {
                if larger.byte_index >= smaller.byte_index {
                    Some(ByteCount(
                        (larger.byte_index.0 - smaller.byte_index.0) as u128,
                    ))
                } else {
                    None
                }
            }
            Ordering::Greater => {
                let index_diff = larger.aes_index.0 - smaller.aes_index.0;
                if larger.byte_index.0 >= smaller.byte_index.0 {
                    let result = index_diff.saturating_mul(BYTES_PER_AES_CALL as u128);
                    let byte_diff = larger.byte_index.0 - smaller.byte_index.0;
                    Some(ByteCount(result.saturating_add(byte_diff as u128)))
                } else {
                    // The byte_diff needs to be subtracted from the result of the
                    // index_diff * BYTES_PER_AES_CALL operation, however to be precise
                    // we have to split the computation in two parts as the multiplication
                    // may slightly overflow to some value that the byte_diff would have
                    // put back into the representable range of u128
                    let byte_diff = smaller.byte_index.0 - larger.byte_index.0;
                    const CUTOFF_INDEX: u128 = u128::MAX / BYTES_PER_AES_CALL as u128;
                    let result1 = (CUTOFF_INDEX.min(index_diff) * BYTES_PER_AES_CALL as u128)
                        - byte_diff as u128;
                    let result2 = index_diff
                        .saturating_sub(CUTOFF_INDEX)
                        .saturating_mul(BYTES_PER_AES_CALL as u128);

                    Some(ByteCount(result1.saturating_add(result2)))
                }
            }
            Ordering::Less => None,
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

    // Test that the overflow detection of overflowing_increased works
    #[test]
    fn prop_test_overflowing_increased() {
        for i in 0..BYTES_PER_AES_CALL as u128 {
            assert!(TableIndex::LAST.decreased(i).overflowing_increased(i + 1).1);
        }

        // Test with some byte index that is not BYTES_PER_AES_CALL-1
        for i in 0..BYTES_PER_AES_CALL as u128 {
            assert!(
                TableIndex {
                    aes_index: AesIndex(u128::MAX),
                    byte_index: ByteIndex(i as usize)
                }
                .overflowing_increased(BYTES_PER_AES_CALL as u128 - i)
                .1
            );
        }

        assert!(
            !TableIndex::LAST
                .decreased(u128::MAX)
                .overflowing_increased(u128::MAX)
                .1
        );
        assert!(
            TableIndex::LAST
                .decreased(u128::MAX - 1)
                .overflowing_increased(u128::MAX)
                .1
        );

        let mut rng = thread_rng();

        // decrease by something < u128::MAX, then increase by u128::MAX overflows
        for _ in 0..REPEATS {
            let dec = rng.gen_range(0..=u128::MAX - 1);
            assert!(
                TableIndex::LAST
                    .decreased(dec)
                    .overflowing_increased(u128::MAX)
                    .1
            );
        }

        // decrease by some random value `dec` and then increase by some random value
        // `inc` which inc > dec creates an overflow
        for _ in 0..REPEATS {
            const MID: u128 = u128::MAX / 2;
            let n = rng.gen::<u128>();
            let (dec, inc) = if n <= MID {
                (n, u128::MAX - n)
            } else {
                (u128::MAX - n, n)
            };

            assert!(inc > dec);
            assert!(TableIndex::LAST.decreased(dec).overflowing_increased(inc).1);
        }
    }

    #[test]
    fn test_distance_first_to_second() {
        assert_eq!(
            TableIndex::distance(&TableIndex::SECOND, &TableIndex::FIRST),
            Some(ByteCount(1))
        );
    }

    #[test]
    fn test_distance_same_aes_index_different_byte() {
        for i in 0..BYTES_PER_AES_CALL {
            for j in i..BYTES_PER_AES_CALL {
                let larger = TableIndex::new(AesIndex(42), ByteIndex(j));
                let smaller = TableIndex::new(AesIndex(42), ByteIndex(i));
                assert_eq!(
                    TableIndex::distance(&larger, &smaller),
                    Some(ByteCount((j - i) as u128)),
                    "larger: {larger:?}, smaller: {smaller:?}"
                );
            }
        }
    }

    #[test]
    fn test_distance_same_aes_index_wrong_order() {
        let smaller = TableIndex::new(AesIndex(42), ByteIndex(3));
        let larger = TableIndex::new(AesIndex(42), ByteIndex(11));
        assert_eq!(TableIndex::distance(&smaller, &larger), None);
    }

    #[test]
    fn test_distance_across_aes_boundary() {
        // byte 15 of aes block N to byte 0 of aes block N+1 = 1 byte
        let a = TableIndex::new(AesIndex(5), ByteIndex(BYTES_PER_AES_CALL - 1));
        let b = a.incremented();
        assert_eq!(TableIndex::distance(&b, &a), Some(ByteCount(1)));
    }

    #[test]
    fn test_distance_larger_byte_index_smaller_than_smaller_byte_index() {
        // aes_index differs, but larger.byte_index < smaller.byte_index
        let smaller = TableIndex::new(AesIndex(10), ByteIndex(12));
        let larger = TableIndex::new(AesIndex(11), ByteIndex(3));
        // distance = (11 - 10) * 16 + 3 - 12 = 16 - 9 = 7
        assert_eq!(TableIndex::distance(&larger, &smaller), Some(ByteCount(7)));
    }

    #[test]
    fn test_distance_near_saturation() {
        for byte_index in 0..BYTES_PER_AES_CALL {
            let smaller = TableIndex {
                aes_index: AesIndex(0),
                byte_index: ByteIndex(byte_index),
            };
            let larger = smaller.increased(u128::MAX);
            let dist = TableIndex::distance(&larger, &smaller).unwrap().0;
            assert_eq!(dist, u128::MAX);

            for inc in 1..BYTES_PER_AES_CALL {
                let larger = larger.increased(inc as u128);
                let dist = TableIndex::distance(&larger, &smaller).unwrap().0;
                assert_eq!(dist, u128::MAX, "larger: {larger:?}, smaller: {smaller:?}");
            }
        }

        for byte_index in 0..BYTES_PER_AES_CALL {
            let smaller = TableIndex {
                aes_index: AesIndex(0),
                byte_index: ByteIndex(byte_index),
            };
            let larger = smaller.increased(u128::MAX - 1);
            let dist = TableIndex::distance(&larger, &smaller).unwrap().0;
            assert_eq!(
                dist,
                u128::MAX - 1,
                "larger: {larger:?}, smaller: {smaller:?}"
            );
        }

        // Test when the distance correctly subtracts from "saturated" value
        for byte_index in 1..BYTES_PER_AES_CALL {
            let larger = TableIndex::FIRST.increased(u128::MAX).increased(1);
            let smaller = TableIndex::FIRST.increased(byte_index as u128);

            let dist = TableIndex::distance(&larger, &smaller).unwrap().0;
            assert_eq!(
                dist,
                u128::MAX - (byte_index as u128 - 1),
                "larger: {larger:?}, smaller: {smaller:?}"
            );
        }
    }

    #[test]
    fn test_distance_near_cutoff() {
        // aes_index diff just below the cutoff: result should be exact
        let cutoff = u128::MAX / (BYTES_PER_AES_CALL as u128);
        for i in 0..BYTES_PER_AES_CALL {
            let smaller = TableIndex::new(AesIndex(0), ByteIndex(i));
            for j in 0..i {
                let larger = TableIndex::new(AesIndex(cutoff), ByteIndex(j));
                let dist = TableIndex::distance(&larger, &smaller).unwrap().0;
                assert_eq!(
                    dist,
                    (cutoff * BYTES_PER_AES_CALL as u128) - (i - j) as u128
                );
            }

            for j in i..BYTES_PER_AES_CALL {
                let larger = TableIndex::new(AesIndex(cutoff), ByteIndex(j));
                let dist = TableIndex::distance(&larger, &smaller).unwrap().0;
                assert_eq!(
                    dist,
                    (cutoff * BYTES_PER_AES_CALL as u128).saturating_add((j - i) as u128)
                );
            }
        }
    }

    #[test]
    fn test_distance_max_aes_index_diff_saturates() {
        let smaller = TableIndex::new(AesIndex(0), ByteIndex(0));
        let larger = TableIndex::new(AesIndex(u128::MAX), ByteIndex(0));
        assert_eq!(
            TableIndex::distance(&larger, &smaller),
            Some(ByteCount(u128::MAX))
        );
    }

    #[test]
    /// Check the property:
    ///     For all table indices larger > smaller such that
    ///     distance(larger, smaller) < u128::MAX (not saturated),
    ///         smaller.increased(distance(larger, smaller)) = larger.
    fn prop_table_index_distance_roundtrip() {
        for _ in 0..REPEATS {
            let (larger, smaller) = any_table_index()
                .zip(any_table_index())
                .find(|(a, b)| TableIndex::distance(a, b).is_some_and(|d| d.0 < u128::MAX))
                .unwrap();
            let dist = TableIndex::distance(&larger, &smaller).unwrap().0;
            if dist < u128::MAX {
                assert_eq!(
                    smaller.increased(dist),
                    larger,
                    "smaller: {smaller:?}, larger: {larger:?}, dist: {dist}"
                );
            }
        }
    }

    #[test]
    /// Check the property (targets the else branch where larger.byte_index < smaller.byte_index):
    ///     For all table indices larger, smaller such that
    ///     larger.aes_index > smaller.aes_index and larger.byte_index < smaller.byte_index,
    ///         smaller.increased(distance(larger, smaller)) = larger (when not saturated).
    fn prop_table_index_distance_cross_byte_boundary() {
        for _ in 0..REPEATS {
            let (larger, smaller) = any_table_index()
                .zip(any_table_index())
                .find(|(a, b)| a.aes_index > b.aes_index && a.byte_index.0 < b.byte_index.0)
                .unwrap();
            let dist = TableIndex::distance(&larger, &smaller).unwrap().0;
            if dist < u128::MAX {
                assert_eq!(
                    smaller.increased(dist),
                    larger,
                    "smaller: {smaller:?}, larger: {larger:?}, dist: {dist}"
                );
            }
        }
    }

    #[test]
    /// Check the property:
    ///     For all table indices a > b > c such that neither distance saturates,
    ///         distance(a, b) + distance(b, c) = distance(a, c).
    fn prop_table_index_distance_additivity() {
        for _ in 0..REPEATS {
            let (a, b, c) = any_table_index()
                .zip(any_table_index())
                .zip(any_table_index())
                .map(|((x, y), z)| {
                    let mut sorted = [x, y, z];
                    sorted.sort();
                    (sorted[2], sorted[1], sorted[0])
                })
                .find(|(a, b, c)| {
                    a > b && b > c && TableIndex::distance(a, c).unwrap().0 < u128::MAX
                })
                .unwrap();
            let d_ab = TableIndex::distance(&a, &b).unwrap().0;
            let d_bc = TableIndex::distance(&b, &c).unwrap().0;
            let d_ac = TableIndex::distance(&a, &c).unwrap().0;
            assert_eq!(d_ab + d_bc, d_ac, "a: {a:?}, b: {b:?}, c: {c:?}");
        }
    }

    #[test]
    /// Check the property:
    ///     For all table indices a, b,
    ///         distance agrees with derived Ord:
    ///         a > b => distance(a, b) = Some(v) with v > 0
    ///         a < b => distance(a, b) = None
    ///         a == b => distance(a, b) = Some(0)
    fn prop_table_index_distance_consistent_with_ord() {
        for _ in 0..REPEATS {
            let (a, b) = any_table_index().zip(any_table_index()).next().unwrap();
            let dist = TableIndex::distance(&a, &b);
            match a.cmp(&b) {
                Ordering::Greater => {
                    assert!(
                        matches!(dist, Some(ByteCount(v)) if v > 0),
                        "a > b but distance is {dist:?}, a: {a:?}, b: {b:?}"
                    );
                }
                Ordering::Less => {
                    assert!(
                        dist.is_none(),
                        "a < b but distance is {dist:?}, a: {a:?}, b: {b:?}"
                    );
                }
                Ordering::Equal => {
                    assert_eq!(
                        dist,
                        Some(ByteCount(0)),
                        "a == b but distance is {dist:?}, a: {a:?}, b: {b:?}"
                    );
                }
            }
        }
    }
}
