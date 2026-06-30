//! Zhc dynamic IOp cache handling.
//!
//! Zhc required to upload optimized graph at runtime, those graph are store in hw and could be reused
//! This structure is here to kept track of the uploaded graph and manage the hw memory.
//! It rely on the `dyn` flag of IOp to separate standard IOp from zhc graph one.
//! The hardware could handle at most IOP_NUMBER distinct entries.
//! Fw memory is view a set of SLOT_SIZE_WORDS u32 slot to ease memory management and reduce fragmentation.

use std::collections::HashMap;

use crate::asm::{self, dop::MAX_HPU_IN_CLUSTER};

/// Slot are 4kiB of contiguous memory
const SLOT_SIZE_WORDS: usize = 1024;

/// GARBAGE ===================================================================
pub trait HW {
    fn upload_stream(stream: &[u32]);
}
/// GARBAGE ===================================================================

#[derive(Debug)]
pub enum Error {
    CacheFull,
    OpNotFound,
}
/// ZhcMetadata
/// Kept information relative to generation of a stream
/// TODO extend
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ZhcMetadata {
    pub name: String,
    pub callsite: String,
}

/// A cache entry content a set of DOp Stream with associated metadata
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ZhcStream {
    pub metadata: ZhcMetadata,
    pub streams: [Vec<u32>; MAX_HPU_IN_CLUSTER],
}

impl ZhcStream {
    pub fn new(metadata: ZhcMetadata, streams: &[&[u32]]) -> Self {
        assert!(
            streams.len() <= MAX_HPU_IN_CLUSTER,
            "Error ZhcStream must contain at most {MAX_HPU_IN_CLUSTER} streams [{} given]",
            streams.len()
        );

        // Copy stream locally
        let mut owned_streams: [Vec<u32>; MAX_HPU_IN_CLUSTER] =
            std::array::from_fn(|_i| Vec::new());
        for (o, i) in std::iter::zip(owned_streams.iter_mut(), streams.iter()) {
            o.extend_from_slice(i);
        }

        Self {
            metadata,
            streams: owned_streams,
        }
    }

    pub fn slots_size(&self) -> [usize; MAX_HPU_IN_CLUSTER] {
        (0..MAX_HPU_IN_CLUSTER)
            .map(|i| self.streams[i].len().div_ceil(SLOT_SIZE_WORDS))
            .collect::<Vec<_>>()
            .try_into()
            .expect("Invalid number of stream")
    }
}

struct CacheEntry {
    id: asm::IOpId,
    slot_starts: [usize; MAX_HPU_IN_CLUSTER],
    slot_counts: [usize; MAX_HPU_IN_CLUSTER],
    // Kept associated stream for debug purpose
    zhc_stream: ZhcStream,
}

fn find_contiguous(slots: &[bool], count: usize) -> Option<usize> {
    if count == 0 {
        return Some(0);
    }
    let mut run_start = 0;
    let mut run_len = 0;
    for (i, &used) in slots.iter().enumerate() {
        if !used {
            if run_len == 0 {
                run_start = i;
            }
            run_len += 1;
            if run_len == count {
                return Some(run_start);
            }
        } else {
            run_len = 0;
        }
    }
    None
}

pub struct ZhcCache<H: HW> {
    entries: HashMap<ZhcStream, CacheEntry>,
    /// Stores a clone of the key so flush() can remove the forward-map entry.
    op_to_stream: HashMap<usize, ZhcStream>,
    used_op_ids: Vec<bool>,
    used_slots: Vec<bool>,
    _hw: std::marker::PhantomData<H>,
}

impl<H: HW> ZhcCache<H> {
    pub fn new(max_zhc_op: usize, zhc_pool_size: usize) -> Self {
        Self {
            entries: HashMap::new(),
            op_to_stream: HashMap::new(),
            used_op_ids: vec![false; max_zhc_op],
            used_slots: vec![false; zhc_pool_size],
            _hw: std::marker::PhantomData,
        }
    }

    pub fn get_or_insert(
        &mut self,
        zhc_stream: ZhcStream,
    ) -> Result<(usize, [usize; MAX_HPU_IN_CLUSTER]), Error> {
        if let Some(e) = self.entries.get(&zhc_stream) {
            return Ok((e.zhc_op_id, e.slot_starts));
        }

        let zhc_op_id = self
            .used_op_ids
            .iter()
            .position(|&u| !u)
            .ok_or(Error::CacheFull)?;

        let mut slot_starts = [0usize; MAX_HPU_IN_CLUSTER];
        let mut slot_counts = [0usize; MAX_HPU_IN_CLUSTER];

        for (i, stream) in zhc_stream.streams.iter().enumerate() {
            let count = slots_needed(stream);
            slot_counts[i] = count;
            match find_contiguous(&self.used_slots, count) {
                Some(start) => {
                    slot_starts[i] = start;
                    for j in start..start + count {
                        self.used_slots[j] = true;
                    }
                }
                None => {
                    for k in 0..i {
                        for j in slot_starts[k]..slot_starts[k] + slot_counts[k] {
                            self.used_slots[j] = false;
                        }
                    }
                    return Err(Error::CacheFull);
                }
            }
        }

        self.used_op_ids[zhc_op_id] = true;
        for stream in zhc_stream.streams.iter() {
            H::upload_stream(stream);
        }

        self.op_to_stream.insert(zhc_op_id, zhc_stream.clone());
        self.entries.insert(
            zhc_stream,
            CacheEntry {
                zhc_op_id,
                slot_starts,
                slot_counts,
            },
        );

        Ok((zhc_op_id, slot_starts))
    }

    pub fn flush(&mut self, zhc_op: usize) -> Result<usize, Error> {
        let key = self.op_to_stream.remove(&zhc_op).ok_or(Error::OpNotFound)?;
        let e = self
            .entries
            .remove(&key)
            .expect("invariant: op_to_stream and entries are always in sync");

        self.used_op_ids[e.zhc_op_id] = false;
        let released: usize = (0..MAX_HPU_IN_CLUSTER)
            .map(|i| {
                for j in e.slot_starts[i]..e.slot_starts[i] + e.slot_counts[i] {
                    self.used_slots[j] = false;
                }
                e.slot_counts[i]
            })
            .sum();

        Ok(released)
    }

    pub fn flush_all(&mut self) {
        self.entries.clear();
        self.op_to_stream.clear();
        self.used_op_ids.fill(false);
        self.used_slots.fill(false);
    }

    pub fn state(&self) -> (usize, usize) {
        let used_ops = self.used_op_ids.iter().filter(|&&u| u).count();
        let used_slots = self.used_slots.iter().filter(|&&u| u).count();
        (used_ops, used_slots)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockHW;
    impl HW for MockHW {
        fn upload_stream(_: &[u32]) {}
    }

    type Cache = ZhcCache<MockHW>;

    fn make(name: &str, spec: [(u32, usize); MAX_HPU_IN_CLUSTER]) -> ZhcStream {
        ZhcStream {
            name: name.into(),
            streams: std::array::from_fn(|i| vec![spec[i].0; spec[i].1]),
        }
    }

    const EMPTY: [(u32, usize); MAX_HPU_IN_CLUSTER] = [(0, 0); MAX_HPU_IN_CLUSTER];

    #[test]
    fn same_streams_same_name_is_a_hit() {
        let mut cache = Cache::new(4, 8);
        let spec = [
            (1, 512),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
        ];
        let first = cache.get_or_insert(make("alpha", spec)).unwrap();
        let second = cache.get_or_insert(make("alpha", spec)).unwrap();
        assert_eq!(first, second);
        assert_eq!(cache.state(), (1, 1));
    }

    #[test]
    fn same_streams_different_names_is_a_miss() {
        let mut cache = Cache::new(4, 8);
        let spec = [
            (1, 512),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
        ];
        let (op1, _) = cache.get_or_insert(make("alpha", spec)).unwrap();
        let (op2, _) = cache.get_or_insert(make("beta", spec)).unwrap();
        assert_ne!(op1, op2);
        assert_eq!(cache.state(), (2, 2));
    }

    #[test]
    fn different_streams_is_a_miss() {
        let mut cache = Cache::new(4, 8);
        let mut s1 = EMPTY;
        s1[0] = (1, 1024);
        let mut s2 = EMPTY;
        s2[0] = (2, 1024);
        let (op1, _) = cache.get_or_insert(make("a", s1)).unwrap();
        let (op2, _) = cache.get_or_insert(make("a", s2)).unwrap();
        assert_ne!(op1, op2);
    }

    #[test]
    fn flush_releases_all_slots() {
        let mut cache = Cache::new(4, 16);
        let mut spec = EMPTY;
        spec[0] = (7, 1024);
        spec[1] = (7, 1024);
        spec[2] = (7, 1024);
        let (op, _) = cache.get_or_insert(make("x", spec)).unwrap();
        assert_eq!(cache.flush(op).unwrap(), 3);
        assert_eq!(cache.state(), (0, 0));
    }

    #[test]
    fn flush_unknown_op_errors() {
        let mut cache = Cache::new(4, 8);
        assert!(matches!(cache.flush(99), Err(Error::OpNotFound)));
    }

    #[test]
    fn op_limit_enforced() {
        let mut cache = Cache::new(2, 16);
        let mut s = EMPTY;
        for (i, v) in [1u32, 2, 3].iter().enumerate() {
            s[0] = (*v, 1);
            let result = cache.get_or_insert(make("n", s));
            if i < 2 {
                assert!(result.is_ok());
            } else {
                assert!(matches!(result, Err(Error::CacheFull)));
            }
        }
    }

    #[test]
    fn partial_allocation_rolls_back() {
        // Pool has 1 slot; entry needs 2 streams × 1 slot → fails.
        // After rollback the single slot must still be available.
        let mut cache = Cache::new(8, 1);
        let mut spec = EMPTY;
        spec[0] = (1, 1024);
        spec[1] = (2, 1024);
        assert!(matches!(
            cache.get_or_insert(make("x", spec)),
            Err(Error::CacheFull)
        ));

        let mut one = EMPTY;
        one[0] = (9, 1);
        assert!(cache.get_or_insert(make("y", one)).is_ok());
    }

    #[test]
    fn flush_all_resets_and_allows_reuse() {
        let mut cache = Cache::new(4, 16);
        let mut s = EMPTY;
        s[0] = (1, 1024);
        cache.get_or_insert(make("a", s)).unwrap();
        s[0] = (2, 1024);
        cache.get_or_insert(make("b", s)).unwrap();
        cache.flush_all();
        assert_eq!(cache.state(), (0, 0));
        s[0] = (1, 1024);
        cache.get_or_insert(make("a", s)).unwrap();
        assert_eq!(cache.state(), (1, 1));
    }
}
