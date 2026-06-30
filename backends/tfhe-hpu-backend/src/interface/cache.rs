//! Zhc dynamic IOp cache handling.
//!
//! Zhc required to upload optimized graph at runtime, those graph are store in hw and could be reused
//! This structure is here to kept track of the uploaded graph and manage the hw memory.
//! It rely on the `dyn` flag of IOp to separate standard IOp from zhc graph one.
//! The hardware could handle at most IOP_NUMBER distinct entries.
//! Fw memory is view a set of SLOT_SIZE_WORDS u32 slot to ease memory management and reduce fragmentation.

use crate::{
    asm::{self, dop::MAX_HPU_IN_CLUSTER, IOpId},
    ffi,
    interface::{memory, IOP_NUMBER},
};
use std::{
    collections::{HashMap, VecDeque},
    hash::{Hash, Hasher},
    sync::Arc,
};
use thiserror::Error;

/// Slot are 4kiB of contiguous memory
const SLOT_SIZE_WORDS: usize = 1024;

/// Kept track of upload dyn operation and associated Fw memory
pub struct ZhcCache {
    // Kept two cache entry indexing for fast bidir lookup
    hash_entries: HashMap<ZhcStreamHash, Arc<ZhcCacheEntry>>,
    id_entries: HashMap<IOpId, Arc<ZhcCacheEntry>>,

    // Management of underlyng storage
    fw_pool: FwPool,
    id_pool: VecDeque<IOpId>,
}

impl ZhcCache {
    pub fn new(ffi_hw: &mut ffi::HpuHw, kind: ffi::MemKind, pool_size: usize) -> Self {
        let mem_props = memory::HugeMemoryProperties {
            mem_cut: vec![kind],
            cut_coefs: pool_size,
        };

        let id_pool = (0..IOP_NUMBER).map(|i| IOpId(i as u8)).collect::<_>();

        Self {
            hash_entries: HashMap::new(),
            id_entries: HashMap::new(),
            fw_pool: FwPool::new(ffi_hw, mem_props, SLOT_SIZE_WORDS),
            id_pool,
        }
    }

    pub fn get_by_stream(&self, stream: &ZhcStream) -> Option<Arc<ZhcCacheEntry>> {
        let stream_hash = ZhcStreamHash::from(stream);
        self.hash_entries.get(&stream_hash).cloned()
    }
    pub fn get_by_id(&self, id: &IOpId) -> Option<Arc<ZhcCacheEntry>> {
        self.id_entries.get(id).cloned()
    }

    pub fn get_or_insert(&mut self, stream: ZhcStream) -> Result<Arc<ZhcCacheEntry>, CacheError> {
        if let Some(e) = self.get_by_stream(&stream) {
            return Ok(e);
        }

        // Allocate slots
        let slots = stream.slots_size().into_iter().enumerate().try_fold(
            std::array::from_fn(|_| Vec::new()),
            |mut slots, (vid, slot_nb)| {
                let cur_slots = self.fw_pool.get_slots(slot_nb)?;
                slots[vid].extend_from_slice(&cur_slots);
                Ok(slots)
            },
        )?;
        // Write stream in associated slots
        // TODO

        // Allocate id
        let id = self.id_pool.pop_front().ok_or(CacheError::CacheFull)?;
        let hash = ZhcStreamHash::from(&stream);

        // Insert entry in cache
        let entry = Arc::new(ZhcCacheEntry {
            id: id.clone(),
            slots,
            stream,
        });
        self.hash_entries.insert(hash, entry.clone());
        self.id_entries.insert(id, entry.clone());

        Ok(entry)
    }

    pub fn flush_by_id(&mut self, id: &IOpId) -> Result<usize, CacheError> {
        if let Some(entry) = self.id_entries.remove(id) {
            // Release  associated slot
            let released_slots = entry
                .slots
                .iter()
                .map(|slots| {
                    self.fw_pool.release_slots(slots);
                    slots.len()
                })
                .sum();
            // Remove associated entry in hash view
            let hash = ZhcStreamHash::from(&entry.stream);
            self.hash_entries
                .remove(&hash)
                .ok_or(CacheError::UnsyncView)?;
            Ok(released_slots)
        } else {
            Err(CacheError::IdNotFound(id.clone()))
        }
    }

    pub fn flush_by_stream(&mut self, stream_hash: &ZhcStreamHash) -> Result<usize, CacheError> {
        if let Some(entry) = self.hash_entries.remove(stream_hash) {
            // Release  associated slot
            let released_slots = entry
                .slots
                .iter()
                .map(|slots| {
                    self.fw_pool.release_slots(slots);
                    slots.len()
                })
                .sum();
            // Remove associated entry in id view
            self.id_entries
                .remove(&entry.id)
                .ok_or(CacheError::UnsyncView)?;
            Ok(released_slots)
        } else {
            Err(CacheError::HashNotFound(stream_hash.clone()))
        }
    }

    pub fn flush_all(&mut self) -> Result<usize, CacheError> {
        let ids = self
            .id_entries
            .keys()
            .map(|id| id.clone())
            .collect::<Vec<_>>();

        for id in ids.iter() {
            self.flush_by_id(id)?;
        }

        if !self.hash_entries.is_empty() {
            Err(CacheError::UnsyncView)
        } else {
            Ok(self.fw_pool.pool.len())
        }
    }

    pub fn get_stats(&self) -> (usize, [usize; MAX_HPU_IN_CLUSTER]) {
        let stats =
            self.id_entries
                .values()
                .fold([0usize; MAX_HPU_IN_CLUSTER], |mut acc, entry| {
                    for (a, v) in acc.iter_mut().zip(entry.slots.iter()) {
                        *a += v.len();
                    }
                    acc
                });
        (self.id_entries.len(), stats)
    }
}

/// Cache Error type
#[derive(Error, Clone, Debug)]
pub enum CacheError {
    #[error("Cache is full")]
    CacheFull,
    #[error("{0} is not currently in use")]
    IdNotFound(asm::IOpId),
    #[error("{0:?} is not currently in use")]
    HashNotFound(ZhcStreamHash),
    #[error("Unsync view between hash/id _entries")]
    UnsyncView,
}

pub struct ZhcCacheEntry {
    id: asm::IOpId,
    slots: [Vec<FwSlotId>; MAX_HPU_IN_CLUSTER],
    // Kept associated stream for debug purpose
    stream: ZhcStream,
}

impl ZhcCacheEntry {
    pub fn id(&self) -> asm::IOpId {
        self.id.clone()
    }
    pub fn stream(&self) -> &ZhcStream {
        &self.stream
    }
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

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ZhcStreamHash(u64);
impl From<&ZhcStream> for ZhcStreamHash {
    fn from(stream: &ZhcStream) -> Self {
        let mut hasher = std::hash::DefaultHasher::new();
        stream.hash(&mut hasher);
        ZhcStreamHash(hasher.finish())
    }
}

struct FwPool {
    mem: memory::HugeMemory<u32>,
    pool: VecDeque<FwSlotId>,
    coef_per_slot: usize,
}

impl FwPool {
    fn new(
        ffi_hw: &mut ffi::HpuHw,
        props: memory::HugeMemoryProperties,
        coef_per_slot: usize,
    ) -> Self {
        let slot_nb = props.cut_coefs.div_ceil(coef_per_slot);
        let mem = memory::HugeMemory::alloc(ffi_hw, props);
        let pool = (0..slot_nb).map(|i| FwSlotId(i)).collect::<VecDeque<_>>();

        Self {
            mem,
            pool,
            coef_per_slot,
        }
    }

    /// Get a list of contiguous Fwslot
    pub fn get_slots(&mut self, slot_nb: usize) -> Result<Vec<FwSlotId>, CacheError> {
        // Implement sliding windows search for contiguous block
        // TODO enhance this algorithm. Currently it's a naive implementation
        let mut win_slots = Vec::with_capacity(self.pool.capacity());

        // Check for contiguousnes and extend the window if necessary
        loop {
            let slot = if let Some(slot) = self.pool.pop_front() {
                slot
            } else {
                return Err(CacheError::CacheFull);
            };
            win_slots.push(slot);
            if win_slots.len() < slot_nb {
                continue;
            }
            win_slots.sort_by(|a, b| a.partial_cmp(&b).unwrap());

            // Check contiguous
            for i in 0..=(win_slots.len() - slot_nb) {
                let is_contiguous = (0..slot_nb).all(|j| win_slots[i + j].0 == win_slots[i].0 + j);
                if is_contiguous {
                    let mut slots = Vec::with_capacity(slot_nb);
                    for (p, slot) in win_slots.into_iter().enumerate() {
                        if (p < i) || p >= (i + slot_nb) {
                            // Return slot to pool
                            self.pool.push_back(slot)
                        } else {
                            slots.push(slot)
                        }
                    }
                    return Ok(slots);
                }
            }
        }
    }

    pub fn release_slots(&mut self, slots: &[FwSlotId]) {
        self.pool.extend(slots);
    }
}

/// Fw memory is split in a poll of slot.
/// Each slot are identified with FwSlot Id
#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq)]
struct FwSlotId(usize);
