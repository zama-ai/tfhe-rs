//! Zhc dynamic IOp cache handling.
//!
//! Zhc requires to upload optimized graphs at runtime, those graphs are stored in hw and can be
//! reused This structure is here to keep track of the uploaded graph and manage the hw memory.
//! It relies on the `dyn` flag of IOp to separate standard IOp from zhc graph one.
//! The hardware could handle at most IOP_NUMBER distinct entries.
//! Fw memory is viewed as a set of SLOT_SIZE_WORDS u32 slot to ease memory management and reduce
//! fragmentation.

use crate::asm::dop::MAX_HPU_IN_CLUSTER;
use crate::asm::{self, IOpProto};
use crate::ffi;
use crate::interface::{memory, IOP_NUMBER};
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use thiserror::Error;

/// Slot are 4kiB of contiguous memory
const SLOT_SIZE_WORDS: usize = 1024;

/// Keep track of uploaded dyn operation and associated Fw memory
pub struct ZhcCache {
    // Keep two cache entry indexing for fast bidir lookup
    hash_entries: HashMap<ZhcStreamHash, Arc<ZhcCacheEntry>>,
    id_entries: HashMap<asm::IOpcode, Arc<ZhcCacheEntry>>,

    // Management of underlying storage
    fw_pool: FwPool,
    iop_pool: VecDeque<asm::IOpcode>,
}

#[allow(unused)]
impl ZhcCache {
    pub fn new(ffi_hw: &mut ffi::HpuHw, kind: ffi::MemKind, pool_size: usize) -> Self {
        let mem_props = memory::HugeMemoryProperties {
            mem_cut: vec![kind],
            cut_coefs: pool_size,
        };

        let id_pool = (0..IOP_NUMBER)
            .map(|i| asm::IOpcode(i as u8))
            .collect::<_>();

        Self {
            hash_entries: HashMap::new(),
            id_entries: HashMap::new(),
            fw_pool: FwPool::new(ffi_hw, mem_props, SLOT_SIZE_WORDS),
            iop_pool: id_pool,
        }
    }

    pub fn get_by_hash(&self, hash: &ZhcStreamHash) -> Option<Arc<ZhcCacheEntry>> {
        self.hash_entries.get(hash).cloned()
    }
    pub fn get_by_iop(&self, iop: &asm::IOpcode) -> Option<Arc<ZhcCacheEntry>> {
        self.id_entries.get(iop).cloned()
    }

    pub fn get_or_insert(
        &mut self,
        hash: ZhcStreamHash,
        stream: ZhcStream,
        proto: IOpProto,
    ) -> Result<Arc<ZhcCacheEntry>, CacheError> {
        if let Some(e) = self.get_by_hash(&hash) {
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
        // Allocate id
        let id = self.iop_pool.pop_front().ok_or(CacheError::CacheFull)?;
        let hash = ZhcStreamHash::from(&stream);

        // Write stream in associated slots
        let vid_bytes_ofst = std::iter::zip(stream.streams.iter(), slots.iter())
            .map(|(dops, slot)| {
                if let Some(sid) = slot.first() {
                    // used vid
                    // Write dop stream
                    let words_ofst = sid.0 * SLOT_SIZE_WORDS;
                    self.fw_pool.mem.write_cut_at(0, words_ofst, dops);
                    (words_ofst * std::mem::size_of::<u32>()) as u32
                } else {
                    // Current vid isn't used return 0
                    // => This first entry point on itself and  is reserved for error
                    0
                }
            })
            .collect::<Vec<_>>();

        // Update lookup-table
        // Write all vid lut addr at once
        self.fw_pool
            .mem
            .write_cut_at(0, 1 + (id.0 as usize * MAX_HPU_IN_CLUSTER), &vid_bytes_ofst);

        // Insert entry in cache
        let entry = Arc::new(ZhcCacheEntry {
            iop: id,
            proto,
            slots,
            stream,
        });
        self.hash_entries.insert(hash, entry.clone());
        self.id_entries.insert(id, entry.clone());

        Ok(entry)
    }

    pub fn flush_by_iop(&mut self, iop: &asm::IOpcode) -> Result<usize, CacheError> {
        if let Some(entry) = self.id_entries.remove(iop) {
            // Release  associated slot
            let released_slots = entry
                .slots
                .iter()
                .map(|slots| {
                    self.fw_pool.release_slots(slots);
                    slots.len()
                })
                .sum();
            // Release iop id
            self.iop_pool.push_back(entry.iop);

            // Remove associated entry in hash view
            let hash = ZhcStreamHash::from(&entry.stream);
            self.hash_entries
                .remove(&hash)
                .ok_or(CacheError::UnsyncView)?;
            Ok(released_slots)
        } else {
            Err(CacheError::IOpNotFound(*iop))
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
            // Release iop id
            self.iop_pool.push_back(entry.iop);

            // Remove associated entry in id view
            self.id_entries
                .remove(&entry.iop)
                .ok_or(CacheError::UnsyncView)?;
            Ok(released_slots)
        } else {
            Err(CacheError::HashNotFound(stream_hash.clone()))
        }
    }

    pub fn flush_all(&mut self) -> Result<usize, CacheError> {
        let ids = self.id_entries.keys().copied().collect::<Vec<_>>();

        for id in ids.iter() {
            self.flush_by_iop(id)?;
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
    #[error("{0:?} is not currently in use")]
    IOpNotFound(asm::IOpcode),
    #[error("{0:?} is not currently in use")]
    HashNotFound(ZhcStreamHash),
    #[error("Unsync view between hash/id _entries")]
    UnsyncView,
}

#[allow(unused)]
pub struct ZhcCacheEntry {
    iop: asm::IOpcode,
    proto: asm::IOpProto,
    slots: [Vec<FwSlotId>; MAX_HPU_IN_CLUSTER],
    // Kept associated stream for debug purpose
    stream: ZhcStream,
}

#[allow(unused)]
impl ZhcCacheEntry {
    pub fn iop(&self) -> asm::IOpcode {
        self.iop
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
    pub metadata: Option<ZhcMetadata>,
    pub streams: [Vec<u32>; MAX_HPU_IN_CLUSTER],
}

impl ZhcStream {
    pub fn new(metadata: Option<ZhcMetadata>, streams: Vec<Vec<u32>>) -> Self {
        assert!(
            streams.len() <= MAX_HPU_IN_CLUSTER,
            "Error ZhcStream must contain at most {MAX_HPU_IN_CLUSTER} streams [{} given]",
            streams.len()
        );

        // Enforce correct number of stream
        let mut owned_streams: [Vec<u32>; MAX_HPU_IN_CLUSTER] =
            std::array::from_fn(|_i| Vec::new());
        for (o, i) in std::iter::zip(owned_streams.iter_mut(), streams) {
            *o = i;
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
    #[allow(unused)]
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
        // NB: Firsts slots are used for table_lookup
        let reserved_slot =
            (IOP_NUMBER * MAX_HPU_IN_CLUSTER * std::mem::size_of::<u32>()).div_ceil(coef_per_slot);
        let pool = (reserved_slot..slot_nb)
            .map(FwSlotId)
            .collect::<VecDeque<_>>();

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

        // Check for contiguousness and extend the window if necessary
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
            win_slots.sort_by(|a, b| a.partial_cmp(b).unwrap());

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
/// Each slot is identified with FwSlot Id
#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq)]
struct FwSlotId(usize);
