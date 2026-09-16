//! Dynamic IOp cache handling.
//!
//! Zhc requires to upload optimized graphs at runtime, those graphs are stored in hw and can be
//! reused This structure is here to keep track of the uploaded graph and manage the hw memory.
//! It relies on the `dyn` flag of IOp to separate standard IOp from zhc graph one.
//! The hardware could handle at most IOP_NUMBER distinct entries.
//! Fw memory is viewed as a set of SLOT_SIZE_WORDS u32 slot to ease memory management and reduce
//! fragmentation.

use crate::asm::MAX_HPU_IN_CLUSTER;
use crate::asm::{self, IOpProto};
use crate::ffi;
use crate::interface::{memory, IOP_NUMBER};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use thiserror::Error;
use zhc::prelude::Fingerprint;

use super::{Pool, PoolError, SlotId};

/// Slot are 4kiB of contiguous memory
const SLOT_SIZE_WORDS: usize = 1024;

/// Keep track of uploaded dyn operation and associated Fw memory
pub struct DynFwCache {
    // Keep two cache entry indexing for fast bidir lookup
    hash_entries: HashMap<Fingerprint, Arc<DynFwEntry>>,
    id_entries: HashMap<asm::IOpcode, Arc<DynFwEntry>>,

    // Management of underlying storage
    fw_pool: Pool<u32>,
    iop_pool: VecDeque<asm::IOpcode>,
}

#[allow(unused)]
impl DynFwCache {
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
            fw_pool: Pool::new(
                ffi_hw,
                mem_props,
                SLOT_SIZE_WORDS,
                Some(IOP_NUMBER * MAX_HPU_IN_CLUSTER),
            ),
            iop_pool: id_pool,
        }
    }

    pub fn get_by_hash(&self, hash: &Fingerprint) -> Option<Arc<DynFwEntry>> {
        self.hash_entries.get(hash).cloned()
    }
    pub fn get_by_iop(&self, iop: &asm::IOpcode) -> Option<Arc<DynFwEntry>> {
        self.id_entries.get(iop).cloned()
    }

    pub fn get_or_insert(
        &mut self,
        fingerprint: Fingerprint,
        proto: IOpProto,
        streams: [Vec<u32>; MAX_HPU_IN_CLUSTER],
    ) -> Result<Arc<DynFwEntry>, DynFwError> {
        // Cache hit ?
        if let Some(e) = self.get_by_hash(&fingerprint) {
            return Ok(e);
        } else {
            // Allocate id
            let id = self.iop_pool.pop_front().ok_or(DynFwError::CacheFull)?;

            let stream_slots: [usize; MAX_HPU_IN_CLUSTER] = streams
                .iter()
                .map(|s| s.len().div_ceil(SLOT_SIZE_WORDS))
                .collect::<Vec<_>>()
                .try_into()
                .expect("Invalid number of stream");

            // Allocate slots
            let slots = stream_slots.into_iter().enumerate().try_fold(
                std::array::from_fn(|_| Vec::new()),
                |mut slots, (vid, slot_nb)| -> Result<_, DynFwError> {
                    let cur_slots = self.fw_pool.get_slots(slot_nb)?;
                    slots[vid].extend_from_slice(&cur_slots);
                    Ok(slots)
                },
            )?;

            // Write stream in associated slots
            let vid_bytes_ofst = std::iter::zip(streams.iter(), slots.iter())
                .map(|(dops, slot)| {
                    if let Some(sid) = slot.first() {
                        // used vid
                        // Write dop stream
                        let words_ofst = sid.index() * SLOT_SIZE_WORDS;
                        self.fw_pool.mem_mut().write_cut_at(0, words_ofst, dops);
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
            self.fw_pool.mem_mut().write_cut_at(
                0,
                1 + (id.0 as usize * MAX_HPU_IN_CLUSTER),
                &vid_bytes_ofst,
            );

            // Insert entry in cache
            let entry = Arc::new(DynFwEntry {
                iop: id,
                hash: fingerprint.clone(),
                proto,
                slots,
                streams,
            });
            self.hash_entries.insert(fingerprint, entry.clone());
            self.id_entries.insert(id, entry.clone());

            Ok(entry)
        }
    }

    pub fn flush_by_iop(&mut self, iop: &asm::IOpcode) -> Result<usize, DynFwError> {
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
            let hash = entry.hash;
            self.hash_entries
                .remove(&hash)
                .ok_or(DynFwError::UnsyncView)?;
            Ok(released_slots)
        } else {
            Err(DynFwError::IOpNotFound(*iop))
        }
    }

    pub fn flush_by_stream(&mut self, stream_hash: &Fingerprint) -> Result<usize, DynFwError> {
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
                .ok_or(DynFwError::UnsyncView)?;
            Ok(released_slots)
        } else {
            Err(DynFwError::HashNotFound(stream_hash.clone()))
        }
    }

    pub fn flush_all(&mut self) -> Result<usize, DynFwError> {
        let ids = self.id_entries.keys().copied().collect::<Vec<_>>();

        for id in ids.iter() {
            self.flush_by_iop(id)?;
        }

        if !self.hash_entries.is_empty() {
            Err(DynFwError::UnsyncView)
        } else {
            Ok(self.fw_pool.len())
        }
    }

    pub fn release(&mut self, ffi_hw: &mut ffi::HpuHw) {
        let _ = self.flush_all();
        self.fw_pool.mem_mut().release(ffi_hw);
    }

    pub fn get_pool_paddr(&self) -> u64 {
        self.fw_pool.mem().cut_paddr()[0]
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
pub enum DynFwError {
    #[error("Cache is full")]
    CacheFull,
    #[error("{0:?} is not currently in use")]
    IOpNotFound(asm::IOpcode),
    #[error("{0:?} is not currently in use")]
    HashNotFound(Fingerprint),
    #[error("Unsync view between hash/id _entries")]
    UnsyncView,
}

impl From<PoolError> for DynFwError {
    fn from(value: PoolError) -> Self {
        match value {
            PoolError::Full => Self::CacheFull,
        }
    }
}

#[allow(unused)]
pub struct DynFwEntry {
    iop: asm::IOpcode,
    hash: Fingerprint,
    proto: asm::IOpProto,
    slots: [Vec<SlotId>; MAX_HPU_IN_CLUSTER],

    // Kept associated stream for debug purpose
    streams: [Vec<u32>; MAX_HPU_IN_CLUSTER],
}

#[allow(unused)]
impl DynFwEntry {
    pub fn iop(&self) -> asm::IOpcode {
        self.iop
    }
    pub fn hash(&self) -> Fingerprint {
        self.hash
    }
    pub fn proto(&self) -> &IOpProto {
        &self.proto
    }
    pub fn streams(&self) -> &[Vec<u32>; MAX_HPU_IN_CLUSTER] {
        &self.streams
    }
}
