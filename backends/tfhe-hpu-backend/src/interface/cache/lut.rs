//! Lut cache handling.
//!
//! On board LUT are store in a cache to enable inspection and addition/deletion runtime.
//! This enable dyn Iop to reuse available LUT while keeping abilities to upload new one if needed
//! Each LUT (i.e. GLWE) use same size, no need to handle memory fragmentation here

use crate::ffi;
#[cfg(feature = "io-dump")]
use crate::interface::io_dump;
use crate::interface::memory;
use crate::prelude::HpuGlweLookuptableOwned;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

use super::{Pool, PoolError, SlotId};
use zhc::crypto::integer_semantics::lut::{LutId, RawLut};

/// Keep track of uploaded LUT and associated properties
pub struct LutCache {
    // Keep two cache entry indexing for fast bidir lookup
    hash_entries: HashMap<RawLut, Arc<LutEntry>>,
    id_entries: HashMap<LutId, Arc<LutEntry>>,

    // Management of underlying storage
    pool: Pool<u64>,
}

#[allow(unused)]
impl LutCache {
    pub fn new(
        ffi_hw: &mut ffi::HpuHw,
        kind: ffi::MemKind,
        lut_number: usize,
        lut_size: usize,
    ) -> Self {
        let mem_props = memory::HugeMemoryProperties {
            mem_cut: vec![kind],
            cut_coefs: lut_number * lut_size,
        };

        Self {
            hash_entries: HashMap::new(),
            id_entries: HashMap::new(),
            pool: Pool::new(ffi_hw, mem_props, lut_size, None),
        }
    }

    pub fn get_by_hash(&self, hash: &RawLut) -> Option<Arc<LutEntry>> {
        self.hash_entries.get(hash).cloned()
    }
    pub fn get_by_iop(&self, id: &LutId) -> Option<Arc<LutEntry>> {
        self.id_entries.get(id).cloned()
    }

    pub fn get_or_insert<F>(&mut self, lut: RawLut, gen_lut: &F) -> Result<Arc<LutEntry>, LutError>
    where
        F: Fn(&RawLut) -> HpuGlweLookuptableOwned<u64>,
    {
        if let Some(e) = self.get_by_hash(&lut) {
            return Ok(e);
        }

        // Allocate slot
        let slot = self.pool.get_slots(1)?.pop().unwrap();

        // Direct mapping between LudId and SlotId
        let id = LutId(slot.index());

        // Expand lut in crypto_lut and upload in HW
        let hpu_lut = gen_lut(&lut);

        // Write in memory
        // NB: lut_mem is always on 1 cut only
        let ofst = slot.index() * hpu_lut.params().pbs_params.polynomial_size;
        self.pool
            .mem_mut()
            .write_cut_at(0, ofst, hpu_lut.as_view().into_container());

        #[cfg(feature = "io-dump")]
        io_dump::dump(
            hpu_lut.as_ref(),
            hpu_lut.params(),
            io_dump::DumpKind::Glwe,
            io_dump::DumpId::Lut(slot.index()),
        );

        // Insert entry in cache
        let entry = Arc::new(LutEntry {
            id,
            slot,
            lut: lut.clone(),
        });
        self.hash_entries.insert(lut, entry.clone());
        self.id_entries.insert(id, entry.clone());

        Ok(entry)
    }

    pub fn flush_by_id(&mut self, id: &LutId) -> Result<(), LutError> {
        if let Some(entry) = self.id_entries.remove(id) {
            // Release  associated slot
            self.pool.release_slots(&[entry.slot]);

            // Remove associated entry in hash view
            self.hash_entries
                .remove(&entry.lut)
                .ok_or(LutError::UnsyncView)?;
            Ok(())
        } else {
            Err(LutError::LutNotFound(*id))
        }
    }

    pub fn flush_by_lut(&mut self, lut: &RawLut) -> Result<(), LutError> {
        if let Some(entry) = self.hash_entries.remove(lut) {
            // Release  associated slot
            self.pool.release_slots(&[entry.slot]);

            // Remove associated entry in id view
            self.id_entries
                .remove(&entry.id)
                .ok_or(LutError::UnsyncView)?;
            Ok(())
        } else {
            Err(LutError::HashNotFound(lut.clone()))
        }
    }

    pub fn flush_all(&mut self) -> Result<usize, LutError> {
        let ids = self.id_entries.keys().copied().collect::<Vec<_>>();

        for id in ids.iter() {
            self.flush_by_id(id)?;
        }

        if !self.hash_entries.is_empty() {
            Err(LutError::UnsyncView)
        } else {
            Ok(self.pool.len())
        }
    }

    pub fn release(&mut self, ffi_hw: &mut ffi::HpuHw) {
        let _ = self.flush_all();
        self.pool.mem_mut().release(ffi_hw);
    }

    pub fn get_pool_paddr(&self) -> u64 {
        self.pool.mem().cut_paddr()[0]
    }

    pub fn get_stats(&self) -> usize {
        self.id_entries.len()
    }
}

/// Cache Error type
#[derive(Error, Clone, Debug)]
pub enum LutError {
    #[error("Cache is full")]
    CacheFull,
    #[error("{0:?} is not currently in use")]
    LutNotFound(LutId),
    #[error("{0:?} is not currently in use")]
    HashNotFound(RawLut),
    #[error("Unsync view between hash/id _entries")]
    UnsyncView,
}

impl From<PoolError> for LutError {
    fn from(value: PoolError) -> Self {
        match value {
            PoolError::Full => Self::CacheFull,
        }
    }
}

#[allow(unused)]
pub struct LutEntry {
    id: LutId,
    lut: RawLut,
    slot: SlotId,
}

#[allow(unused)]
impl LutEntry {
    pub fn id(&self) -> &LutId {
        &self.id
    }
    pub fn lut(&self) -> &RawLut {
        &self.lut
    }
    pub fn slot(&self) -> &SlotId {
        &self.slot
    }
}
