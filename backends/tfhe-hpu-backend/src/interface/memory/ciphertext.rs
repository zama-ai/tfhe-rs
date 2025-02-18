//!
//! Memory manager for HPU
//! Memory is allocatod upfront and abstract as a set of slot
use crate::ffi;
use std::collections::VecDeque;
use std::sync::mpsc;

/// Describe Slot position
/// Abstract from internal ASM type to help with future
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
pub struct SlotId(pub(crate) usize);

/// Ciphertext could be spread over multiple HbmPc.
/// A Slot is describe as a position and a set of associated MemZone
pub struct CiphertextSlot {
    pub(crate) id: SlotId,
    pub(crate) mz: Vec<ffi::MemZone>,
}

impl std::fmt::Debug for CiphertextSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.id)
    }
}

impl CiphertextSlot {
    fn alloc(ffi_hw: &mut ffi::HpuHw, id: SlotId, props: &CiphertextMemoryProperties) -> Self {
        let mz = props
            .mem_cut
            .iter()
            .map(|kind| {
                let cut_props = ffi::MemZoneProperties {
                    mem_kind: kind.clone(),
                    size_b: props.cut_size_b,
                };
                ffi_hw.alloc(cut_props)
            })
            .collect::<Vec<_>>();
        CiphertextSlot { id, mz }
    }

    fn release(&mut self, ffi_hw: &mut ffi::HpuHw) {
        self.mz.iter_mut().for_each(|mz| ffi_hw.release(mz));
    }
}

#[derive(Debug, Clone)]
pub struct CiphertextMemoryProperties {
    pub mem_cut: Vec<ffi::MemKind>,
    pub cut_size_b: usize,
    pub slot_nb: usize,
}

#[derive(Debug)]
pub struct CiphertextMemory {
    pool: VecDeque<CiphertextSlot>,
    /// Slot free are done through mpsc channel
    free_rx: mpsc::Receiver<CiphertextSlot>,
    free_tx: mpsc::Sender<CiphertextSlot>,
}

/// Structure to keep track of Slot alongside free channel
/// CiphertextSlot are automatically return back to pool on drop
#[derive(Debug)]
pub struct CiphertextBundle {
    slots: Vec<CiphertextSlot>,
    free_tx: mpsc::Sender<CiphertextSlot>,
}

impl Drop for CiphertextBundle {
    fn drop(&mut self) {
        let Self { slots, free_tx, .. } = self;
        while let Some(slot) = slots.pop() {
            free_tx
                .send(slot)
                .expect("CiphertextBundle: Issue with garbage collection");
        }
    }
}

impl CiphertextBundle {
    /// Bundle is characterized by its first slot
    pub fn id(&self) -> &SlotId {
        &self.slots[0].id
    }
    pub fn iter(&mut self) -> std::slice::Iter<'_, CiphertextSlot> {
        self.slots.iter()
    }
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, CiphertextSlot> {
        self.slots.iter_mut()
    }
}

impl CiphertextMemory {
    #[tracing::instrument(level = "trace", skip(ffi_hw, regmap), ret)]
    pub fn alloc(
        ffi_hw: &mut ffi::HpuHw,
        regmap: &hw_regmap::FlatRegmap,
        props: &CiphertextMemoryProperties,
    ) -> Self {
        let pool = (0..props.slot_nb)
            .map(|cid| {
                let id = SlotId(cid);
                CiphertextSlot::alloc(ffi_hw, id, props)
            })
            .collect::<VecDeque<_>>();

        let mut paddr = Vec::with_capacity(props.mem_cut.len());
        if !pool.is_empty() {
            // Sanity check
            // Slot must be contiguous in each cut

            for cut_nb in 0..props.mem_cut.len() {
                let base_addr = pool[0].mz[cut_nb].paddr();
                paddr.push(base_addr);

                pool.iter().enumerate().for_each(|(i, slot)| {
                    let cont_addr = base_addr + (i * props.cut_size_b) as u64;
                    let real_addr = slot.mz[cut_nb].paddr();
                    assert_eq!(
                        cont_addr, real_addr,
                        "Ct slot@{i} weren't contiguous in memory"
                    );
                });
            }

            // Extract LdSt_addr_pc register addr
            let ldst_addr_pc = (0..props.mem_cut.len())
                .map(|idx| {
                    let lsb_name = format!("LdSt::addr_pc{idx}_lsb");
                    let msb_name = format!("LdSt::addr_pc{idx}_msb");
                    let lsb = regmap
                        .register()
                        .get(&lsb_name)
                        .expect("Unknow register, check regmap definition");
                    let msb = regmap
                        .register()
                        .get(&msb_name)
                        .expect("Unknow register, check regmap definition");
                    (lsb, msb)
                })
                .collect::<Vec<_>>();

            // Write pc_addr in registers
            for (addr, (lsb, msb)) in std::iter::zip(paddr.iter(), ldst_addr_pc.iter()) {
                ffi_hw.write_reg(
                    *msb.offset() as u64,
                    ((addr >> u32::BITS) & (u32::MAX) as u64) as u32,
                );
                ffi_hw.write_reg(*lsb.offset() as u64, (addr & (u32::MAX as u64)) as u32);
            }
        }
        // Construct channel for mt API
        // Keep track of the sender for clone it later on
        let (free_tx, free_rx) = mpsc::channel();

        Self {
            pool,
            free_rx,
            free_tx,
        }
    }

    #[tracing::instrument(level = "trace", skip(ffi_hw), ret)]
    pub fn release(&mut self, ffi_hw: &mut ffi::HpuHw) {
        self.pool.iter_mut().for_each(|slot| slot.release(ffi_hw));
    }
}

impl CiphertextMemory {
    /// Extract a bundle of contiguous slot in pool
    #[tracing::instrument(level = "trace", skip(self), ret)]
    pub fn get_bundle(&mut self, bundle_size: usize) -> CiphertextBundle {
        // TODO handle fragmentation
        // Check that bundle is contiguous

        // TODO check that given bundle wasn't reserved for heap
        // NB: Heap must be outside of allocated memory to prevent collision
        // However, this `unseen` memory couldn't be correctly handled by the
        // current mockup implementation
        // FIXME

        let mut slots = Vec::with_capacity(bundle_size);
        for _ in 0..bundle_size {
            slots.push(self.pool.pop_front().unwrap());
        }

        CiphertextBundle {
            slots,
            free_tx: self.free_tx.clone(),
        }
    }

    /// Return a set of slot into the pool
    /// Pool is sorted after the operation to prevent fragmentation
    #[tracing::instrument(level = "trace", skip(self), ret)]
    pub(crate) fn gc_bundle(&mut self) {
        while let Ok(slot) = self.free_rx.try_recv() {
            self.pool.push_back(slot);
        }
        self.pool
            .make_contiguous()
            .sort_by(|a, b| a.id.partial_cmp(&b.id).unwrap());
    }
}
