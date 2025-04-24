//!
//! Memory manager for HPU
//! Memory is allocatod upfront and abstract as a set of slot
use crate::ffi;
use crossbeam::queue::ArrayQueue;

/// Define the rate of WARNING on allocation retry
pub const ALLOC_RETRY_WARN_RATE: std::time::Duration = std::time::Duration::from_secs(1);

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
                    mem_kind: *kind,
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
    pub used_as_heap: usize,
    pub retry_rate_us: u64,
}

#[derive(Debug, Clone)]
pub struct CiphertextMemory {
    pub(crate) pool: std::sync::Arc<ArrayQueue<CiphertextSlot>>,
    retry_rate_us: u64,
}

impl std::ops::Deref for CiphertextMemory {
    type Target = std::sync::Arc<ArrayQueue<CiphertextSlot>>;

    fn deref(&self) -> &Self::Target {
        &self.pool
    }
}

/// Structure to keep track of Slot alongside pool
/// CiphertextSlot are automatically return back to pool on drop
#[derive(Debug)]
pub struct CiphertextBundle {
    slots: Vec<CiphertextSlot>,
    pool: CiphertextMemory,
}

impl Drop for CiphertextBundle {
    fn drop(&mut self) {
        let Self { slots, pool, .. } = self;
        while let Some(slot) = slots.pop() {
            pool.push(slot)
                .expect("Error: Release a slot in already full pool");
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
            .collect::<Vec<_>>();

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
                    let lsb_name = format!("hbm_axi4_addr_1in3::ct_pc{idx}_lsb");
                    let msb_name = format!("hbm_axi4_addr_1in3::ct_pc{idx}_msb");
                    let lsb = regmap
                        .register()
                        .get(&lsb_name)
                        .expect("Unknown register, check regmap definition");
                    let msb = regmap
                        .register()
                        .get(&msb_name)
                        .expect("Unknown register, check regmap definition");
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

        // Store slot in ArrayQueue for MpMc access
        let array_queue = ArrayQueue::new(props.slot_nb - props.used_as_heap);
        for (idx, slot) in pool.into_iter().enumerate() {
            if idx < (props.slot_nb - props.used_as_heap) {
                array_queue.push(slot).expect("Check ArrayQueue allocation");
            }
            // else slot is used by heap and shouldn't be handled by the ct pool
        }
        Self {
            pool: std::sync::Arc::new(array_queue),
            retry_rate_us: props.retry_rate_us,
        }
    }

    #[tracing::instrument(level = "trace", skip(ffi_hw), ret)]
    pub fn release(&mut self, ffi_hw: &mut ffi::HpuHw) {
        while let Some(mut slot) = self.pool.pop() {
            slot.release(ffi_hw)
        }
    }
}

impl CiphertextMemory {
    /// Extract a bundle of contiguous slot in pool
    #[tracing::instrument(level = "trace", skip(self), ret)]
    pub fn get_bundle(&self, bundle_size: usize) -> CiphertextBundle {
        // Implement sliding windows search for contiguous block
        // TODO enhance this algorithm. Currently it's a naive implementation
        let mut win_slots = Vec::with_capacity(self.pool.capacity());

        // Check for contiguousnes and extend the window if necessary
        loop {
            let mut retry = std::time::Duration::from_micros(0);
            let retry_rate = std::time::Duration::from_micros(self.retry_rate_us);
            let slot = loop {
                if let Some(slot) = self.pool.pop() {
                    break slot;
                } else {
                    std::thread::sleep(retry_rate);
                    retry += retry_rate;
                    if retry >= ALLOC_RETRY_WARN_RATE {
                        tracing::warn!("Allocation struggle more than {retry:?} to get ciphertext from pool. Check that your algorithm memory allocation and associated Hpu configuration");
                        retry = std::time::Duration::from_micros(0)
                    }
                }
            };
            win_slots.push(slot);
            if win_slots.len() < bundle_size {
                continue;
            }
            win_slots.sort_by(|a, b| a.id.partial_cmp(&b.id).unwrap());

            // Check contiguous
            for i in 0..=(win_slots.len() - bundle_size) {
                let is_contiguous =
                    (0..bundle_size).all(|j| win_slots[i + j].id == SlotId(win_slots[i].id.0 + j));
                if is_contiguous {
                    let mut slots = Vec::with_capacity(bundle_size);
                    for (p, slot) in win_slots.into_iter().enumerate() {
                        if (p < i) || p > (i + bundle_size) {
                            // Return slot to pool
                            self.pool
                                .push(slot)
                                .expect("Error: Release a slot in already full pool");
                        } else {
                            slots.push(slot)
                        }
                    }
                    return CiphertextBundle {
                        slots,
                        pool: self.clone(),
                    };
                }
            }
        }
    }

    /// Enforce CiphertextMemory completeness and ordering
    /// Use to prevent fragmentation between various workload
    ///
    /// Warn: This function could block in case of un-released ciphertext slots
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub fn reorder_pool(&self) {
        let all_in_one_bundle = self.get_bundle(self.pool.capacity());
        std::hint::black_box(&all_in_one_bundle);
        drop(all_in_one_bundle);
    }
}
