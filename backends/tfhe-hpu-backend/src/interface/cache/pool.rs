use bytemuck::Pod;
use std::collections::VecDeque;
use thiserror::Error;

use crate::ffi;
use crate::interface::memory;

/// Fw memory is split in a pool of slots.
/// Each slot is identified with a SlotId.
#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq)]
pub struct SlotId(usize);

impl SlotId {
    pub fn index(&self) -> usize {
        self.0
    }
}

pub struct Pool<T> {
    mem: memory::HugeMemory<T>,
    pool: VecDeque<SlotId>,
    #[allow(unused)]
    coef_per_slot: usize,
}

impl<T: Pod> Pool<T> {
    pub fn new(
        ffi_hw: &mut ffi::HpuHw,
        props: memory::HugeMemoryProperties,
        coef_per_slot: usize,
        reserved_word: Option<usize>,
    ) -> Self {
        let slot_nb = props.cut_coefs.div_ceil(coef_per_slot);
        let mem = memory::HugeMemory::alloc(ffi_hw, props);
        let reserved_slot =
            (reserved_word.unwrap_or(0) * std::mem::size_of::<T>()).div_ceil(coef_per_slot);
        let pool = (reserved_slot..slot_nb)
            .map(SlotId)
            .collect::<VecDeque<_>>();

        Self {
            mem,
            pool,
            coef_per_slot,
        }
    }

    /// Get a list of contiguous slots
    pub fn get_slots(&mut self, slot_nb: usize) -> Result<Vec<SlotId>, PoolError> {
        // Implement sliding windows search for contiguous block
        // TODO enhance this algorithm. Currently it's a naive implementation
        let mut win_slots = Vec::with_capacity(self.pool.capacity());

        loop {
            let slot = if let Some(slot) = self.pool.pop_front() {
                slot
            } else {
                return Err(PoolError::Full);
            };
            win_slots.push(slot);
            if win_slots.len() < slot_nb {
                continue;
            }
            win_slots.sort();

            for i in 0..=(win_slots.len() - slot_nb) {
                let is_contiguous = (0..slot_nb).all(|j| win_slots[i + j].0 == win_slots[i].0 + j);
                if is_contiguous {
                    let mut slots = Vec::with_capacity(slot_nb);
                    for (p, slot) in win_slots.into_iter().enumerate() {
                        if (p < i) || p >= (i + slot_nb) {
                            self.pool.push_back(slot);
                        } else {
                            slots.push(slot);
                        }
                    }
                    return Ok(slots);
                }
            }
        }
    }

    pub fn release_slots(&mut self, slots: &[SlotId]) {
        self.pool.extend(slots);
    }

    pub fn len(&self) -> usize {
        self.pool.len()
    }

    pub fn mem(&self) -> &memory::HugeMemory<T> {
        &self.mem
    }
    pub fn mem_mut(&mut self) -> &mut memory::HugeMemory<T> {
        &mut self.mem
    }
}

/// Pool Error type
#[derive(Error, Clone, Debug)]
pub enum PoolError {
    #[error("Pool is full")]
    Full,
}
