//!
//! Abstraction over Hpu ciphertext data
//! Handle lifetime management, deallocation and state inside HpuDevice.

use super::*;
use crate::asm::iop::VarMode;
use crate::asm::{IOpId, PhysId, SW_IOP_ID};
use crate::entities::{HpuLweCiphertextOwned, HpuParameters};
use rayon::prelude::*;
use std::sync::{Arc, Mutex};

pub(crate) struct HpuVar {
    bundle: memory::CiphertextBundle,
    pending: usize,
    iid: IOpId,
}

impl std::fmt::Debug for HpuVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HpuVar<{{pending: {:?}, bundle: {:?}}}",
            self.pending, self.bundle
        )
    }
}

impl HpuVar {
    pub fn ready(&mut self) -> bool {
        self.pending == 0
    }

    pub(crate) fn operation_pending(&mut self, iid: IOpId) {
        self.pending += 1;
        self.iid = iid;
    }
    pub(crate) fn operation_done(&mut self) {
        if self.pending > 0 {
            self.pending -= 1;
        } else {
            panic!("`operation_done` called on variable without pending operations");
        }
    }
    pub(crate) fn iid(&self) -> IOpId {
        self.iid
    }
}

#[derive(Clone)]
pub struct HpuVarWrapped {
    pub(crate) inner: Arc<Mutex<HpuVar>>,
    // Properties that could be accessed without lock
    pub(crate) id: memory::ciphertext::SlotId,
    pub(crate) params: Arc<HpuParameters>,
    pub(crate) width: usize,
    pub(crate) mode: VarMode,
    /// Reference to associated cluster
    pub(crate) hpu_id: PhysId,
    pub(crate) parent: HpuClusterWrapped,
}

impl std::fmt::Debug for HpuVarWrapped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HpuVarWrapped{{ {:?} }}", self.id)
    }
}

/// Conversion function between inner type and HpuLweCiphertext
impl HpuVarWrapped {
    fn new_on(
        hpu_id: PhysId,
        cluster: HpuClusterWrapped,
        params: Arc<HpuParameters>,
        width: usize,
        mode: VarMode,
    ) -> Self {
        let pool = &cluster.get(&hpu_id.0).expect("Invalid Hpu Id").ct_mem;
        let bundle = pool.get_bundle(width);

        Self {
            id: *bundle.id(),
            params,
            width,
            mode,
            hpu_id,
            parent: cluster,
            inner: Arc::new(Mutex::new(HpuVar {
                bundle,
                pending: 0,
                iid: SW_IOP_ID,
            })),
        }
    }

    pub(crate) fn new_from(
        hpu_id: PhysId,
        cluster: HpuClusterWrapped,
        params: Arc<HpuParameters>,
        ct: Vec<HpuLweCiphertextOwned<u64>>,
        mode: VarMode,
    ) -> Self {
        let var = Self::new_on(hpu_id, cluster, params, ct.len(), mode);

        // Write cpu_ct with correct interleaving in host buffer
        // Now value is considered CpuSync (i.e. data valid only on cpu-side)
        {
            let mut inner = var.inner.lock().unwrap();

            #[cfg(feature = "io-dump")]
            for (slot, ct) in std::iter::zip(inner.bundle.iter(), &ct) {
                for (id, cut) in ct.as_view().into_container().iter().enumerate() {
                    io_dump::dump(
                        cut,
                        ct.params(),
                        io_dump::DumpKind::BlweIn,
                        io_dump::DumpId::Slot(slot.id, id),
                    );
                }
            }

            // One DMA transfer per PC, all slots
            let conts = ct
                .into_iter()
                .map(|ct| ct.into_container())
                .collect::<Vec<_>>();
            let first = inner.bundle.iter_mut().next().expect("Empty bundle");
            first.mz.par_iter_mut().enumerate().for_each(|(id, mz)| {
                let stride = mz.size() / std::mem::size_of::<u64>();
                let mut buf = vec![0u64; stride * conts.len()];
                for (slot, cont) in buf.chunks_exact_mut(stride).zip(&conts) {
                    slot[..cont[id].len()].copy_from_slice(&cont[id]);
                }
                mz.write(0, &buf);
            });
        }
        var
    }

    /// Create a new HpuVarWrapped with same properties
    /// Associated data is != only share properties
    pub(crate) fn fork(&self, trgt_mode: VarMode, trgt_pos: PhysId) -> Self {
        let Self {
            params,
            width,
            mode,
            parent,
            ..
        } = self.clone();

        let width = match (&mode, &trgt_mode) {
            (_, VarMode::Bool) => 1,
            (VarMode::Native, VarMode::Native) => width,
            (VarMode::Native, VarMode::Half) => width / 2,
            (VarMode::Half, VarMode::Native) => 2 * width,
            (VarMode::Half, VarMode::Half) => width,
            _ => panic!("Unsupported mode, couldn't use a Boolean to build a bigger variable"),
        };
        Self::new_on(trgt_pos, parent, params, width, trgt_mode)
    }

    pub fn try_into(self) -> Result<Vec<HpuLweCiphertextOwned<u64>>, HpuError> {
        // Check if value is available
        let mut inner = self.inner.lock().unwrap();
        if !inner.ready() {
            drop(inner);
            return Err(HpuError::SyncPending(self));
        }

        // One DMA transfer per PC, all slots
        let n_slots = inner.bundle.iter().len();
        let first = inner.bundle.iter().next().expect("Empty bundle");
        let bufs = first
            .mz
            .par_iter()
            .map(|mz| {
                let mut buf = vec![0u64; mz.size() / std::mem::size_of::<u64>() * n_slots];
                mz.read(0, &mut buf);
                buf
            })
            .collect::<Vec<_>>();

        let mut ct = Vec::new();

        #[allow(unused_variables)]
        for (s, slot) in inner.bundle.iter().enumerate() {
            // Allocate HpuLwe
            // and view inner buffer as cut
            let mut hpu_lwe = HpuLweCiphertextOwned::<u64>::new(0, (*self.params).clone());
            let mut hw_slice = hpu_lwe.as_mut_view().into_container();

            // Copy from bundle buffers
            #[allow(unused_variables)]
            std::iter::zip(bufs.iter(), hw_slice.iter_mut())
                .enumerate()
                .for_each(|(id, (buf, cut))| {
                    let stride = buf.len() / n_slots;
                    cut.copy_from_slice(&buf[s * stride..][..cut.len()]);
                    #[cfg(feature = "io-dump")]
                    io_dump::dump(
                        cut,
                        &self.params,
                        io_dump::DumpKind::BlweOut,
                        io_dump::DumpId::Slot(slot.id, id),
                    );
                });
            ct.push(hpu_lwe);
        }

        Ok(ct)
    }

    /// Retrieved a vector of HpuLweCiphertext from a Hpu variable
    /// Blocking call that pool the Hpu Backend until variable is ready
    pub fn into_ct(self) -> Vec<HpuLweCiphertextOwned<u64>> {
        // TODO Replace pooling with IRQ when supported by the backend
        let mut var = self;
        loop {
            var = match var.try_into() {
                Ok(ct) => break ct,
                Err(err) => match err {
                    HpuError::SyncPending(v) => v,
                },
            }
        }
    }

    /// Wait end of pending operation and synced on Cpu side
    /// Blocking call that pool the Hpu Backend until variable is ready
    pub fn wait(&self) {
        loop {
            if self.inner.lock().unwrap().ready() {
                break;
            }
        }
    }

    /// Check if inner value depicts a boolean
    pub fn is_boolean(&self) -> bool {
        self.mode == VarMode::Bool
    }
}
