//!
//! Abstraction over Hpu ciphertext data
//! Handle lifetime management, deallocation and state inside HpuDevice.
use super::*;
use crate::asm::iop::VarMode;
use crate::entities::{HpuLweCiphertextOwned, HpuParameters};
use crate::ffi;
use std::sync::{mpsc, Arc, Mutex};

#[derive(Debug)]
enum SyncState {
    None,
    CpuSync,
    HpuSync,
    BothSync,
}

pub(crate) struct HpuVar {
    bundle: memory::CiphertextBundle,
    state: SyncState,
    pending: usize,
}

impl std::fmt::Debug for HpuVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HpuVar<{{state: {:?}, bundle: {:?}}}",
            self.state, self.bundle
        )
    }
}

/// Handle sync between Hpu and Cpu
impl HpuVar {
    pub fn try_cpu_sync(&mut self) -> Result<(), HpuInternalError> {
        if self.pending > 0 {
            Err(HpuInternalError::OperationPending)
        } else {
            match self.state {
                SyncState::CpuSync | SyncState::BothSync => Ok(()),
                SyncState::HpuSync => {
                    for slot in self.bundle.iter_mut() {
                        slot.mz
                            .iter_mut()
                            .for_each(|mz| mz.sync(ffi::SyncMode::Device2Host));
                    }
                    self.state = SyncState::BothSync;
                    Ok(())
                }
                SyncState::None => Err(HpuInternalError::UninitData),
            }
        }
    }

    pub(crate) fn try_hpu_sync(&mut self) -> Result<(), HpuInternalError> {
        // Nb: synced on hpu could be achieved even with registered pending IOp
        //    Indeed, this is used for assign IOp since dst == src.
        match self.state {
            SyncState::None => {
                if self.pending > 0 {
                    Ok(()) // Use of future result
                } else {
                    Err(HpuInternalError::UninitData)
                }
            }
            SyncState::HpuSync | SyncState::BothSync => Ok(()),
            SyncState::CpuSync => {
                for slot in self.bundle.iter_mut() {
                    slot.mz
                        .iter_mut()
                        .for_each(|mz| mz.sync(ffi::SyncMode::Host2Device));
                }
                self.state = if self.pending > 0 {
                    SyncState::HpuSync
                } else {
                    SyncState::BothSync
                };
                Ok(())
            }
        }
    }
}

impl HpuVar {
    pub(crate) fn operation_pending(&mut self) {
        self.pending += 1;
    }
    pub(crate) fn operation_done(&mut self) {
        if self.pending > 0 {
            self.pending -= 1;
            self.state = SyncState::HpuSync;
        } else {
            panic!("`operation_done` called on variable without pending operations");
        }
    }
}

#[derive(Clone)]
pub struct HpuVarWrapped {
    pub(crate) inner: Arc<Mutex<HpuVar>>,
    pub(crate) id: memory::ciphertext::SlotId,
    /// Reference to associated ct pool
    pub(crate) pool: memory::CiphertextMemory,
    /// Way to push cmd inside the backend without need of locking
    pub(crate) cmd_api: mpsc::Sender<cmd::HpuCmd>,
    pub(crate) params: Arc<HpuParameters>,
    pub(crate) width: usize,
    pub(crate) mode: VarMode,
}

impl std::fmt::Debug for HpuVarWrapped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HpuVarWrapped{{ {:?} }}", self.id)
    }
}

/// Conversion function between inner type and HpuLweCiphertext
impl HpuVarWrapped {
    fn new_in(
        pool: memory::CiphertextMemory,
        cmd_api: mpsc::Sender<cmd::HpuCmd>,
        params: Arc<HpuParameters>,
        width: usize,
        mode: VarMode,
    ) -> Self {
        let bundle = pool.get_bundle(width);

        Self {
            id: *bundle.id(),
            pool,
            cmd_api,
            params,
            width,
            mode,
            inner: Arc::new(Mutex::new(HpuVar {
                bundle,
                state: SyncState::None,
                pending: 0,
            })),
        }
    }

    pub(crate) fn new_from(
        pool: memory::CiphertextMemory,
        cmd_api: mpsc::Sender<cmd::HpuCmd>,
        params: Arc<HpuParameters>,
        ct: Vec<HpuLweCiphertextOwned<u64>>,
        mode: VarMode,
    ) -> Self {
        let var = Self::new_in(pool, cmd_api, params, ct.len(), mode);

        // Write cpu_ct with correct interleaving in host buffer
        // TODO check perf of mmap vs write
        // Now value is considered CpuSync (i.e. data valid only on cpu-side)
        {
            let mut inner = var.inner.lock().unwrap();

            for (slot, ct) in std::iter::zip(inner.bundle.iter_mut(), ct.into_iter()) {
                #[cfg(feature = "io-dump")]
                let params = ct.params().clone();
                for (id, cut) in ct.into_container().iter().enumerate() {
                    slot.mz[id].write(0, cut);
                    #[cfg(feature = "io-dump")]
                    io_dump::dump(
                        &cut.as_slice(),
                        &params,
                        io_dump::DumpKind::BlweIn,
                        io_dump::DumpId::Slot(slot.id, id),
                    );
                }
            }
            inner.state = SyncState::CpuSync;
        }
        var
    }

    /// Create a new HpuVarWrapped with same properties
    /// Associated data is != only share properties
    pub(crate) fn fork(&self, trgt_mode: VarMode) -> Self {
        let Self {
            pool,
            cmd_api,
            params,
            width,
            mode,
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
        Self::new_in(pool, cmd_api, params, width, trgt_mode)
    }

    pub fn try_into(self) -> Result<Vec<HpuLweCiphertextOwned<u64>>, HpuError> {
        // Check if value is available
        let mut inner = self.inner.lock().unwrap();
        match inner.try_cpu_sync() {
            Ok(_) => {}
            Err(err) => {
                drop(inner);
                match err {
                    HpuInternalError::OperationPending => return Err(HpuError::SyncPending(self)),
                    HpuInternalError::UninitData => {
                        panic!("Encounter unrecoverable HpuInternalError: {err:?}")
                    }
                }
            }
        }

        let mut ct = Vec::new();

        for slot in inner.bundle.iter() {
            // Allocate HpuLwe
            // and view inner buffer as cut
            let mut hpu_lwe = HpuLweCiphertextOwned::<u64>::new(0, (*self.params).clone());
            let mut hw_slice = hpu_lwe.as_mut_view().into_container();

            // Copy from Xrt memory
            #[allow(unused_variables)]
            std::iter::zip(slot.mz.iter(), hw_slice.iter_mut())
                .enumerate()
                .for_each(|(id, (mz, cut))| {
                    mz.read(0, cut);
                    #[cfg(feature = "io-dump")]
                    io_dump::dump(
                        &cut.as_ref(),
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
            match self.inner.lock().unwrap().try_cpu_sync() {
                Ok(_) => break,
                Err(err) => match err {
                    HpuInternalError::OperationPending => {}
                    HpuInternalError::UninitData => {
                        panic!("Encounter unrecoverable HpuInternalError: {err:?}")
                    }
                },
            }
        }
    }

    /// Check if inner value depicts a boolean
    pub fn is_boolean(&self) -> bool {
        self.mode == VarMode::Bool
    }
}
