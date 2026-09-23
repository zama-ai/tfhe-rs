//!
//! Abstraction over Hpu ciphertext data
//! Handle lifetime management, deallocation and state inside HpuDevice.
//!
//! A variable is backed by two buffers:
//!  * `host_mem`: a plain host-side vector of [`HpuLweCiphertextOwned`]
//!  * `hpu_mem`: a bundle of on-board ciphertext slots
//!
//! The on-board buffer is allocated lazily (c.f. [`HpuVarWrapped::dispatch_on`]): the targeted
//! node is only selected when a computation is issued on the variable. This prevents pinning
//! data on a node before knowing where the associated work will run, and thus reduces
//! board-to-board transfers inside a cluster.

use super::*;
use crate::asm::{IOpId, PhysId, SW_IOP_ID};
use crate::entities::{HpuLweCiphertextOwned, HpuParameters};
use memory::ciphertext::SlotId;
use std::sync::{Arc, Mutex, OnceLock};
use zhc::builder::{CiphertextSpec, Type};

/// Depict the position of the data.
/// Enable to triggered data transfer only on purpose
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyncState {
    /// Variable doesn't hold any valid value yet
    None,
    /// Only the host buffer is up to date
    Host,
    /// Only the on-board buffer is up to date
    Hpu,
    /// Both buffers hold the same value
    Both,
}

pub(crate) struct HpuVar {
    params: Arc<HpuParameters>,
    /// Number of Lwe blocks handled by the variable
    blocks: u8,
    /// Host-side mirror.
    /// Lazily allocated: a variable that is only produced and consumed by the Hpu never pays
    /// for it.
    host_mem: Vec<HpuLweCiphertextOwned<u64>>,
    /// On-board slots alongside the node they belong to.
    /// `None` until the variable is dispatched.
    hpu_mem: Option<(PhysId, memory::CiphertextBundle)>,
    sync_state: SyncState,
    pending: usize,
    iid: IOpId,
}

impl std::fmt::Debug for HpuVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HpuVar<{{state: {:?}, pending: {:?}, hpu_mem: {:?}}}",
            self.sync_state,
            self.pending,
            self.hpu_mem
                .as_ref()
                .map(|(hid, bundle)| (hid, bundle.id()))
        )
    }
}

impl HpuVar {
    fn new(
        params: Arc<HpuParameters>,
        blocks: u8,
        from: Option<Vec<HpuLweCiphertextOwned<u64>>>,
    ) -> Self {
        let (host_mem, sync_state) = match from {
            Some(ct) => {
                assert_eq!(
                    ct.len(),
                    blocks as usize,
                    "Ciphertext blocks number mismatch with variable specification"
                );
                (ct, SyncState::Host)
            }
            // NB: host_mem is allocated on demand (c.f. `try_host_sync`)
            None => (Vec::new(), SyncState::None),
        };

        Self {
            params,
            blocks,
            host_mem,
            hpu_mem: None,
            sync_state,
            pending: 0,
            iid: SW_IOP_ID,
        }
    }

    /// Handle dispatch over Hpu
    /// Dispatch is a lazy-allocation mechanisms that enable to select a targeted node only
    ///  when computation is triggered
    ///
    /// `bundle` is acquired by the caller outside of the variable lock (c.f.
    /// [`HpuVarWrapped::dispatch_on`]). If the variable happens to be already dispatched, the
    /// surplus bundle is dropped here, i.e. given back to its pool, and the effective position
    /// is returned instead.
    fn dispatch(&mut self, hid: PhysId, bundle: memory::CiphertextBundle) -> (PhysId, SlotId) {
        match self.hpu_mem.as_ref() {
            Some((cur_hid, cur_bundle)) => (*cur_hid, *cur_bundle.id()),
            None => {
                let pos = (hid, *bundle.id());
                self.hpu_mem = Some((hid, bundle));
                pos
            }
        }
    }
}

/// Handle sync between Host and Hpu
impl HpuVar {
    /// Enforce that the host buffer holds the up to date value.
    /// Trigger a board -> host transfer only when required.
    pub(crate) fn try_host_sync(&mut self) -> Result<(), HpuInternalError> {
        if self.pending > 0 {
            return Err(HpuInternalError::OperationPending);
        }
        match self.sync_state {
            SyncState::Host | SyncState::Both => Ok(()),
            SyncState::None => Err(HpuInternalError::UnInitData),
            SyncState::Hpu => {
                let Self {
                    params,
                    blocks,
                    host_mem,
                    hpu_mem,
                    sync_state,
                    ..
                } = self;
                let (_hid, bundle) = hpu_mem.as_ref().ok_or(HpuInternalError::UnAllocData)?;

                // Allocate the host mirror on first read-back
                if host_mem.is_empty() {
                    *host_mem = (0..*blocks)
                        .map(|_| HpuLweCiphertextOwned::new(0, (**params).clone()))
                        .collect::<Vec<_>>();
                }

                for (host_block, hpu_slot) in std::iter::zip(host_mem.iter_mut(), bundle.iter()) {
                    let mut host_cut = host_block.as_mut_view().into_container();

                    #[allow(unused_variables)]
                    for (id, (cut, mz)) in
                        std::iter::zip(host_cut.iter_mut(), hpu_slot.mz.iter()).enumerate()
                    {
                        mz.read(0, cut);
                        #[cfg(feature = "io-dump")]
                        io_dump::dump(
                            cut,
                            params,
                            io_dump::DumpKind::BlweOut,
                            io_dump::DumpId::Slot(hpu_slot.id, id),
                        );
                    }
                }
                *sync_state = SyncState::Both;
                Ok(())
            }
        }
    }

    /// Enforce that the on-board buffer holds the up to date value.
    /// Trigger a host -> board transfer only when required.
    pub(crate) fn try_hpu_sync(&mut self) -> Result<(), HpuInternalError> {
        // Nb: synced on hpu could be achieved even with registered pending IOp
        //    Indeed, this is used for assign IOp since dst == src.
        match self.sync_state {
            SyncState::None => {
                if self.pending > 0 {
                    Ok(()) // Use of future result
                } else {
                    Err(HpuInternalError::UnInitData)
                }
            }
            SyncState::Hpu | SyncState::Both => Ok(()),
            SyncState::Host => {
                // `params` is only consumed by the `io-dump` feature
                #[cfg_attr(not(feature = "io-dump"), allow(unused_variables))]
                let Self {
                    params,
                    host_mem,
                    hpu_mem,
                    sync_state,
                    pending,
                    ..
                } = self;
                let (_hid, bundle) = hpu_mem.as_mut().ok_or(HpuInternalError::UnAllocData)?;

                for (hpu_slot, host_block) in std::iter::zip(bundle.iter_mut(), host_mem.iter()) {
                    let host_cut = host_block.as_view().into_container();

                    #[allow(unused_variables)]
                    for (id, (mz, cut)) in
                        std::iter::zip(hpu_slot.mz.iter_mut(), host_cut.iter()).enumerate()
                    {
                        mz.write(0, cut);
                        #[cfg(feature = "io-dump")]
                        io_dump::dump(
                            cut,
                            params,
                            io_dump::DumpKind::BlweIn,
                            io_dump::DumpId::Slot(hpu_slot.id, id),
                        );
                    }
                }
                // An IOp is already targeting this variable, it will overwrite the on-board
                // value -> host mirror couldn't be considered in sync.
                *sync_state = if *pending > 0 {
                    SyncState::Hpu
                } else {
                    SyncState::Both
                };
                Ok(())
            }
        }
    }
}

impl HpuVar {
    pub fn ready(&self) -> bool {
        self.pending == 0
    }

    pub(crate) fn operation_pending(&mut self, iid: IOpId) {
        self.pending += 1;
        self.iid = iid;
        // Hw is about to overwrite the on-board buffer.
        // Whatever the host mirror used to hold, it's now stale.
        self.sync_state = SyncState::Hpu;
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
    /// Node and base slot the variable is bound to.
    /// Empty until the variable is dispatched. Shared by every clone so that a dispatch issued
    /// through one handle is immediately visible -- without locking -- through the others.
    pub(crate) position: Arc<OnceLock<(PhysId, SlotId)>>,
    pub(crate) spec: CiphertextSpec,
    /// Reference to associated cluster
    pub(crate) parent: HpuClusterWrapped,
}

impl std::fmt::Debug for HpuVarWrapped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HpuVarWrapped{{ {:?} }}", self.position.get())
    }
}

/// Conversion function between inner type and HpuLweCiphertext
impl HpuVarWrapped {
    /// Create a variable from scratch.
    ///
    /// `spec` fully describes the variable (bit-width and block layout), so the cluster is the
    /// only other thing needed: parameters are read back from it.
    /// Optionally initialized with `from` and optionally dispatched on a given node.
    ///
    /// Leaving `pos` to `None` defers the node selection to the first IOp using the variable
    /// (c.f. [`crate::interface::HpuCmd::exec_raw`]).
    pub(crate) fn new(
        cluster: HpuClusterWrapped,
        spec: CiphertextSpec,
        pos: Option<PhysId>,
        from: Option<Vec<HpuLweCiphertextOwned<u64>>>,
    ) -> Self {
        let data_avail = from.is_some();
        let inner = HpuVar::new(cluster.params.clone(), spec.block_count(), from);

        let var = Self {
            inner: Arc::new(Mutex::new(inner)),
            position: Arc::new(OnceLock::new()),
            spec,
            parent: cluster,
        };

        // User explicitly requested an early allocation on a given node
        if let Some(hid) = pos {
            let _ = var.dispatch_and_sync(hid, data_avail);
        }
        var
    }

    /// This variable's own concrete bit-width. Used to key lookups into an IOp's zhc
    /// `Signature<Type>` (e.g. [`crate::interface::HpuCluster::get_signature`]).
    pub(crate) fn bit_width(&self) -> u16 {
        self.spec.int_size()
    }

    /// Number of Lwe blocks backing this variable, i.e. the number of on-board slots it
    /// requires. Available without locking.
    pub(crate) fn blocks(&self) -> u8 {
        self.spec.block_count()
    }

    /// Check if this variable's own encoded width matches the given zhc `Type` (used to
    /// validate an assign-style IOp's rhs against its declared `Signature<Type>`).
    pub(crate) fn matches_type(&self, ty: &Type) -> bool {
        match ty {
            Type::Ciphertext(spec) => spec.int_size() == self.bit_width(),
            Type::Plaintext(_) => false,
        }
    }
}

/// Late allocation and host/board synchronization
impl HpuVarWrapped {
    /// Node and base slot the variable is bound to, `None` if not dispatched yet.
    /// Probed without taking the inner lock.
    pub(crate) fn position(&self) -> Option<(PhysId, SlotId)> {
        self.position.get().copied()
    }

    /// Node the variable is bound to, `None` if not dispatched yet.
    /// Probed without taking the inner lock.
    pub fn hpu_pos(&self) -> Option<PhysId> {
        self.position.get().map(|(hid, _sid)| *hid)
    }

    /// Check if the variable already owns on-board memory.
    /// Probed without taking the inner lock.
    pub fn is_dispatched(&self) -> bool {
        self.position.get().is_some()
    }

    /// Bind the variable to a bundle of on-board slots of node `hid`.
    ///
    /// Optionally sync data on board. Both functions are fused to prevent double lock on mutex
    ///
    /// Idempotent: a variable already dispatched keeps its position, which is returned as is
    /// and might thus differ from `hid`.
    pub(crate) fn dispatch_and_sync(
        &self,
        hid: PhysId,
        sync: bool,
    ) -> Result<(PhysId, SlotId), HpuInternalError> {
        if let Some(pos) = self.position.get() {
            if sync {
                self.try_hpu_sync()?;
            }
            return Ok(*pos);
        }

        // Acquire the slots *before* locking the variable: `get_bundle` blocks while the pool
        // is empty and the ack background thread requires that very lock to release the slots
        // held by completed IOp.
        let pool = &self.parent.get(&hid.0).expect("Invalid Hpu Id").ct_mem;
        let bundle = pool.get_bundle(self.blocks() as usize);

        let mut inner_lock = self.inner.lock().expect("Error with variable mutex");
        // Inner lock arbitrates concurrent dispatch of the same variable: the surplus bundle
        // is released by `dispatch` and every racer observes the very same position.
        let pos = inner_lock.dispatch(hid, bundle);
        if sync {
            inner_lock.try_hpu_sync()?;
        }
        let _ = self.position.set(pos);
        Ok(pos)
    }

    /// Bind the variable to a bundle of on-board slots of node `hid`.
    pub(crate) fn dispatch_on(&self, hid: PhysId) -> (PhysId, SlotId) {
        self.dispatch_and_sync(hid, false)
            .expect("Unexpected sync error")
    }

    /// Enforce that the on-board buffer of the variable holds the up to date value.
    /// Variable must have been dispatched beforehand.
    pub(crate) fn try_hpu_sync(&self) -> Result<(), HpuInternalError> {
        self.inner
            .lock()
            .expect("Error with variable mutex")
            .try_hpu_sync()
    }
}

impl HpuVarWrapped {
    pub fn try_into(self) -> Result<Vec<HpuLweCiphertextOwned<u64>>, HpuError> {
        // Enforce that the host buffer is up to date.
        // NB: this is the only place triggering a board -> host transfer.
        {
            let mut inner = self.inner.lock().expect("Error with variable mutex");
            match inner.try_host_sync() {
                Ok(_) => {}
                Err(err) => {
                    drop(inner);
                    match err {
                        HpuInternalError::OperationPending => {
                            return Err(HpuError::SyncPending(self))
                        }
                        HpuInternalError::UnInitData | HpuInternalError::UnAllocData => {
                            panic!("Encounter unrecoverable HpuInternalError: {err:?}")
                        }
                    }
                }
            }
        }

        // Try to extract inner host_mem if possible otherwise clone it
        let Self { inner, .. } = self;
        let host_mem = match Arc::try_unwrap(inner) {
            Ok(mutex) => {
                mutex
                    .into_inner()
                    .unwrap_or_else(|err| err.into_inner())
                    .host_mem
            }
            // Variable is still referenced elsewhere (an other handle, a pending IOp, ...)
            // -> the host buffer must be kept in place.
            Err(arc) => arc
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .host_mem
                .clone(),
        };
        Ok(host_mem)
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
            if self
                .inner
                .lock()
                .expect("Error with variable mutex")
                .ready()
            {
                break;
            }
        }
    }

    /// Check if inner value depicts a boolean
    /// Currently
    pub fn is_boolean(&self) -> bool {
        self.bit_width() == (self.spec.block_spec().message_size() as u16)
    }
}
