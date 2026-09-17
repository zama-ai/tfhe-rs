//!
//! Abstraction over Hpu ciphertext data
//! Handle lifetime management, deallocation and state inside HpuDevice.

use super::*;
use crate::asm::{IOpId, PhysId, SW_IOP_ID};
use crate::entities::{HpuLweCiphertextOwned, HpuParameters};
use std::sync::{Arc, Mutex};
use zhc::builder::{CiphertextSpec, Type};

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
    pub(crate) spec: CiphertextSpec,
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
        spec: CiphertextSpec,
    ) -> Self {
        let pool = &cluster.get(&hpu_id.0).expect("Invalid Hpu Id").ct_mem;
        let bundle = pool.get_bundle(width);

        Self {
            id: *bundle.id(),
            params,
            width,
            spec,
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
        spec: CiphertextSpec,
    ) -> Self {
        let var = Self::new_on(hpu_id, cluster, params, ct.len(), spec);

        // Write cpu_ct with correct interleaving in host buffer
        // Now value is considered CpuSync (i.e. data valid only on cpu-side)
        {
            let mut inner = var.inner.lock().unwrap();

            for (slot, ct) in std::iter::zip(inner.bundle.iter_mut(), ct) {
                #[cfg(feature = "io-dump")]
                let params = ct.params().clone();
                for (id, cut) in ct.into_container().iter().enumerate() {
                    slot.mz[id].write(0, cut);
                    #[cfg(feature = "io-dump")]
                    io_dump::dump(
                        cut.as_slice(),
                        &params,
                        io_dump::DumpKind::BlweIn,
                        io_dump::DumpId::Slot(slot.id, id),
                    );
                }
            }
        }
        var
    }

    /// Create a new HpuVarWrapped with same properties
    /// Associated data is != only share properties
    ///
    /// `trgt_ty` is the target's concrete type as declared by the IOp's zhc `Signature<Type>`.
    /// Since it already carries the target's absolute [`CiphertextSpec`] (bit-width and block
    /// layout), the new variable's storage width is derived directly from it.
    pub(crate) fn fork(&self, trgt_ty: &Type, trgt_pos: PhysId) -> Self {
        let Self { params, parent, .. } = self.clone();

        let trgt_spec = match trgt_ty {
            Type::Ciphertext(spec) => *spec,
            Type::Plaintext(_) => panic!("Couldn't fork a variable into a plaintext type"),
        };
        let width = trgt_spec.block_count() as usize;
        Self::new_on(trgt_pos, parent, params, width, trgt_spec)
    }

    /// This variable's own concrete bit-width. Used to key lookups into an IOp's zhc
    /// `Signature<Type>` (e.g. [`crate::interface::HpuCluster::get_signature`]).
    pub(crate) fn bit_width(&self) -> u16 {
        self.spec.int_size()
    }

    /// Check if this variable's own encoded width matches the given zhc `Type` (used to
    /// validate an assign-style IOp's rhs against its declared `Signature<Type>`).
    pub(crate) fn matches_type(&self, ty: &Type) -> bool {
        match ty {
            Type::Ciphertext(spec) => spec.int_size() == self.bit_width(),
            Type::Plaintext(_) => false,
        }
    }

    pub fn try_into(self) -> Result<Vec<HpuLweCiphertextOwned<u64>>, HpuError> {
        // Check if value is available
        let mut inner = self.inner.lock().unwrap();
        if !inner.ready() {
            drop(inner);
            return Err(HpuError::SyncPending(self));
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
    /// Currently 
    pub fn is_boolean(&self) -> bool {
        self.bit_width() == (self.spec.block_spec().message_size() as u16)
    }
}
