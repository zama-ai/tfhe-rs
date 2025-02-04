//!
//! Abstraction over Hpu ciphertext data
//! Handle lifetime management, deallocation and state inside HpuDevice.
use super::*;
use crate::entities::{HpuLweCiphertextOwned, HpuParameters};
use crate::{asm, ffi};
use backend::HpuBackendWrapped;
use std::sync::{mpsc, Arc, Mutex};

#[derive(Debug)]
enum SyncState {
    None,
    CpuSync,
    HpuSync,
    BothSync,
    OperationPending,
}

pub(crate) struct HpuVar {
    /// Reference to associated backend to be able to allocate dst variable with std::ops trait
    backend: backend::HpuBackendWrapped,
    /// Way to push cmd insid the backend without need of locking
    cmd_api: mpsc::Sender<cmd::HpuCmd>,
    bundle: memory::CiphertextBundle,
    state: SyncState,
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
        match self.state {
            SyncState::None | SyncState::OperationPending => Err(HpuInternalError::SyncPending),
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
        }
    }

    pub(crate) fn try_hpu_sync(&mut self) -> Result<(), HpuInternalError> {
        match self.state {
            SyncState::None => Err(HpuInternalError::SyncPending),
            SyncState::HpuSync | SyncState::BothSync | SyncState::OperationPending => Ok(()),
            SyncState::CpuSync => {
                for slot in self.bundle.iter_mut() {
                    slot.mz
                        .iter_mut()
                        .for_each(|mz| mz.sync(ffi::SyncMode::Host2Device));
                }
                self.state = SyncState::BothSync;
                Ok(())
            }
        }
    }
}

impl HpuVar {
    pub(crate) fn operation_pending(&mut self) {
        self.state = SyncState::OperationPending;
    }
    pub(crate) fn operation_done(&mut self) {
        self.state = SyncState::HpuSync;
    }
}

/// Parameters inspection
impl HpuVar {
    pub fn params(&self) -> HpuParameters {
        let params = {
            let be_lock = self.backend.lock().unwrap();
            be_lock.params.clone()
        };
        params
    }
}

#[derive(Clone)]
pub struct HpuVarWrapped {
    pub(crate) inner: Arc<Mutex<HpuVar>>,
    id: memory::ciphertext::SlotId,
    width: usize,
}

impl std::fmt::Debug for HpuVarWrapped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HpuVarWrapped{{ {:?} }}", self.id)
    }
}

/// Conversion function between inner type and HpuLweCiphertext
impl HpuVarWrapped {
    fn new_on(backend: HpuBackendWrapped, width: usize) -> Self {
        let (bundle, cmd_api) = {
            let mut be_lock = backend.lock().unwrap();
            (be_lock.ct_mem.get_bundle(width), be_lock.cmd_tx.clone())
        };

        Self {
            width,
            id: bundle.id().clone(),
            inner: Arc::new(Mutex::new(HpuVar {
                backend,
                cmd_api,
                bundle,
                state: SyncState::None,
            })),
        }
    }

    pub(crate) fn new_from(
        backend: HpuBackendWrapped,
        ct: Vec<HpuLweCiphertextOwned<u64>>,
    ) -> Self {
        let var = Self::new_on(backend, ct.len());

        // Write cpu_ct with correct interleaving in host buffer
        // TODO check perf of mmap vs write
        // Now value is considered CpuSync (i.e. data valid only on cpu-side)
        {
            let mut inner = var.inner.lock().unwrap();

            for (slot, ct) in std::iter::zip(inner.bundle.iter_mut(), ct.into_iter()) {
                #[cfg(feature = "io-dump")]
                let params = ct.params().clone();
                for (id, cut) in ct.into_container().iter().enumerate() {
                    slot.mz[id].write(0, &cut);
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

    pub fn try_into(self) -> Result<Vec<HpuLweCiphertextOwned<u64>>, HpuError> {
        // Check if value is available
        let mut inner = self.inner.lock().unwrap();
        match inner.try_cpu_sync() {
            Ok(_) => {}
            Err(x) => {
                drop(inner);
                match x {
                    HpuInternalError::SyncPending => return Err(HpuError::SyncPending(self)),
                }
            }
        }

        let params = inner.params();
        let mut ct = Vec::new();

        for slot in inner.bundle.iter() {
            // Allocate HpuLwe
            // and view inner buffer as cut
            let mut hpu_lwe = HpuLweCiphertextOwned::<u64>::new(0, params.clone());
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
                        &params,
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


    pub fn wait(&self) {
        let mut inner = self.inner.lock().unwrap();
        let _ = inner.try_cpu_sync();

    }
}

/// Easily construct asm::Arg from HpuVarWrapped
impl HpuVarWrapped {
    pub fn as_arg(&self) -> asm::Arg {
        // Extract bid/cid of first ct slot
        let memory::ciphertext::SlotId { bid, cid } = self.id;
        let mem_slot = asm::MemSlot::new_uncheck(bid, cid, asm::arg::MemMode::Raw, None);
        asm::Arg::MemId(mem_slot)
    }
}

/// Generic Iop function call
impl HpuVarWrapped {
    /// This function format and push associated work in cmd_api
    /// IOp format is Ct <- Ct x Ct
    /// IOp width is inferred from operand width
    #[inline(always)]
    fn iop_ct_raw(name: crate::asm::IOpName, dst: &Self, rhs_0: &Self, rhs_1: &Self) {
        let hpu_op = cmd::HpuCmd::new_ct_ct(name, dst.clone(), rhs_0.clone(), rhs_1.clone());
        dst.inner
            .lock()
            .unwrap()
            .cmd_api
            .send(hpu_op.into())
            .expect("Issue with cmd_api");
    }

    /// This function format and push associated work in cmd_api
    /// IOp format is Ct <- Ct x Ct
    /// IOp width is inferred from operand width
    /// Dst operand is allocated
    pub fn iop_ct(self, name: crate::asm::IOpName, rhs: Self) -> Self {
        // Allocate output variable
        let backend = {
            // NB: use extra scop to take care of mutex lifetime
            let inner = self.inner.lock().unwrap();
            inner.backend.clone()
        };
        let dst = Self::new_on(backend, self.width);

        Self::iop_ct_raw(name, &dst, &self, &rhs);
        dst
    }

    /// This function format and push associated work in cmd_api
    /// IOp format is Ct <- Ct x Ct
    /// IOp width is inferred from operand width
    /// Dest operand is first src operand
    pub fn iop_ct_assign(&mut self, name: crate::asm::IOpName, rhs: Self) {
        Self::iop_ct_raw(name, &self, &self, &rhs);
    }

    /// This function format and push associated work in dst cmd_api
    /// IOp format is Ct <- Ct x Imm
    /// IOp width is inferred from operand width
    #[inline(always)]
    fn iop_imm_raw(name: crate::asm::IOpName, dst: &Self, rhs_0: &Self, rhs_1: usize) {
        let hpu_op = cmd::HpuCmd::new_ct_imm(name, dst.clone(), rhs_0.clone(), rhs_1);
        dst.inner
            .lock()
            .unwrap()
            .cmd_api
            .send(hpu_op.into())
            .expect("Issue with cmd_api");
    }

    /// This function format and push associated work in dst cmd_api
    /// IOp format is Ct <- Ct x Imm
    /// IOp width is inferred from operand width
    /// Dst operand is allocated
    pub fn iop_imm(self, name: crate::asm::IOpName, rhs: usize) -> Self {
        // Allocate output variable
        let backend = {
            // NB: use extra scop to take care of mutex lifetime
            let inner = self.inner.lock().unwrap();
            inner.backend.clone()
        };
        let dst = Self::new_on(backend, self.width);

        Self::iop_imm_raw(name, &dst, &self, rhs);
        dst
    }

    /// This function format and push associated work in dst cmd_api
    /// IOp format is Ct <- Ct x Imm
    /// IOp width is inferred from operand width
    /// Dest operand is first src operand
    pub fn iop_imm_assign(&mut self, name: crate::asm::IOpName, rhs: usize) {
        Self::iop_imm_raw(name, &self, &self, rhs);
    }
}

/// Utility macro to define new Operation implementation
/// Operation are defined as raw (dst, src, src) to easly map x, x_assign function on it
#[macro_export]
macro_rules! impl_ct_ct_raw {
    ($hpu_op: literal) => {
        ::paste::paste! {

            impl HpuVarWrapped
                where Self: Clone,
                    cmd::HpuCmd: From<cmd::HpuCmd>,
            {
                /// This function format and push associated work in dst cmd_api
                fn [<$hpu_op:lower _raw>](dst: &Self, rhs_0: &Self, rhs_1: &Self) {
                    Self::iop_ct_raw(crate::asm::IOpName::[<$hpu_op:upper>],dst, rhs_0, rhs_1)
                }
            }
        }
    };
}

#[macro_export]
/// Easily map an Hpu operation to std::ops rust trait
macro_rules! map_ct_ct {
    ($hpu_op: literal -> $rust_op: literal) => {
        ::paste::paste! {
            impl std::ops::[<$rust_op:camel>] for HpuVarWrapped{
                type Output = HpuVarWrapped;

                fn [<$rust_op:lower>](self, rhs: Self) -> Self::Output {
                    // Allocate output variable
                    let backend = {
                        // NB: use extra scop to take care of mutex lifetime
                        let inner = self.inner.lock().unwrap();
                        inner.backend.clone()
                    };
                    let dst = Self::new_on(backend, self.width);

                    Self::[<$hpu_op:lower _raw>](&dst, &self, &rhs);
                    dst
                }
            }

            impl<'a> std::ops::[<$rust_op:camel>] for &'a HpuVarWrapped{
                type Output = HpuVarWrapped;

                fn [<$rust_op:lower>](self, rhs: Self) -> Self::Output {
                    // Allocate output variable
                    let backend = {
                        // NB: use extra scop to take care of mutex lifetime
                        let inner = self.inner.lock().unwrap();
                        inner.backend.clone()
                    };
                    let dst = HpuVarWrapped::new_on(backend, self.width);

                    HpuVarWrapped::[<$hpu_op:lower _raw>](&dst, self, rhs);
                    dst
                }
            }


            impl std::ops::[<$rust_op:camel Assign>] for HpuVarWrapped{
                fn [<$rust_op:lower _assign>](&mut self, rhs: Self) {
                    Self::[<$hpu_op:lower _raw>](&self, &self, &rhs);
                }
            }

            impl<'a> std::ops::[<$rust_op:camel Assign>]<&'a Self> for HpuVarWrapped{
                fn [<$rust_op:lower _assign>](&mut self, rhs: &'a Self) {
                    HpuVarWrapped::[<$hpu_op:lower _raw>](&self, &self, rhs);
                }
            }
        }
    };
}
impl_ct_ct_raw!("ADD");
map_ct_ct!("ADD" -> "Add");

impl_ct_ct_raw!("SUB");
map_ct_ct!("SUB" -> "Sub");

impl_ct_ct_raw!("MUL");
map_ct_ct!("MUL" -> "Mul");

impl_ct_ct_raw!("BW_AND");
map_ct_ct!("BW_AND" -> "BitAnd");

impl_ct_ct_raw!("BW_OR");
map_ct_ct!("BW_OR" -> "BitOr");

impl_ct_ct_raw!("BW_XOR");
map_ct_ct!("BW_XOR" -> "BitXor");

#[macro_export]
/// Operation are defined as raw (dst, src, imm) to easly map x, x_assign function on it
macro_rules! impl_ct_imm_raw {
    ( $hpu_op: literal) => {
        ::paste::paste! {

            impl HpuVarWrapped
            where Self: Clone,
                cmd::HpuCmd: From<cmd::HpuCmd>,
            {
                /// This function format and push associated work in dst cmd_api
                fn [<$hpu_op:lower _raw>](dst: &Self, rhs_0: &Self, rhs_1: usize) {
                    Self::iop_imm_raw(crate::asm::IOpName::[<$hpu_op:upper>], dst, rhs_0, rhs_1);
                }
            }
        }
    };
}

#[macro_export]
/// Easily map an Hpu operation to std::ops rust trait
/// NB: ct_imm have two variants `ct,imm` and `imm,ct`
macro_rules! map_ct_imm {
    ($hpu_op: literal -> $rust_op: literal) => {
        ::paste::paste! {

            impl std::ops::[<$rust_op:camel>]<usize> for HpuVarWrapped{
                type Output = HpuVarWrapped;

                fn [<$rust_op:lower>](self, rhs: usize) -> Self::Output {
                    // Allocate output variable
                    let backend = {
                        // NB: use extra scop to take care of mutex lifetime
                        let inner = self.inner.lock().unwrap();
                        inner.backend.clone()
                    };
                    let dst = Self::new_on(backend, self.width);

                    Self::[<$hpu_op:lower _raw>](&dst, &self, rhs);
                    dst
                }
            }

            impl std::ops::[<$rust_op:camel Assign>]<usize> for HpuVarWrapped{
                fn [<$rust_op:lower _assign>](&mut self, rhs: usize) {
                    Self::[<$hpu_op:lower _raw>](&self, &self, rhs);
                }
            }
        }
    };
}

macro_rules! map_imm_ct {
    ( $hpu_op: literal -> $rust_op: literal) => {
        ::paste::paste! {
            impl std::ops::[<$rust_op:camel>]<HpuVarWrapped> for usize {
                type Output = HpuVarWrapped;

                fn [<$rust_op:lower>](self, rhs: HpuVarWrapped) -> Self::Output {
                    // Allocate output variable
                    let backend = {
                        // NB: use extra scop to take care of mutex lifetime
                        let inner = rhs.inner.lock().unwrap();
                        inner.backend.clone()
                    };
                    let dst = HpuVarWrapped::new_on(backend, rhs.width);

                    HpuVarWrapped::[<$hpu_op:lower _raw>](&dst, &rhs, self);
                    dst
                }
            }
        }
    };
}

impl_ct_imm_raw!("ADDS");
map_ct_imm!("ADDS" -> "Add");
map_imm_ct!("ADDS" -> "Add");

impl_ct_imm_raw!("SUBS");
map_ct_imm!("SUBS" -> "Sub");
impl_ct_imm_raw!("SSUB");
map_imm_ct!("SSUB" -> "Sub");

impl_ct_imm_raw!("MULS");
map_ct_imm!("MULS" -> "Mul");
map_imm_ct!("MULS" -> "Mul");

// TODO Handle CMP operation
// Couldn't be maped to std::ops trait due to return type != bool
// -> Check the approach taken by tfhe-rs and follow it

// Implement custom operation
// Custom operation couldn't be map on a trait instead use function
// Keep two steps approach:
// 1. Behavior expressed in a `_raw` function
// 2. std function/ assign function impl based on `_raw` one

#[macro_export]
/// Easily map custom Hpu operation on variables
macro_rules! cust_map_ct_ct {
    ($hpu_op: literal) => {
        ::paste::paste! {

            impl HpuVarWrapped{
                pub fn [<$hpu_op:lower>](self, rhs: Self) -> HpuVarWrapped {
                    // Allocate output variable
                    let backend = {
                        // NB: use extra scop to take care of mutex lifetime
                        let inner = self.inner.lock().unwrap();
                        inner.backend.clone()
                    };
                    let dst = Self::new_on(backend, self.width);

                    Self::[<$hpu_op:lower _raw>](&dst, &self, &rhs);
                    dst
                }

                pub fn [<$hpu_op:lower _assign>](&mut self, rhs: Self) {
                    Self::[<$hpu_op:lower _raw>](&self, &self, &rhs);
                }
            }
        }
    };
}

impl_ct_ct_raw!("CUST_0");
cust_map_ct_ct!("CUST_0");
impl_ct_ct_raw!("CUST_1");
cust_map_ct_ct!("CUST_1");
impl_ct_ct_raw!("CUST_2");
cust_map_ct_ct!("CUST_2");
impl_ct_ct_raw!("CUST_3");
cust_map_ct_ct!("CUST_3");
impl_ct_ct_raw!("CUST_4");
cust_map_ct_ct!("CUST_4");
impl_ct_ct_raw!("CUST_5");
cust_map_ct_ct!("CUST_5");
impl_ct_ct_raw!("CUST_6");
cust_map_ct_ct!("CUST_6");
impl_ct_ct_raw!("CUST_7");
cust_map_ct_ct!("CUST_7");
impl_ct_ct_raw!("CUST_8");
cust_map_ct_ct!("CUST_8");
impl_ct_ct_raw!("CUST_9");
cust_map_ct_ct!("CUST_9");
impl_ct_ct_raw!("CUST_A");
cust_map_ct_ct!("CUST_A");
impl_ct_ct_raw!("CUST_B");
cust_map_ct_ct!("CUST_B");
impl_ct_ct_raw!("CUST_C");
cust_map_ct_ct!("CUST_C");
impl_ct_ct_raw!("CUST_D");
cust_map_ct_ct!("CUST_D");
impl_ct_ct_raw!("CUST_E");
cust_map_ct_ct!("CUST_E");
impl_ct_ct_raw!("CUST_F");
cust_map_ct_ct!("CUST_F");

macro_rules! cust_map_ct_imm {
    ( $hpu_op: literal) => {
        ::paste::paste! {
            impl HpuVarWrapped{
                pub fn [<$hpu_op:lower>](self, rhs: usize) -> HpuVarWrapped {
                    // Allocate output variable
                    let backend = {
                        // NB: use extra scop to take care of mutex lifetime
                        let inner = self.inner.lock().unwrap();
                        inner.backend.clone()
                    };
                    let dst = Self::new_on(backend, self.width);

                    Self::[<$hpu_op:lower _raw>](&dst, &self, rhs);
                    dst
                }

                pub fn [<$hpu_op:lower _assign>](&mut self, rhs: usize) {
                        Self::[<$hpu_op:lower _raw>](&self, &self, rhs);
                    }
            }
        }
    };
}
impl_ct_imm_raw!("CUSTI_0");
cust_map_ct_imm!("CUSTI_0");
impl_ct_imm_raw!("CUSTI_1");
cust_map_ct_imm!("CUSTI_1");
impl_ct_imm_raw!("CUSTI_2");
cust_map_ct_imm!("CUSTI_2");
impl_ct_imm_raw!("CUSTI_3");
cust_map_ct_imm!("CUSTI_3");
impl_ct_imm_raw!("CUSTI_4");
cust_map_ct_imm!("CUSTI_4");
impl_ct_imm_raw!("CUSTI_5");
cust_map_ct_imm!("CUSTI_5");
impl_ct_imm_raw!("CUSTI_6");
cust_map_ct_imm!("CUSTI_6");
impl_ct_imm_raw!("CUSTI_7");
cust_map_ct_imm!("CUSTI_7");
impl_ct_imm_raw!("CUSTI_8");
cust_map_ct_imm!("CUSTI_8");
impl_ct_imm_raw!("CUSTI_9");
cust_map_ct_imm!("CUSTI_9");
impl_ct_imm_raw!("CUSTI_A");
cust_map_ct_imm!("CUSTI_A");
impl_ct_imm_raw!("CUSTI_B");
cust_map_ct_imm!("CUSTI_B");
impl_ct_imm_raw!("CUSTI_C");
cust_map_ct_imm!("CUSTI_C");
impl_ct_imm_raw!("CUSTI_D");
cust_map_ct_imm!("CUSTI_D");
impl_ct_imm_raw!("CUSTI_E");
cust_map_ct_imm!("CUSTI_E");
impl_ct_imm_raw!("CUSTI_F");
cust_map_ct_imm!("CUSTI_F");
