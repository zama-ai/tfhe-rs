//!
//! A firmware abstraction layer in which the operation dependencies are
//! represented in a non acyclical graph. The resulting graph can then be used
//! to dump a series of instructions that maximize the target resources.

pub mod config;
mod macros;

use super::isc_sim;
use super::isc_sim::report::PeStoreRpt;
use super::isc_sim::{InstructionKind, PeFlush, PeStore};
use super::metavar::{MetaVarCell, PosKind, RegLockPtr, VarPos};
use super::program::{AtomicRegType, Program, StmtLink};
use crate::asm::{ImmId, Pbs, PbsLut};
use crate::rtl_op;
use bitflags::bitflags;
use config::{FlushBehaviour, OpCfg};
use enum_dispatch::enum_dispatch;
use std::cell::{Ref, RefCell, RefMut};
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::fmt;
use std::fmt::Debug;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use strum_macros::{Display, EnumDiscriminants, EnumString};
use tracing::{debug, instrument, trace};

static COUNTER: AtomicUsize = AtomicUsize::new(1);
fn new_uid() -> usize {
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[derive(Clone, Debug, Default)]
pub struct LoadStats {
    depth: usize,
}

// Encodes an operation priority when scheduling
// Order first by depth, then by most registers, then by uid
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Prio {
    latency_tier: usize,
    depth: usize,
    reg_balance: usize,
    uid: usize,
}

impl From<&OperationCell> for Prio {
    fn from(value: &OperationCell) -> Self {
        let value = value.borrow();
        let stats = value.load_stats().clone().unwrap_or_default();
        Prio {
            latency_tier: value.latency_tier(),
            depth: stats.depth,
            uid: *value.uid(),
            reg_balance: value.src().len(),
        }
    }
}

#[derive(Clone)]
pub struct Var {
    driver: Option<(OperationCell, usize)>,
    loads: HashSet<OperationCell>,
    meta: Option<MetaVarCell>,
    load_stats: Option<LoadStats>,
    uid: usize,
}

impl Var {
    pub fn clone_on(&self, prog: &Program) -> Var {
        Var {
            driver: self.driver.as_ref().map(|(d, i)| (d.clone_on(prog), *i)),
            loads: HashSet::new(),
            meta: self.meta.as_ref().map(|m| m.clone_on(prog)),
            load_stats: self.load_stats.clone(),
            ..*self
        }
    }
}

impl std::ops::Drop for Var {
    fn drop(&mut self) {
        trace!("Var Dropped: {:?}", &self);
    }
}

impl std::cmp::PartialEq for Var {
    fn eq(&self, other: &Var) -> bool {
        self.uid == other.uid
    }
}

impl std::cmp::Eq for Var {}

impl std::hash::Hash for Var {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.uid.hash(state);
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct VarCell(Rc<RefCell<Var>>);

impl VarCell {
    // Purposely not public
    fn borrow_mut(&self) -> RefMut<'_, Var> {
        self.0.borrow_mut()
    }
    fn borrow(&self) -> Ref<'_, Var> {
        self.0.borrow()
    }

    pub fn clone_on(&self, prog: &Program) -> Self {
        self.borrow().clone_on(prog).into()
    }

    pub fn copy_uid(&self) -> usize {
        self.borrow().uid
    }

    pub fn copy_meta(&self) -> Option<MetaVarCell> {
        self.0.borrow().meta.clone()
    }

    pub fn copy_driver(&self) -> Option<(OperationCell, usize)> {
        self.borrow().driver.clone()
    }

    pub fn copy_loads(&self) -> Vec<OperationCell> {
        self.borrow().loads.iter().cloned().collect()
    }

    // If a variable's driver was removed, it is scheduled
    pub fn is_ready(&self) -> bool {
        !self.has_driver()
    }

    pub fn has_driver(&self) -> bool {
        self.0.borrow().driver.is_some()
    }

    pub fn has_meta(&self) -> bool {
        self.0.borrow().meta.is_some()
    }

    pub fn set_driver(&self, op: Option<(OperationCell, usize)>) {
        self.0.borrow_mut().driver = op;
    }

    // The key is not mutable since OperationCell implements an immutable hash
    #[allow(clippy::mutable_key_type)]
    pub fn set_loads(&self, loads: HashSet<OperationCell>) {
        self.0.borrow_mut().loads = loads;
    }

    pub fn set_load_stats(&self, load_stats: LoadStats) -> LoadStats {
        self.borrow_mut().load_stats = Some(load_stats.clone());
        load_stats
    }

    pub fn set_meta(&self, var: MetaVarCell) {
        self.0.borrow_mut().meta = Some(var);
    }

    pub fn add_load(&self, op: &OperationCell) {
        self.0.borrow_mut().loads.insert(op.clone());
    }

    pub fn clear_driver(&self) {
        self.0.borrow_mut().driver = None;
    }

    pub fn remove_load(&self, load: &OperationCell) {
        self.0.borrow_mut().loads.remove(load);
    }

    pub fn copy_load_stats(&self) -> LoadStats {
        let load_stats = self.borrow().load_stats.clone();
        load_stats.unwrap_or_else(|| self.set_load_stats(self.compute_load_stats()))
    }

    //The load of a variable is the number of variables depending on it
    //(excluding itself).
    pub fn compute_load_stats(&self) -> LoadStats {
        LoadStats {
            depth: self
                .copy_loads()
                .into_iter()
                .map(|d| d.copy_load_stats().depth)
                .max()
                .unwrap_or(0),
        }
    }

    // Adds references from root to leaf, recursively
    pub fn load(&self) {
        if let Some((d, i)) = self.copy_driver() {
            if d.borrow().dst()[i].is_none() {
                d.set_dst(i, self);
                d.load();
            }
        }
    }

    pub fn new() -> VarCell {
        VarCell(Rc::new(RefCell::new(Var {
            driver: None,
            loads: HashSet::new(),
            meta: None,
            uid: new_uid(),
            load_stats: None,
        })))
    }

    pub fn pbs(&self, lut: &Pbs) -> Vec<VarCell> {
        let var: Vec<_> = (0..lut.lut_nb()).map(|_| VarCell::new()).collect();
        let new_op = PbsOp::new_op(var.as_slice(), lut, self);
        var.iter()
            .enumerate()
            .for_each(|(i, v)| v.set_driver(Some((new_op.clone(), i))));
        var
    }

    pub fn single_pbs(&self, lut: &Pbs) -> VarCell {
        self.pbs(lut).into_iter().next().unwrap()
    }

    pub fn mac(&self, cnst: usize, coeff: &VarCell) -> VarCell {
        let var = VarCell::new();
        let new_op = MacOp::new_op(cnst, coeff, self);
        var.set_driver(Some((new_op.clone(), 0)));
        var
    }

    pub fn from_vec(v: Vec<MetaVarCell>) -> Vec<VarCell> {
        v.into_iter().map(VarCell::from).collect()
    }
}

impl Default for VarCell {
    fn default() -> Self {
        Self::new()
    }
}

impl From<MetaVarCell> for VarCell {
    fn from(meta: MetaVarCell) -> VarCell {
        let var = VarCell::new();
        var.set_meta(meta);
        var
    }
}

impl From<&MetaVarCell> for VarCell {
    fn from(meta: &MetaVarCell) -> VarCell {
        let var = VarCell::new();
        var.set_meta(meta.clone());
        var
    }
}

impl From<Var> for VarCell {
    fn from(var: Var) -> VarCell {
        VarCell(Rc::new(RefCell::new(var)))
    }
}

impl std::hash::Hash for VarCell {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.borrow().hash(state)
    }
}

#[enum_dispatch(Operation)]
trait OperationTrait
where
    Self: Sized + Debug + std::hash::Hash,
{
    fn dst(&self) -> &Vec<Option<VarCell>>;
    fn dst_mut(&mut self) -> &mut Vec<Option<VarCell>>;
    fn src(&self) -> &Vec<VarCell>;
    fn uid(&self) -> &usize;
    fn load_stats(&self) -> &Option<LoadStats>;
    fn load_stats_mut(&mut self) -> &mut Option<LoadStats>;
    fn clear_src(&mut self);
    fn clear_dst(&mut self);
    fn kind(&self) -> InstructionKind;
    fn clone_on(&self, prog: &Program) -> Operation;
    // {{{1 Debug
    // -----------------------------------------------------------------------
    #[cfg(feature = "rtl_graph")]
    fn name(&self) -> &str;
    // }}}
}

#[enum_dispatch(Operation)]
trait ToFlush
where
    Self: Sized + Debug + std::hash::Hash,
{
    fn to_flush(&mut self) {}
}

#[enum_dispatch(Operation)]
trait ProgManager
where
    Self: Sized + Debug + std::hash::Hash + OperationTrait,
{
    // Analyzes the current program state to know if this operation can be added
    // The blanket implementation handles the typical case where an operation
    // has many sources and only a single destination
    fn peek_prog(&self, prog: &mut Program) -> bool {
        if self.dst()[0].is_some() {
            let mut range: Vec<_> = self
                .src()
                .iter()
                .map(|src| {
                    let meta = src.copy_meta().unwrap();
                    match meta.get_pos() {
                        PosKind::REG => AtomicRegType::Existing(meta.as_reg().unwrap()),
                        PosKind::IMM => match meta.as_imm().unwrap() {
                            ImmId::Cst(_) => AtomicRegType::None,
                            ImmId::Var { .. } => AtomicRegType::NewRange(1),
                        },
                        PosKind::PBS => AtomicRegType::None,
                        PosKind::MEM => AtomicRegType::NewRange(1),
                        PosKind::EMPTY => AtomicRegType::NewRange(1),
                        // EMPTY variables are a specially case for
                        // operations that result in a constant
                        // independently on the variable value itself, such
                        // as a-a
                        _ => panic!("Unexpected metavar position"),
                    }
                })
                .collect();

            if range.iter().any(|rng| !matches!(*rng, AtomicRegType::None)) {
                range.push(AtomicRegType::NewRange(1));
            }

            prog.atomic_reg_range(range.as_slice()).is_some()
        } else {
            // This operation is not needed, just say yes
            true
        }
    }

    // This blanket implementation handles the typical case where an operation
    // has two sources and only a single destination
    fn alloc1_prog(&mut self, prog: &mut Program) -> OpLock1 {
        if let Some(dst) = self.dst()[0].as_ref() {
            let mut a = self.src()[0].copy_meta().unwrap();
            let mut b = self.src()[1].copy_meta().unwrap();
            let mut d = prog.new_var();
            dst.set_meta(d.clone());

            let alock = {
                a.reg_alloc_mv();
                a.reg_lock()
            };
            let block = {
                b.reg_alloc_mv();
                b.reg_lock()
            };

            assert!((a.is_in(PosKind::REG) || a.is_cst()) && (b.is_in(PosKind::REG) || b.is_cst()));

            if !(a.is_cst() && b.is_cst()) {
                d.reg_alloc_mv();
            }

            OpLock1 {
                rd_lock: Some(vec![alock, block]),
                wr_lock: Some(d.reg_lock()),
            }
        } else {
            OpLock1::default()
        }
    }

    // Allocates program resources for this operation, including locking the
    // necessary registers to itself and moving metavariables to registers
    fn alloc_prog(&mut self, prog: &mut Program);
    // Adds the operation to the program. All resources keep locked
    fn add_prog(&mut self, prog: &mut Program);
    // Free read resources
    fn free_rd(&mut self);
    // Free write resources
    fn free_wr(&mut self);
}

// Not every DOP is implemented, add more if you need more

#[derive(Clone, Debug, Default)]
struct OpLock1 {
    rd_lock: Option<Vec<RegLockPtr>>,
    wr_lock: Option<RegLockPtr>,
}

#[derive(Clone, Debug, Default)]
struct AddsData {
    cnst: usize,
    rd_lock: Option<Vec<RegLockPtr>>,
    wr_lock: Option<RegLockPtr>,
}

#[derive(Clone, Debug, Default)]
struct MacData {
    lock: OpLock1,
    mult: usize,
}

#[derive(Clone, Debug)]
struct PbsData {
    lut: Pbs,
    rd_lock: Option<RegLockPtr>,
    wr_lock: Option<Vec<RegLockPtr>>,
    stmt_link: Option<StmtLink>,
}

rtl_op!("ADDS", Arith, AddsData);
rtl_op!("ADD", Arith, OpLock1);
rtl_op!("SUB", Arith, OpLock1);
rtl_op!("SUBS", Arith, AddsData);
rtl_op!("MAC", Arith, MacData);
rtl_op!("MULS", Arith, MacData);
rtl_op!("PBS", Pbs, PbsData);
rtl_op!("ST", MemSt, Option<RegLockPtr>);

impl ProgManager for AddsOp {
    fn alloc_prog(&mut self, prog: &mut Program) {
        self.data = if let Some(dst) = self.dst()[0].as_ref() {
            let mut a = self.src()[0].copy_meta().unwrap();
            let mut d = prog.new_var();
            dst.set_meta(d.clone());

            let alock = {
                a.reg_alloc_mv();
                a.reg_lock()
            };
            if !a.is_cst() {
                d.reg_alloc_mv();
            }

            AddsData {
                cnst: self.data.cnst,
                rd_lock: Some(vec![alock]),
                wr_lock: Some(d.reg_lock()),
            }
        } else {
            AddsData::default()
        }
    }

    fn add_prog(&mut self, prog: &mut Program) {
        if let Some(d) = self.dst[0].as_ref() {
            let a = self.src[0].copy_meta().unwrap();
            let b = prog.new_imm(self.data.cnst);
            let d = d.copy_meta().unwrap();
            d.add_raw(&a, &b, false);
        }
    }

    fn free_rd(&mut self) {
        self.data.rd_lock = None;
    }

    fn free_wr(&mut self) {
        self.data.wr_lock = None;
    }
}

impl ProgManager for SubsOp {
    fn alloc_prog(&mut self, prog: &mut Program) {
        self.data = if let Some(dst) = self.dst()[0].as_ref() {
            let mut a = self.src()[0].copy_meta().unwrap();
            let mut d = prog.new_var();
            dst.set_meta(d.clone());

            let alock = {
                a.reg_alloc_mv();
                a.reg_lock()
            };
            if !a.is_cst() {
                d.reg_alloc_mv();
            }

            AddsData {
                cnst: self.data.cnst,
                rd_lock: Some(vec![alock]),
                wr_lock: Some(d.reg_lock()),
            }
        } else {
            AddsData::default()
        }
    }

    fn add_prog(&mut self, prog: &mut Program) {
        if let Some(d) = self.dst[0].as_ref() {
            let a = self.src[0].copy_meta().unwrap();
            let b = prog.new_imm(self.data.cnst);
            let d = d.copy_meta().unwrap();
            d.sub_raw(&a, &b, false);
        }
    }

    fn free_rd(&mut self) {
        self.data.rd_lock = None;
    }

    fn free_wr(&mut self) {
        self.data.wr_lock = None;
    }
}

impl ProgManager for AddOp {
    fn alloc_prog(&mut self, prog: &mut Program) {
        self.data = self.alloc1_prog(prog)
    }

    fn add_prog(&mut self, _: &mut Program) {
        if let Some(d) = self.dst[0].as_ref() {
            let a = self.src[0].copy_meta().unwrap();
            let b = self.src[1].copy_meta().unwrap();
            let d = d.copy_meta().unwrap();
            d.add_raw(&a, &b, false);
        }
    }

    fn free_rd(&mut self) {
        self.data.rd_lock = None;
    }

    fn free_wr(&mut self) {
        self.data.wr_lock = None;
    }
}

impl ProgManager for SubOp {
    fn alloc_prog(&mut self, prog: &mut Program) {
        self.data = self.alloc1_prog(prog)
    }

    fn add_prog(&mut self, _: &mut Program) {
        if let Some(d) = self.dst[0].as_ref() {
            let a = self.src[0].copy_meta().unwrap();
            let b = self.src[1].copy_meta().unwrap();
            let d = d.copy_meta().unwrap();
            d.sub_raw(&a, &b, false);
        }
    }

    fn free_rd(&mut self) {
        self.data.rd_lock = None;
    }

    fn free_wr(&mut self) {
        self.data.wr_lock = None;
    }
}

impl ProgManager for MacOp {
    fn alloc_prog(&mut self, prog: &mut Program) {
        self.data.lock = self.alloc1_prog(prog)
    }

    fn add_prog(&mut self, _: &mut Program) {
        if let Some(d) = self.dst[0].as_ref() {
            let a = self.src[0].copy_meta().unwrap();
            let b = self.src[1].copy_meta().unwrap();
            let d = d.copy_meta().unwrap();
            d.mac_raw(&a, self.data.mult as u8, &b);
        }
    }

    fn free_rd(&mut self) {
        self.data.lock.rd_lock = None;
    }

    fn free_wr(&mut self) {
        self.data.lock.wr_lock = None;
    }
}

impl ProgManager for MulsOp {
    fn alloc_prog(&mut self, prog: &mut Program) {
        self.data.lock = if let Some(dst) = self.dst()[0].as_ref() {
            let mut a = self.src()[0].copy_meta().unwrap();
            let mut d = prog.new_var();
            dst.set_meta(d.clone());

            let alock = {
                a.reg_alloc_mv();
                a.reg_lock()
            };

            assert!(a.is_in(PosKind::REG) || a.is_cst());

            if !a.is_cst() {
                d.reg_alloc_mv();
            }

            OpLock1 {
                rd_lock: Some(vec![alock]),
                wr_lock: Some(d.reg_lock()),
            }
        } else {
            OpLock1::default()
        };
    }

    fn add_prog(&mut self, prog: &mut Program) {
        if let Some(d) = self.dst[0].as_ref() {
            let a = self.src[0].copy_meta().unwrap();
            let d = d.copy_meta().unwrap();
            d.mul(&a, &prog.new_imm(self.data.mult));
        }
    }

    fn free_rd(&mut self) {
        self.data.lock.rd_lock = None;
    }

    fn free_wr(&mut self) {
        self.data.lock.wr_lock = None;
    }
}

impl ProgManager for PbsOp {
    fn peek_prog(&self, prog: &mut Program) -> bool {
        // Make sure there's at least one used destination
        assert!(self.dst().iter().any(|d| d.is_some()));

        let mut range: Vec<_> = self
            .src()
            .iter()
            .map(|src| {
                let meta = src.copy_meta().unwrap();
                match meta.get_pos() {
                    PosKind::REG => AtomicRegType::Existing(meta.as_reg().unwrap()),
                    PosKind::MEM => AtomicRegType::NewRange(1),
                    PosKind::EMPTY => panic!("Cannot operate on an empty variable"),
                    _ => panic!("Unexpected metavar position"),
                }
            })
            .collect();
        range.push(AtomicRegType::NewRange(self.dst().len()));

        prog.atomic_reg_range(range.as_slice()).is_some()
    }

    fn alloc_prog(&mut self, prog: &mut Program) {
        let reg_start = prog
            .atomic_reg_range(&[AtomicRegType::NewRange(self.dst.len())])
            .unwrap()[0];

        let d = self
            .dst()
            .iter()
            .enumerate()
            .map(|(i, d)| {
                let meta = prog.new_var();
                meta.force_reg_alloc(reg_start + i);
                d.as_ref().inspect(|d| d.set_meta(meta.clone()));
                meta
            })
            .collect::<Vec<_>>();

        self.data.wr_lock = Some(d.into_iter().map(|mut d| d.reg_lock()).collect());
        // Assume at least one destination is needed
        let mut a = self.src()[0].copy_meta().unwrap();
        a.reg_alloc_mv();

        assert!(
            a.is_in(PosKind::REG),
            "Cannot do a PBS from something other than a register"
        );
        self.data.rd_lock = Some(a.reg_lock());
    }

    fn add_prog(&mut self, prog: &mut Program) {
        let pbs = prog.var_from(Some(VarPos::Pbs(self.data.lut.clone())));
        let tfhe_params = prog.params().clone().into();
        let src = self.src[0].copy_meta().unwrap();
        let dst = self
            .data
            .wr_lock
            .as_ref()
            .unwrap()
            .iter()
            .map(MetaVarCell::from)
            .collect::<Vec<_>>();

        self.data.stmt_link = Some(MetaVarCell::pbs_raw(
            &dst.iter().collect::<Vec<_>>(),
            &src,
            &pbs,
            false,
            &tfhe_params,
        ));
    }

    fn free_rd(&mut self) {
        self.data.rd_lock = None;
    }

    fn free_wr(&mut self) {
        self.data.wr_lock = None;
    }
}

impl ProgManager for StOp {
    fn peek_prog(&self, prog: &mut Program) -> bool {
        // If this is not needed or there's no meta to go to, it's definitely
        // possible to add this operation to the program
        if self.dst[0].is_none() || !self.dst[0].as_ref().unwrap().has_meta() {
            return true;
        }

        let meta = self.src[0].copy_meta().unwrap();
        let range = [match meta.get_pos() {
            PosKind::REG => AtomicRegType::Existing(meta.as_reg().unwrap()),
            PosKind::MEM => AtomicRegType::NewRange(1),
            PosKind::EMPTY => panic!("Cannot operate on an empty variable"),
            _ => panic!("Unexpected metavar position"),
        }];
        prog.atomic_reg_range(&range).is_some()
    }

    fn alloc_prog(&mut self, _: &mut Program) {
        // There's no need to allocate anything if there's no destination or the
        // destination has no meta yet, in which case we can simply copy the
        // source meta to it
        if self.dst[0].is_some() && self.dst[0].as_ref().unwrap().has_meta() {
            let mut a = self.src()[0].copy_meta().unwrap();
            a.reg_alloc_mv();
            assert!(
                a.is_in(PosKind::REG),
                "Cannot move to a destination from a location other than a register"
            );
            self.data = Some(a.reg_lock());
        }
    }

    fn add_prog(&mut self, _: &mut Program) {
        let rhs = self.src[0].copy_meta().unwrap();
        if let Some(dst) = self.dst[0].as_ref() {
            if let Some(mut lhs) = dst.copy_meta() {
                lhs <<= rhs.clone();
            } else {
                dst.set_meta(rhs.clone());
            }
        }
    }

    fn free_rd(&mut self) {
        self.data = None;
    }

    fn free_wr(&mut self) {}
}

impl AddsOp {
    fn new_op(var: &VarCell, cnst: usize) -> OperationCell {
        let op = AddsOp {
            src: vec![var.clone()],
            dst: vec![None],
            uid: new_uid(),
            load_stats: None,
            data: AddsData {
                cnst,
                rd_lock: None,
                wr_lock: None,
            },
        };
        OperationCell(Rc::new(RefCell::new(Operation::ADDS(op))))
    }
}

impl SubsOp {
    fn new_op(var: &VarCell, cnst: usize) -> OperationCell {
        let op = SubsOp {
            src: vec![var.clone()],
            dst: vec![None],
            uid: new_uid(),
            load_stats: None,
            data: AddsData {
                cnst,
                rd_lock: None,
                wr_lock: None,
            },
        };
        OperationCell(Rc::new(RefCell::new(Operation::SUBS(op))))
    }
}

impl AddOp {
    fn new_op(lhs: &VarCell, rhs: &VarCell) -> OperationCell {
        let op = AddOp {
            src: vec![lhs.clone(), rhs.clone()],
            dst: vec![None],
            uid: new_uid(),
            load_stats: None,
            data: OpLock1::default(),
        };
        OperationCell(Rc::new(RefCell::new(Operation::ADD(op))))
    }
}

impl SubOp {
    fn new_op(lhs: &VarCell, rhs: &VarCell) -> OperationCell {
        let op = SubOp {
            src: vec![lhs.clone(), rhs.clone()],
            dst: vec![None],
            uid: new_uid(),
            load_stats: None,
            data: OpLock1::default(),
        };
        OperationCell(Rc::new(RefCell::new(Operation::SUB(op))))
    }
}

impl MacOp {
    fn new_op(mult: usize, coeff: &VarCell, acc: &VarCell) -> OperationCell {
        let op = MacOp {
            src: vec![coeff.clone(), acc.clone()],
            dst: vec![None],
            uid: new_uid(),
            load_stats: None,
            data: MacData {
                mult,
                lock: OpLock1::default(),
            },
        };
        OperationCell(Rc::new(RefCell::new(Operation::MAC(op))))
    }
}

impl MulsOp {
    fn new_op(var: &VarCell, mult: usize) -> OperationCell {
        let op = MulsOp {
            src: vec![var.clone()],
            dst: vec![None],
            uid: new_uid(),
            load_stats: None,
            data: MacData {
                mult,
                lock: OpLock1::default(),
            },
        };
        OperationCell(Rc::new(RefCell::new(Operation::MULS(op))))
    }
}

impl PbsOp {
    fn new_op(dst: &[VarCell], lut: &Pbs, lhs: &VarCell) -> OperationCell {
        let op = PbsOp {
            src: vec![lhs.clone()],
            dst: dst.iter().map(|_| None).collect(),
            data: PbsData {
                lut: lut.clone(),
                rd_lock: None,
                wr_lock: None,
                stmt_link: None,
            },
            uid: new_uid(),
            load_stats: None,
        };
        OperationCell(Rc::new(RefCell::new(Operation::PBS(op))))
    }
}

impl StOp {
    fn new_op(src: &VarCell) -> OperationCell {
        let op = StOp {
            src: vec![src.clone()],
            dst: vec![None],
            uid: new_uid(),
            load_stats: None,
            data: None,
        };
        OperationCell(Rc::new(RefCell::new(Operation::ST(op))))
    }
}

impl ToFlush for AddsOp {}
impl ToFlush for SubsOp {}
impl ToFlush for AddOp {}
impl ToFlush for SubOp {}
impl ToFlush for MacOp {}
impl ToFlush for MulsOp {}
impl ToFlush for PbsOp {
    fn to_flush(&mut self) {
        if let Some(asm) = &mut self.data.stmt_link {
            asm.to_flush();
        }
    }
}
impl ToFlush for StOp {}

#[enum_dispatch]
#[derive(EnumDiscriminants, Debug, Hash, PartialEq, Eq, Clone)]
#[strum_discriminants(name(OperationNames))]
#[strum_discriminants(derive(EnumString, Display))]
pub enum Operation {
    ADDS(AddsOp),
    SUBS(SubsOp),
    ADD(AddOp),
    SUB(SubOp),
    MAC(MacOp),
    MULS(MulsOp),
    PBS(PbsOp),
    ST(StOp),
}

// Divide the operations into latency tiers to help the scheduler decide the
// best order.
impl Operation {
    pub fn latency_tier(&self) -> usize {
        match self {
            Operation::PBS(_) => 0,
            _ => 1,
        }
    }

    fn is_pbs(&self) -> bool {
        matches!(self, Operation::PBS(_))
    }
}

// All pointers are reference counted pointers in the tree, both drivers and
// loads. This is because the FW when building the tree will hold only end
// variables, while when scheduling we'll hold source variables. While
// scheduling the tree needs to be de-constructed carefully so that it can be
// fully dropped.
#[derive(Clone, Eq, Debug)]
pub struct OperationCell(Rc<RefCell<Operation>>);

impl OperationCell {
    fn borrow(&self) -> Ref<'_, Operation> {
        self.0.borrow()
    }
    fn is_ready(&self) -> bool {
        self.borrow().src().iter().all(|x| x.is_ready())
    }
    fn copy_dst(&self) -> Vec<Option<VarCell>> {
        self.0.borrow().dst().clone()
    }
    fn copy_src(&self) -> Vec<VarCell> {
        self.0.borrow().src().clone()
    }
    fn kind(&self) -> InstructionKind {
        self.0.borrow().kind()
    }
    fn latency_tier(&self) -> usize {
        self.0.borrow().latency_tier()
    }
    fn is_pbs(&self) -> bool {
        self.0.borrow().is_pbs()
    }

    pub fn set_load_stats(&self, stats: LoadStats) -> LoadStats {
        *self.0.borrow_mut().load_stats_mut() = Some(stats.clone());
        stats
    }

    fn set_dst(&self, idx: usize, dst: &VarCell) {
        self.0.borrow_mut().dst_mut()[idx] = Some(dst.clone());
    }

    // Adds references from root to leaf, recursively
    pub fn load(&self) {
        self.copy_src().into_iter().for_each(|v| {
            v.add_load(self);
            v.load();
        });
    }

    // Removes all links from roots to leaves
    fn unload(&self) {
        self.0
            .borrow()
            .src()
            .iter()
            .for_each(|s| s.remove_load(self));
        self.0.borrow_mut().dst_mut().iter_mut().for_each(|s| {
            *s = None;
        });
    }

    // Removes ourselves from the load list of any variable by following the
    // source list and clears the source list
    fn clear_src(&self) {
        self.0
            .borrow()
            .src()
            .iter()
            .for_each(|s| s.remove_load(self));
        self.0.borrow_mut().clear_src()
    }

    // Removes ourselves from the driver pointer of any variable by following the
    // destination list and clears the destination list
    fn clear_dst(&self) {
        self.0
            .borrow()
            .dst()
            .iter()
            .filter(|s| s.is_some())
            .for_each(|s| s.as_ref().unwrap().clear_driver());
        self.0.borrow_mut().clear_dst()
    }

    // The load of an operation is the amount of variables directly and
    // indirectly driven by it. The load of a variable is the number of
    // variables depending on it (excluding itself).
    fn compute_load_stats(&self) -> LoadStats {
        LoadStats {
            depth: self
                .copy_dst()
                .into_iter()
                .flatten()
                .map(|d| d.copy_load_stats().depth + 1)
                .max()
                .unwrap_or(0),
        }
    }

    pub fn copy_load_stats(&self) -> LoadStats {
        let load_stats = self.borrow().load_stats().clone();
        load_stats.unwrap_or_else(|| self.set_load_stats(self.compute_load_stats()))
    }

    // Removes self from all sources and destinations so that the program can
    // evict this variable and returns a list of operations that depends on this
    // one
    // You should drop the OperationCell holding this too after
    fn remove(&self) -> Vec<OperationCell> {
        let loads = self
            .borrow()
            .dst()
            .iter()
            .filter_map(|dst| dst.as_ref().map(|d| d.copy_loads().into_iter()))
            .flatten()
            .collect::<Vec<_>>();

        // Remove and mark this operation as ready
        self.clear_src();
        self.clear_dst();

        loads.into_iter().filter(|op| op.is_ready()).collect()
    }

    fn get_all_ops(&self) -> Vec<OperationCell> {
        let mut ret = vec![self.clone()];
        let mut other: Vec<_> = self
            .borrow()
            .src()
            .iter()
            .filter_map(|s| s.copy_driver())
            .flat_map(|d| d.0.get_all_ops())
            .collect();
        ret.append(&mut other);
        ret
    }

    fn to_flush(&self) {
        self.0.borrow_mut().to_flush()
    }

    fn peek_prog(&self, prog: Option<&mut Program>) -> bool {
        prog.map(|prog| self.0.borrow_mut().peek_prog(prog))
            .unwrap_or(true)
    }

    fn alloc_prog(&mut self, prog: Option<&mut Program>) {
        if let Some(prog) = prog {
            self.0.borrow_mut().alloc_prog(prog);
        }
    }

    fn add_prog(&self, prog: Option<&mut Program>) {
        if let Some(prog) = prog {
            self.0.borrow_mut().add_prog(prog)
        }
    }

    fn free_rd(&mut self) {
        self.0.borrow_mut().free_rd();
    }

    // Free write resources
    fn free_wr(&mut self) {
        self.0.borrow_mut().free_wr();
    }

    fn clone_on(&self, prog: &Program) -> Self {
        self.0.borrow().clone_on(prog).into()
    }

    // {{{1 Debug
    // -----------------------------------------------------------------------
    #[cfg(feature = "rtl_graph")]
    fn copy_uid(&self) -> usize {
        *self.0.borrow().uid()
    }
    #[cfg(feature = "rtl_graph")]
    fn copy_name(&self) -> String {
        String::from(self.borrow().name())
    }
    #[cfg(feature = "rtl_graph")]
    fn get_heads(&self) -> HashSet<OperationCell> {
        let heads: HashSet<_> = self
            .borrow()
            .src()
            .iter()
            .filter_map(|s| s.copy_driver())
            .flat_map(|d| d.0.get_heads())
            .collect();
        if heads.len() > 0 {
            heads
        } else {
            [self.clone()].into_iter().collect()
        }
    }
    // -----------------------------------------------------------------------
    // }}}
}

impl std::hash::Hash for OperationCell {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.borrow().hash(state)
    }
}

impl From<Operation> for OperationCell {
    fn from(value: Operation) -> Self {
        OperationCell(Rc::new(RefCell::new(value)))
    }
}

// These are implemented to order operations in the BinaryHeap of pending
// operations
impl Ord for OperationCell {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        Prio::from(other).cmp(&Prio::from(self))
    }
}

impl PartialOrd for OperationCell {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for OperationCell {
    fn eq(&self, other: &Self) -> bool {
        matches!(self.cmp(other), std::cmp::Ordering::Equal)
    }
}

impl std::ops::Add for &VarCell {
    type Output = VarCell;

    fn add(self, other: &VarCell) -> VarCell {
        let var = VarCell::new();
        let new_op = AddOp::new_op(self, other);
        var.set_driver(Some((new_op.clone(), 0)));
        var
    }
}

impl std::ops::Add<usize> for &VarCell {
    type Output = VarCell;

    fn add(self, other: usize) -> VarCell {
        let var = VarCell::new();
        let new_op = AddsOp::new_op(self, other);
        var.set_driver(Some((new_op.clone(), 0)));
        var
    }
}

impl std::ops::Sub for &VarCell {
    type Output = VarCell;

    fn sub(self, other: &VarCell) -> VarCell {
        let var = VarCell::new();
        let new_op = SubOp::new_op(self, other);
        var.set_driver(Some((new_op.clone(), 0)));
        var
    }
}

impl std::ops::Sub<usize> for &VarCell {
    type Output = VarCell;

    fn sub(self, other: usize) -> VarCell {
        let var = VarCell::new();
        let new_op = SubsOp::new_op(self, other);
        var.set_driver(Some((new_op.clone(), 0)));
        var
    }
}

impl std::ops::Mul<usize> for &VarCell {
    type Output = VarCell;

    fn mul(self, coeff: usize) -> VarCell {
        let var = VarCell::new();
        let new_op = MulsOp::new_op(self, coeff);
        var.set_driver(Some((new_op.clone(), 0)));
        var
    }
}

impl std::ops::ShlAssign<&VarCell> for VarCell {
    fn shl_assign(&mut self, rhs: &VarCell) {
        let new_op = StOp::new_op(rhs);
        self.set_driver(Some((new_op.clone(), 0)));
    }
}

// I was expecting more events to be waited for...
bitflags! {
    #[derive(Clone, Debug)]
    struct WaitEvents: u8 {
        const RdUnlock = 0x1;
    }
}

// Used to emulate the ALU store add instructions to the program and manipulate
// the register file
struct Arch {
    pe_store: PeStore,
    program: Option<Program>,
    cycle: usize,
    events: BinaryHeap<isc_sim::Event>,
    queued: HashMap<usize, VecDeque<OperationCell>>,
    rd_pdg: HashMap<usize, VecDeque<OperationCell>>,
    wr_pdg: HashMap<usize, VecDeque<OperationCell>>,
    use_ipip: bool,
    cfg: OpCfg,
    timeout: Option<usize>,
    waiting_for: WaitEvents,
}

// An interface to the target architecture
// Responsible for simulating the architecture and inserting operations into the
// program
// TODO: The whole Arch could be a trait, so that this whole infrastructure
// could be re-used in other contexts outside our HPU firmware generation
impl Arch {
    // interface
    #[instrument(level = "trace", skip(self, op))]
    pub fn try_dispatch(&mut self, op: BinaryHeap<OperationCell>) -> BinaryHeap<OperationCell> {
        // Postpone scheduling high latency operations until there's no other
        // option to keep everything going. This is very heuristic, so this
        // behavior could be turned off on an iop basis.
        let mut max_tier = if self.cfg.use_tiers {
            self.max_tier().unwrap_or(0)
        } else {
            0
        };

        self.waiting_for = WaitEvents::empty();

        let ret = op
            .into_sorted_vec()
            .into_iter()
            .filter_map(|mut op| {
                if op.latency_tier() >= max_tier {
                    if let Some(id) = {
                        // Shortcut peeking the program if the PE won't
                        // accept our kind. Peeking the program is very
                        // heavy.
                        self.pe_store
                            .avail_kind()
                            .intersects(op.kind())
                            .then_some(true)
                            .and_then(|_| {
                                let prog_ok = op.peek_prog(self.program.as_mut());
                                self.waiting_for.set(WaitEvents::RdUnlock, !prog_ok);
                                prog_ok.then_some(true)
                            })
                            .and_then(|_| self.pe_store.try_push(op.kind(), false))
                    } {
                        max_tier = if self.cfg.use_tiers {
                            max_tier.max(op.latency_tier())
                        } else {
                            0
                        };

                        op.alloc_prog(self.program.as_mut());

                        self.rd_pdg.entry(id).or_default().push_front(op);
                        trace!("rd_pdg: {:?}", self.rd_pdg);

                        None
                    } else {
                        Some(op)
                    }
                } else {
                    Some(op)
                }
            })
            .collect::<BinaryHeap<_>>();

        // Select the flush behavior
        match (self.use_ipip, self.cfg.flush_behaviour) {
            (true, _) | (false, FlushBehaviour::Opportunist) => {
                self.probe_for_exec(Some(PeFlush::Force));
            }
            (false, FlushBehaviour::NoPBS) => {
                let flush = (!ret.iter().any(|i| i.is_pbs())).then_some(PeFlush::Force);
                self.probe_for_exec(flush);
            }
            (false, FlushBehaviour::Patient) => {
                self.probe_for_exec(None);
                let flush = (ret.is_empty() && self.events.is_empty()).then_some(PeFlush::Force);
                self.probe_for_exec(flush);
            }
            (false, FlushBehaviour::Timeout(_)) => {
                self.probe_for_exec(None);
            }
        };

        ret
    }

    pub fn max_tier(&self) -> Option<usize> {
        self.rd_pdg
            .values()
            .chain(self.queued.values())
            .chain(self.wr_pdg.values())
            .flatten()
            .map(|op| op.latency_tier())
            .max()
    }

    #[instrument(level = "trace", skip(self))]
    pub fn done(&mut self) -> Option<OperationCell> {
        if self.events.is_empty() {
            // It can happen that for lack of registers, the PE cannot be
            // filled. In that case, try a forced flush
            self.probe_for_exec(Some(PeFlush::Force));
            assert!(!self.events.is_empty());
        }

        let waiting_for = self.waiting_for.clone();
        let mut waiting = (true, None);

        while let (true, _) = waiting {
            trace!("---------- Processing Loop ------------");
            trace!("Events: {:?}", self.events);
            trace!("rd_pdg: {:?}", self.rd_pdg);
            trace!("queued: {:?}", self.queued);
            trace!("wr_pdg: {:?}", self.wr_pdg);
            trace!("waiting: {:?}", self.waiting_for);
            trace!("---------------------------------------");

            let event = {
                let mut event = self.events.pop();
                if self.timeout.is_some()
                    && self.timeout.unwrap()
                        < event.as_ref().map(|x| x.at_cycle).unwrap_or(usize::MAX)
                {
                    self.probe_for_exec(Some(PeFlush::Timeout));
                    self.timeout = None;
                    if let Some(event) = event {
                        self.events.push(event);
                    }
                    event = self.events.pop();
                }
                event
            };

            waiting = if let Some(isc_sim::Event {
                at_cycle,
                event_type,
            }) = event
            {
                self.cycle = at_cycle;

                match event_type {
                    isc_sim::EventType::RdUnlock(_, id) => {
                        // update associated pe state
                        self.pe_store.rd_unlock(id);
                        self.probe_for_exec(None);

                        let mut op = self.rd_pdg.get_mut(&id).unwrap().pop_back().unwrap();
                        op.add_prog(self.program.as_mut());
                        op.free_rd();
                        self.queued.entry(id).or_default().push_front(op);
                        (!(waiting_for.intersects(WaitEvents::RdUnlock)), None)
                    }
                    isc_sim::EventType::BatchStart { pe_id, issued } => {
                        self.queued.entry(pe_id).and_modify(|fifo| {
                            let mut batch = fifo.split_off(fifo.len() - issued);
                            if self.cfg.flush {
                                batch.front_mut().unwrap().to_flush();
                            }
                            let fifo = self.wr_pdg.entry(pe_id).or_default();
                            batch.into_iter().for_each(|e| fifo.push_front(e));
                        });
                        (true, None)
                    }
                    isc_sim::EventType::WrUnlock(_, id) => {
                        // update associated pe state
                        self.pe_store.wr_unlock(id);
                        self.probe_for_exec(None);

                        let mut op = self.wr_pdg.get_mut(&id).unwrap().pop_back().unwrap();
                        op.free_wr();
                        (false, Some(op))
                    }
                    _ => panic!("Received an unexpected event: {event_type:?}"),
                }
            } else {
                (false, None)
            };
        }
        waiting.1
    }

    pub fn busy(&self) -> bool {
        (!self.events.is_empty())
            || (self.pe_store.pending() != 0)
            || (self.rd_pdg.iter().any(|x| !x.1.is_empty()))
    }

    pub fn cycle(&self) -> usize {
        self.cycle
    }

    fn report_usage(&self) -> PeStoreRpt {
        PeStoreRpt::from(&self.pe_store)
    }

    fn probe_for_exec(&mut self, flush: Option<PeFlush>) {
        self.events.extend(
            self.pe_store
                .probe_for_exec(self.cycle, flush)
                .into_iter()
                .filter(
                    |isc_sim::Event {
                         at_cycle: _,
                         event_type: ev,
                     }| {
                        match (self.cfg.flush_behaviour, ev) {
                            (
                                FlushBehaviour::Timeout(timeout),
                                isc_sim::EventType::ReqTimeout(_, _),
                            ) => {
                                self.timeout = Some(self.cycle + timeout);
                                false
                            }
                            (FlushBehaviour::Timeout(_), isc_sim::EventType::DelTimeout(_, _)) => {
                                self.timeout = None;
                                false
                            }
                            (_, isc_sim::EventType::ReqTimeout(_, _))
                            | (_, isc_sim::EventType::DelTimeout(_, _)) => false,
                            _ => true,
                        }
                    },
                ),
        );
    }
}

impl Arch {
    fn from(program: &Program) -> Self {
        let params = program.params();
        let op_cfg = program.op_cfg();
        let mut pe_store = PeStore::from(params.pe_cfg.clone());

        if op_cfg.min_batch_size {
            pe_store.set_min_batch_limit();
        }

        if !op_cfg.fill_batch_fifo {
            pe_store.set_fifo_to_batch_limit();
        }

        Arch {
            pe_store,
            program: Some(program.clone()),
            cycle: 0,
            use_ipip: params.use_ipip,
            events: BinaryHeap::new(),
            queued: HashMap::new(),
            rd_pdg: HashMap::new(),
            wr_pdg: HashMap::new(),
            cfg: op_cfg,
            timeout: None,
            waiting_for: WaitEvents::empty(),
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct Rtl(Vec<VarCell>);

impl Rtl {
    pub fn iter(&self) -> core::slice::Iter<'_, VarCell> {
        self.0.iter()
    }

    // Adds references from the root to leaf direction recursively
    pub fn load(&mut self) {
        self.iter().for_each(|v| v.load());
    }

    // Remove all loads either to move self into an iterator or to drop the
    // whole tree
    pub fn unload(&mut self) {
        self.iter()
            .filter_map(|v| v.copy_driver())
            .flat_map(|(d, _)| d.get_all_ops().into_iter())
            .for_each(|op| {
                op.unload();
            });
    }

    #[allow(clippy::mutable_key_type)]
    #[instrument(level = "trace")]
    fn find_roots(from: &mut [VarCell]) -> HashSet<OperationCell> {
        let mut not_ready: HashSet<OperationCell> = HashSet::new();
        let mut ready: HashSet<OperationCell> = HashSet::new();
        let mut to_check: VecDeque<OperationCell> = from
            .iter()
            .filter_map(|v| v.copy_driver().map(|(d, _)| d))
            .collect();
        let mut all: HashSet<OperationCell> = HashSet::new();

        while !to_check.is_empty() {
            let op = to_check.pop_front().unwrap();

            if !all.contains(&op) {
                if op.is_ready() {
                    ready.insert(op.clone());
                } else {
                    not_ready.insert(op.clone());
                    to_check.extend(
                        op.copy_src()
                            .into_iter()
                            .flat_map(|v| v.copy_driver().map(|(d, _)| d)),
                    );
                }
                all.insert(op);
            }
        }

        ready.iter().for_each(|op| {
            op.set_load_stats(op.compute_load_stats());
        });

        ready
    }

    #[instrument(level = "trace", skip(self, prog))]
    pub fn raw_add(mut self, prog: &Program) -> (usize, Vec<MetaVarCell>) {
        self.load();

        let mut arch = Arch::from(prog);
        let mut todo: BinaryHeap<_> = Rtl::find_roots(&mut self.0).into_iter().collect();

        self.write_dot(prog, 0);

        debug!(
            "Running simulation for {:?}@{}bits",
            prog.borrow().params.op_name,
            prog.borrow().params.integer_w
        );

        trace!("todo: {:?}", &todo);

        while (!todo.is_empty()) || arch.busy() {
            // Try to dispatch everything that is ready to be done
            todo = arch.try_dispatch(todo);
            trace!("todo: {:?}", &todo);

            if let Some(op) = arch.done() {
                trace!("Removing {:?}", &op);
                let new = op.remove();
                trace!("new ready op {:?}", &new);
                todo.extend(new.into_iter());
                self.write_dot(prog, arch.cycle());
            }
        }

        debug!(
            "arch report for {:?}@{}: {}, cycles estimate: {}",
            prog.borrow().params.op_name,
            prog.borrow().params.integer_w,
            arch.report_usage(),
            arch.cycle()
        );

        (
            arch.cycle(),
            self.into_iter().map(|x| x.copy_meta().unwrap()).collect(),
        )
    }

    #[instrument(level = "trace", skip(self, prog))]
    pub fn add_to_prog(self, prog: &Program) -> Vec<MetaVarCell> {
        self.raw_add(prog).1
    }

    #[instrument(level = "trace", skip(self, prog))]
    pub fn estimate(self, prog: &Program) -> usize {
        self.raw_add(prog).0
    }
}

impl std::ops::Add<Rtl> for Rtl {
    type Output = Rtl;
    fn add(self, rhs: Rtl) -> Self::Output {
        self.into_iter().chain(rhs).collect::<Vec<_>>().into()
    }
}

impl std::iter::Sum<Rtl> for Rtl {
    fn sum<I: Iterator<Item = Rtl>>(iter: I) -> Self {
        iter.fold(Rtl::default(), |acc, x| acc + x)
    }
}

impl Drop for Rtl {
    fn drop(&mut self) {
        self.unload();
    }
}

impl IntoIterator for Rtl {
    type Item = VarCell;
    type IntoIter = <Vec<VarCell> as IntoIterator>::IntoIter;
    fn into_iter(mut self) -> Self::IntoIter {
        self.unload();
        let mut vec = Vec::new();
        std::mem::swap(&mut self.0, &mut vec);
        vec.into_iter()
    }
}

impl From<Vec<VarCell>> for Rtl {
    fn from(value: Vec<VarCell>) -> Self {
        Rtl(value)
    }
}

// {{{1 Debugging stuff
// ----------------------------------------------------------------------------

#[cfg(feature = "rtl_graph")]
use dot2;
#[cfg(feature = "rtl_graph")]
use std::borrow::Cow;

impl Rtl {
    #[cfg(feature = "rtl_graph")]
    fn write_dot(&self, prog: &Program, cycle: usize) {
        Graph::new(
            prog.op_name().unwrap_or("default".into()),
            prog.params().blk_w(),
            cycle,
            self.0
                .iter()
                .filter_map(|v| v.copy_driver().and_then(|(d, _)| Some(d)))
                .collect::<Vec<_>>()
                .as_slice(),
        )
        .write();
    }
    #[cfg(not(feature = "rtl_graph"))]
    fn write_dot(&self, _prog: &Program, _: usize) {}
}

#[cfg(feature = "rtl_graph")]
struct Graph {
    name: String,
    width: usize,
    cycle: usize,
    heads: HashSet<OperationCell>,
    nodes: HashSet<OperationCell>,
}

#[cfg(feature = "rtl_graph")]
use itertools::Itertools;
#[cfg(feature = "rtl_graph")]
use std::io::{Seek, Write};
#[cfg(feature = "rtl_graph")]
impl Graph {
    pub fn write(&self) {
        let dir = format!("graph/{}/{}", self.width, self.name);
        std::fs::DirBuilder::new()
            .recursive(true)
            .create(&dir)
            .unwrap();
        let mut fid = std::fs::File::create(format!("{}/cycle{}.dot", &dir, self.cycle)).unwrap();
        dot2::render(self, &mut fid).unwrap();
        // Append rank information
        fid.seek_relative(-2).expect("Seek failed");
        let head_str = self
            .heads
            .iter()
            .map(|x| format!("N{}", x.copy_uid()))
            .join(";");
        writeln!(fid, "{{ rank=same; {} }}\n}}", head_str).expect("Write failed");
    }

    pub fn get_nodes(roots: &[OperationCell]) -> HashSet<OperationCell> {
        roots
            .iter()
            .map(|g| g.get_all_ops().into_iter())
            .flatten()
            .collect()
    }

    pub fn get_heads(roots: &[OperationCell]) -> HashSet<OperationCell> {
        roots
            .iter()
            .flat_map(|g| g.get_heads().into_iter())
            .collect()
    }

    pub fn new(name: String, width: usize, cycle: usize, roots: &[OperationCell]) -> Graph {
        Graph {
            name,
            width,
            cycle,
            heads: Graph::get_heads(roots),
            nodes: Graph::get_nodes(roots),
        }
    }
}

#[cfg(feature = "rtl_graph")]
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
struct GraphEdge {
    from: OperationCell,
    to: OperationCell,
    port_id: usize,
    loads: usize,
    uid: usize,
}

// Dot2 implementation for Operation
#[cfg(feature = "rtl_graph")]
impl<'a> dot2::Labeller<'a> for Graph {
    type Node = OperationCell;
    type Edge = GraphEdge;
    type Subgraph = ();

    fn graph_id(&'a self) -> dot2::Result<dot2::Id<'a>> {
        dot2::Id::new(format!("RTL{}", self.cycle))
    }

    fn node_id(&'a self, n: &Self::Node) -> dot2::Result<dot2::Id<'a>> {
        dot2::Id::new(format!("N{}", n.borrow().uid()))
    }

    fn node_label<'b>(&'b self, n: &Self::Node) -> dot2::Result<dot2::label::Text<'b>> {
        Ok(dot2::label::Text::LabelStr(Cow::from(String::from(
            format!(
                "{}(load={},uid={},dst_used={})",
                n.copy_name(),
                n.borrow()
                    .load_stats()
                    .clone()
                    .and_then(|l| Some(format!("{:?}", l)))
                    .unwrap_or(String::from("None")),
                n.copy_uid(),
                n.borrow().dst().iter().filter_map(|d| Some(d)).count()
            ),
        ))))
    }

    fn edge_label<'b>(&'b self, e: &Self::Edge) -> dot2::label::Text<'b> {
        dot2::label::Text::LabelStr(format!("{}[{},{}]", e.uid, e.port_id, e.loads).into())
    }
}

#[cfg(feature = "rtl_graph")]
impl<'a> dot2::GraphWalk<'a> for Graph {
    type Node = OperationCell;
    type Edge = GraphEdge;
    type Subgraph = ();

    fn nodes(&self) -> dot2::Nodes<'a, Self::Node> {
        self.nodes.iter().map(|x| x.clone()).collect()
    }

    fn edges(&'a self) -> dot2::Edges<'a, Self::Edge> {
        let hash_set: HashSet<GraphEdge> = self
            .nodes
            .iter()
            .map(|g| {
                g.copy_src()
                    .into_iter()
                    .filter_map(move |v| {
                        v.copy_driver().and_then(|(d, port_id)| {
                            Some((v.copy_uid(), g, d, port_id, v.copy_loads().len()))
                        })
                    })
                    .map(|(uid, g, d, port_id, loads)| GraphEdge {
                        from: d.clone(),
                        to: g.clone(),
                        uid,
                        port_id,
                        loads,
                    })
            })
            .flatten()
            .filter(|x| self.nodes.contains(&x.from) && self.nodes.contains(&x.to))
            .collect();
        hash_set.into_iter().collect()
    }

    fn source(&self, e: &Self::Edge) -> Self::Node {
        e.from.clone()
    }

    fn target(&self, e: &Self::Edge) -> Self::Node {
        e.to.clone()
    }
}

impl Debug for Var {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("Var")
            .field("uid", &self.uid)
            .field("meta", &self.meta.as_ref())
            .field("loads", &self.loads.len())
            .finish()
    }
}

impl Debug for VarCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        self.borrow().fmt(f)
    }
}

// ----------------------------------------------------------------------------
// }}}

// vim: foldmethod=marker
