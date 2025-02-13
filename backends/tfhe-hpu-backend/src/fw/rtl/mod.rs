//!
//! A firmware abstraction layer in which the operation dependencies are
//! represented in a non acyclical graph. The resulting graph can then be used
//! to dump a series of instructions that maximize the target resources.

mod macros;

use super::isc_sim;
use super::isc_sim::{report::PeStoreRpt, InstructionKind, PeFlush, PeStore};
use super::metavar::{MetaVarCell, PosKind, RegLockPtr, VarPos};
use super::program::{AtomicRegType, Program};
use crate::asm::{Pbs, PbsLut};
use crate::rtl_op;
use enum_dispatch::enum_dispatch;
use std::cell::{Ref, RefCell, RefMut};
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::fmt;
use std::fmt::Debug;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use strum_macros::{Display, EnumDiscriminants, EnumString};
use tracing::trace;

static COUNTER: AtomicUsize = AtomicUsize::new(1);
fn new_uid() -> usize {
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LoadStats {
    load_cnt: usize,
    depth: usize,
}

// Encodes an operation priority when scheduling
// Order first by load_stats then by uid
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Prio {
    depth: usize,
    reg_balance: usize,
    uid: usize,
}

impl From<&OperationCell> for Prio {
    fn from(value: &OperationCell) -> Self {
        let stats = value.borrow().load_stats().unwrap_or_default();
        Prio {
            depth: stats.depth,
            uid: *value.borrow().uid(),
            reg_balance: value.borrow().src().len(),
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
            ..*self
        }
    }
}

impl std::ops::Drop for Var {
    fn drop(&mut self) {
        trace!(target: "rtl", "Var Dropped: {:?}", &self);
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
    // Purposedly not public
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
        self.borrow_mut().load_stats = Some(load_stats);
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
        let load_stats = self.borrow().load_stats;
        load_stats.unwrap_or_else(|| self.set_load_stats(self.compute_load_stats()))
    }

    //The load of a variable is the number of variables depending on it
    //(excluding itself).
    pub fn compute_load_stats(&self) -> LoadStats {
        LoadStats {
            load_cnt: self
                .copy_loads()
                .into_iter()
                .map(|d| d.copy_load_stats().load_cnt)
                .sum::<usize>(),
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
            d.set_dst(i, self);
            d.load();
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

    pub fn mac(&self, cnst: usize, other: &VarCell) -> VarCell {
        let var = VarCell::new();
        let new_op = MacOp::new_op(cnst, self, other);
        var.set_driver(Some((new_op.clone(), 0)));
        var
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
    fn clear_src(&mut self);
    fn clear_dst(&mut self);
    fn name(&self) -> &str;
    fn kind(&self) -> InstructionKind;
    fn set_load_stats(&mut self, stats: LoadStats);
    fn clone_on(&self, prog: &Program) -> Operation;
}

#[enum_dispatch(Operation)]
trait SetFlush
where
    Self: Sized + Debug + std::hash::Hash,
{
    fn set_flush(&mut self, _flush: bool) {}
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
                        PosKind::IMM | PosKind::PBS => AtomicRegType::None,
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

            if range.iter().any(|rng| *rng != AtomicRegType::None) {
                range.push(AtomicRegType::NewRange(1));
            }

            prog.atomic_reg_range(range.as_slice()).is_some()
        } else {
            // This operation is not needed, just say yes
            true
        }
    }

    // This blanket implementation handles the typical case where an operation
    // has many sourcs and only a single destination
    fn alloc1_prog(&mut self, prog: &mut Program) -> OpLock1 {
        if let Some(dst) = self.dst()[0].as_ref() {
            let a = self.src()[0].copy_meta().unwrap();
            let b = self.src()[1].copy_meta().unwrap();
            let mut d = prog.new_var();
            dst.set_meta(d.clone());

            a.reg_alloc_mv();
            b.reg_alloc_mv();
            if !(a.is_in(PosKind::IMM) && b.is_in(PosKind::IMM)) {
                d.reg_alloc_mv();
            }

            OpLock1 {
                rd_lock: Some([a, b].iter_mut().map(|m| m.reg_lock()).collect()),
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
struct MacData {
    lock: OpLock1,
    mult: usize,
}

#[derive(Clone, Debug)]
struct PbsData {
    lut: Pbs,
    flush: bool,
    rd_lock: Option<RegLockPtr>,
    wr_lock: Option<Vec<RegLockPtr>>,
}

rtl_op!("ADD", Arith, OpLock1);
rtl_op!("SUB", Arith, OpLock1);
rtl_op!("MAC", Arith, MacData);
rtl_op!("PBS", Pbs, PbsData);
rtl_op!("ST", MemSt, Option<RegLockPtr>);

impl ProgManager for AddOp {
    fn alloc_prog(&mut self, prog: &mut Program) {
        self.data = self.alloc1_prog(prog)
    }

    fn add_prog(&mut self, _: &mut Program) {
        if let Some(d) = self.dst[0].as_ref() {
            let a = self.src[0].copy_meta().unwrap();
            let b = self.src[1].copy_meta().unwrap();
            let d = d.copy_meta().unwrap();
            d.add_raw(&a, &b);
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
            d.sub_raw(&a, &b);
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
        // Assume at least one destination is needed
        let mut a = self.src()[0].copy_meta().unwrap();
        a.reg_alloc_mv();

        assert!(
            a.is_in(PosKind::REG),
            "Cannot do a PBS from something other than a register"
        );

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

        self.data.rd_lock = Some(a.reg_lock());
        self.data.wr_lock = Some(d.into_iter().map(|mut d| d.reg_lock()).collect());
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

        MetaVarCell::pbs_raw(
            &dst.iter().collect::<Vec<_>>(),
            &src,
            &pbs,
            self.data.flush,
            &tfhe_params,
        );
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
    fn new_op(mult: usize, lhs: &VarCell, rhs: &VarCell) -> OperationCell {
        let op = MacOp {
            src: vec![lhs.clone(), rhs.clone()],
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

impl PbsOp {
    fn new_op(dst: &[VarCell], lut: &Pbs, lhs: &VarCell) -> OperationCell {
        let op = PbsOp {
            src: vec![lhs.clone()],
            dst: dst.iter().map(|_| None).collect(),
            data: PbsData {
                lut: lut.clone(),
                flush: false,
                rd_lock: None,
                wr_lock: None,
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

impl SetFlush for AddOp {}
impl SetFlush for SubOp {}
impl SetFlush for MacOp {}
impl SetFlush for PbsOp {
    fn set_flush(&mut self, flush: bool) {
        self.data.flush = flush
    }
}
impl SetFlush for StOp {}

#[enum_dispatch]
#[derive(EnumDiscriminants, Debug, Hash, PartialEq, Eq, Clone)]
#[strum_discriminants(name(OperationNames))]
#[strum_discriminants(derive(EnumString, Display))]
pub enum Operation {
    ADD(AddOp),
    SUB(SubOp),
    MAC(MacOp),
    PBS(PbsOp),
    ST(StOp),
}

// All pointers are reference counted pointers in the tree, both drivers and
// loads. This is because the FW when building the tree will hold only end
// variables, while when scheduling we'll hold source variables. While
// scheduling the tree needs to be de-constructed carefully so that it can be
// fully dropped.
#[derive(Clone, Eq)]
pub struct OperationCell(Rc<RefCell<Operation>>);

impl OperationCell {
    fn borrow(&self) -> Ref<'_, Operation> {
        self.0.borrow()
    }
    fn is_ready(&self) -> bool {
        self.borrow()
            .src()
            .iter()
            .fold(true, |acc, x| acc & x.is_ready())
    }
    fn copy_dst(&self) -> Vec<Option<VarCell>> {
        self.0.borrow().dst().clone()
    }
    fn copy_src(&self) -> Vec<VarCell> {
        self.0.borrow().src().clone()
    }
    fn copy_name(&self) -> String {
        String::from(self.borrow().name())
    }
    fn prio(&self) -> Prio {
        Prio::from(self)
    }
    fn kind(&self) -> InstructionKind {
        self.0.borrow().kind()
    }

    fn set_load_stats(&self, stats: LoadStats) -> LoadStats {
        self.0.borrow_mut().set_load_stats(stats);
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

    // Removes all links from roots to leafs
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
            load_cnt: self
                .copy_dst()
                .into_iter()
                .flatten()
                .map(|d| d.copy_load_stats().load_cnt + 1)
                .sum::<usize>(),
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
        let load_stats = *self.borrow().load_stats();
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

    fn set_flush(&self, flush: bool) {
        self.0.borrow_mut().set_flush(flush)
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
        other.prio().cmp(&self.prio())
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

impl std::ops::Sub for &VarCell {
    type Output = VarCell;

    fn sub(self, other: &VarCell) -> VarCell {
        let var = VarCell::new();
        let new_op = SubOp::new_op(self, other);
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

// Used to emulate the ALU store add instructions to the program and manipulate
// the register file
struct Arch {
    pe_store: PeStore,
    program: Option<Program>,
    cycle: usize,
    events: BinaryHeap<isc_sim::Event>,
    queued: HashMap<usize, Vec<OperationCell>>,
    rd_pdg: HashMap<usize, Vec<OperationCell>>,
    wr_pdg: HashMap<usize, Vec<OperationCell>>,
    use_ipip: bool,
}

// An interface to the target architecture
// Responsible for simulating the architecture and inserting operations into the
// program
impl Arch {
    // interface
    pub fn try_dispatch(&mut self, op: BinaryHeap<OperationCell>) -> BinaryHeap<OperationCell> {
        let ret = op
            .into_iter()
            .filter_map(|mut op| {
                if let Some(id) = {
                    op.peek_prog(self.program.as_mut())
                        .then_some(true)
                        .and_then(|_| self.pe_store.try_push(op.kind()))
                } {
                    trace!(target: "rtl", "{:?} queued", op);

                    op.alloc_prog(self.program.as_mut());

                    self.queued.entry(id).or_default().push(op.clone());
                    self.rd_pdg.entry(id).or_default().push(op);
                    None
                } else {
                    Some(op)
                }
            })
            .collect::<BinaryHeap<_>>();

        if !self.use_ipip {
            self.probe_for_exec(None);
        }

        // Flush if there's nothing else to do or use_ipip
        if (ret.is_empty() && self.events.is_empty()) || self.use_ipip {
            self.probe_for_exec(Some(PeFlush::ByFlush));
        }

        ret
    }

    pub fn done(&mut self) -> Option<OperationCell> {
        trace!(target: "rtl", "Events: {:?}", self.events);

        let isc_sim::Event {
            at_cycle,
            event_type,
        } = self.events.pop().expect("Event queue is empty");
        self.cycle = at_cycle;

        match event_type {
            isc_sim::EventType::BatchStart(id) => {
                let batch = self.queued.remove(&id).unwrap();
                batch.last().unwrap().set_flush(true);
                for op in batch {
                    op.add_prog(self.program.as_mut())
                }
                None
            }
            isc_sim::EventType::RdUnlock(_, id) => {
                // update associated pe state
                self.pe_store.rd_unlock(id);
                let mut op = self.rd_pdg.get_mut(&id).unwrap().pop().unwrap();
                op.free_rd();
                self.wr_pdg.entry(id).or_default().push(op);
                None
            }
            isc_sim::EventType::WrUnlock(_, id) => {
                // update associated pe state
                self.pe_store.wr_unlock(id);
                let mut op = self.wr_pdg.get_mut(&id).unwrap().pop().unwrap();
                op.free_wr();
                Some(op)
            }
            _ => panic!("Received an unexpected event"),
        }
    }

    pub fn busy(&self) -> bool {
        self.pe_store.is_busy() || (!self.events.is_empty()) || (self.pe_store.pending() != 0)
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
                     }| !matches!(ev, isc_sim::EventType::ReqTimeout(_, _)),
                ),
        );
    }
}

impl From<&Program> for Arch {
    fn from(program: &Program) -> Self {
        let params = program.params();
        let mut pe_store = PeStore::from(params.pe_cfg.clone());
        if params.fill_batch_fifo {
            pe_store.set_fifo_limit(params.total_pbs_nb);
        } else {
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
        }
    }
}

#[derive(Clone, Debug)]
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
    fn find_roots(from: &mut [VarCell]) -> HashSet<OperationCell> {
        let res: HashSet<OperationCell> = from
            .iter()
            .filter_map(|v| v.copy_driver().map(|(d, _)| d))
            .flat_map(|d| {
                if d.is_ready() {
                    HashSet::from([d]).into_iter()
                } else {
                    Rtl::find_roots(&mut d.copy_src()).into_iter()
                }
            })
            .collect();

        res.iter().for_each(|op| {
            op.set_load_stats(op.copy_load_stats());
        });

        res
    }

    pub fn raw_add(mut self, prog: &Program) -> (usize, Vec<MetaVarCell>) {
        self.load();
        self.write_dot(0);

        let mut arch = Arch::from(prog);
        let mut todo: BinaryHeap<_> = Rtl::find_roots(&mut self.0).into_iter().collect();

        trace!(target: "rtl", "todo: {:?}", &todo);

        while (!todo.is_empty()) || arch.busy() {
            // Try to dispatch everything that is ready to be done
            todo = arch.try_dispatch(todo);
            trace!(target: "rtl", "todo: {:?}", &todo);

            if let Some(op) = arch.done() {
                trace!(target: "rtl", "Removing {:?}", &op);
                // Done is consumed here
                let new = op.remove();
                trace!(target: "rtl", "new ready op {:?}", &new);
                todo.extend(new.into_iter());
                self.write_dot(arch.cycle());
            }
        }

        trace!(target: "rtl", "arch report: {}, cycles estimate: {}",
               arch.report_usage(),
               arch.cycle());

        (
            arch.cycle(),
            self.into_iter().map(|x| x.copy_meta().unwrap()).collect(),
        )
    }

    pub fn add_to_prog(self, prog: &Program) -> Vec<MetaVarCell> {
        self.raw_add(prog).1
    }

    pub fn estimate(self, prog: &Program) -> usize {
        self.raw_add(prog).0
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
    fn write_dot(&self, cycle: usize) {
        Graph::new(
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
    fn write_dot(&self, _: usize) {}
}

#[cfg(feature = "rtl_graph")]
struct Graph {
    cycle: usize,
    nodes: HashSet<OperationCell>,
}

#[cfg(feature = "rtl_graph")]
impl Graph {
    pub fn write(&self) {
        let mut fid = std::fs::File::create(format!("operation{}.dot", self.cycle)).unwrap();
        dot2::render(self, &mut fid).unwrap();
    }

    pub fn get_nodes(roots: &[OperationCell]) -> HashSet<OperationCell> {
        roots
            .iter()
            .map(|g| g.get_all_ops().into_iter())
            .flatten()
            .collect()
    }

    pub fn new(cycle: usize, roots: &[OperationCell]) -> Graph {
        Graph {
            cycle,
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

impl Debug for OperationCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("Operation")
            .field("name", &self.copy_name())
            .field("uid", self.borrow().uid())
            .field("dst", &self.borrow().dst().len())
            .finish()
    }
}
// ----------------------------------------------------------------------------
// }}}

// vim: foldmethod=marker
