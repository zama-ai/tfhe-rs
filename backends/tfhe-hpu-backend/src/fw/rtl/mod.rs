//!
//! A firmware abstraction layer in which the operation dependencies are
//! represented in a non acyclical graph. The resulting graph can then be used
//! to dump a series of instructions that maximize the target resources.

mod macros;

use super::metavar::{MetaVarCell, MetaVarCellWeak, VarPos};
use super::program::Program;
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
use super::isc_sim;
use super::isc_sim::{
    InstructionKind,
    PeStore, PeFlush,
    report::PeStoreRpt,
};

static COUNTER: AtomicUsize = AtomicUsize::new(1);
fn new_uid() -> usize {
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug)]
pub struct LoadStats {
    load_cnt: usize,
    depth: usize,
}

impl Default for LoadStats {
    fn default() -> Self {
        LoadStats {
            depth: 0,
            load_cnt: 0,
        }
    }
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
        let stats = value.borrow().load_stats().unwrap_or(LoadStats::default());
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
    rid: Option<usize>, // The RID currently allocated for this variable
    uid: usize,
}

impl Var {
    pub fn unlinked(&self) -> Var {
        Var {
            driver: None,
            loads: HashSet::new(),
            meta: self.meta.clone(),
            ..*self
        }
    }

    pub fn get_driver(&self) -> Option<&(OperationCell, usize)> {
        self.driver.as_ref()
    }

    pub fn set_driver(&mut self, drv: Option<(OperationCell, usize)>) {
        self.driver = drv;
    }

    pub fn set_loads(&mut self, loads: HashSet<OperationCell>) {
        self.loads = loads;
    }

    pub fn add_load(&mut self, op: &OperationCell) {
        self.loads.insert(op.clone());
    }

    pub fn clear_driver(&mut self) {
        self.driver = None;
    }

    pub fn remove_load(&mut self, load: &OperationCell) {
        self.loads.remove(load);
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

    pub fn unlinked(&self) -> Self {
        self.borrow().unlinked().into()
    }

    pub fn copy_uid(&self) -> usize {
        self.borrow().uid.clone()
    }

    pub fn copy_meta(&self) -> Option<MetaVarCell> {
        self.0.borrow().meta.clone()
    }

    pub fn copy_driver(&self) -> Option<(OperationCell, usize)> {
        if let Some(x) = self.borrow().get_driver() {
            Some(x.clone())
        } else {
            None
        }
    }

    pub fn copy_loads(&self) -> Vec<OperationCell> {
        self.borrow().loads.iter().map(|x| x.clone()).collect()
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
        self.0.borrow_mut().set_driver(op);
    }

    pub fn set_loads(&self, loads: HashSet<OperationCell>) {
        self.0.borrow_mut().set_loads(loads);
    }

    pub fn set_load_stats(&self, load_stats: LoadStats) -> LoadStats {
        self.borrow_mut().load_stats = Some(load_stats.clone());
        load_stats
    }

    pub fn set_meta(&self, var: MetaVarCell) {
        self.0.borrow_mut().meta = Some(var);
    }

    pub fn set_rid(&self, rid: usize) {
        self.0.borrow_mut().rid = Some(rid);
    }

    pub fn add_load(&self, op: &OperationCell) {
        self.0.borrow_mut().add_load(op);
    }

    pub fn clear_driver(&self) {
        self.0.borrow_mut().clear_driver();
    }

    pub fn pop_rid(&self) -> usize {
        let out = self.0.borrow().rid.unwrap();
        self.0.borrow_mut().rid = None;
        out
    }

    pub fn remove_load(&self, load: &OperationCell) {
        self.0.borrow_mut().remove_load(load);
    }

    pub fn copy_load_stats(&self) -> LoadStats {
        let load_stats = self.borrow().load_stats.clone();
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
            rid: None,
            uid: new_uid(),
            load_stats: None,
        })))
    }

    pub fn pbs(&self, lut: &Pbs) -> Vec<VarCell> {
        let var: Vec<_> = (0..lut.lut_nb())
            .into_iter()
            .map(|_| VarCell::new())
            .collect();
        let new_op = PbsOp::new(var.as_slice(), lut, self);
        var.iter()
            .enumerate()
            .for_each(|(i, v)| v.set_driver(Some((new_op.clone(), i))));
        var
    }

    pub fn mac(&self, cnst: usize, other: &VarCell) -> VarCell {
        let var = VarCell::new();
        let new_op = MacOp::new(cnst, self, other);
        var.set_driver(Some((new_op.clone(), 0)));
        var
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
        VarCell(Rc::new(RefCell::new(var.clone())))
    }
}

impl std::hash::Hash for VarCell {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.borrow().hash(state)
    }
}

#[enum_dispatch(Operation)]
pub trait OperationTrait
where
    Self: Sized + Debug + std::hash::Hash,
{
    fn get_meta_var(&self, prog: &mut Option<Program>) -> Vec<MetaVarCell>;
    fn dst(&self) -> &Vec<Option<VarCell>>;
    fn dst_mut(&mut self) -> &mut Vec<Option<VarCell>>;
    fn src(&self) -> &Vec<VarCell>;
    fn uid(&self) -> &usize;
    fn load_stats(&self) -> &Option<LoadStats>;
    fn clear_src(&mut self);
    fn clear_dst(&mut self);
    fn name(&self) -> &str;
    fn kind(&self) -> InstructionKind;
    fn unlinked(&self) -> Self;
    fn set_src(&mut self, src: Vec<VarCell>);
    fn set_load_stats(&mut self, stats: LoadStats);
}

// Not every DOP is implemented, add more if you need more

rtl_op!("ADD", Arith, (self, _) {
    let a = self.src[0].copy_meta().unwrap();
    let b = self.src[1].copy_meta().unwrap();
    a.reg_alloc_mv();
    b.reg_alloc_mv();
    vec![&a+&b]
});

rtl_op!("SUB", Arith, (self, _) {
    let a = self.src[0].copy_meta().unwrap();
    let b = self.src[1].copy_meta().unwrap();
    a.reg_alloc_mv();
    b.reg_alloc_mv();
    vec![&a-&b]
});

rtl_op!("MAC", Arith, usize, (self, _) {
    let a = self.src[0].copy_meta().unwrap();
    let b = self.src[1].copy_meta().unwrap();
    a.reg_alloc_mv();
    b.reg_alloc_mv();
    vec![a.mac(self.data as u8, &b)]
});

rtl_op!("PBS", Pbs, Pbs, (self, prog) {
    let pbs = prog.var_from(Some(VarPos::Pbs(self.data.clone())));
    self.src[0].copy_meta().unwrap().pbs_many(&pbs, false)
});

rtl_op!("ST", MemSt, (self, _) {
    let rhs = self.src[0].copy_meta().unwrap();
    if let Some(dst) = self.dst[0].as_ref() {
        if let Some(mut lhs) = dst.copy_meta() {
            lhs <<= rhs.clone();
        } else {
            dst.set_meta(rhs.clone());
        }
    }
    vec![rhs]
});

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

impl AddOp {
    fn new(lhs: &VarCell, rhs: &VarCell) -> OperationCell {
        let op = AddOp {
            src: vec![lhs.clone(), rhs.clone()],
            dst: vec![None],
            uid: new_uid(),
            load_stats: None,
        };
        OperationCell(Rc::new(RefCell::new(Operation::ADD(op))))
    }
}

impl SubOp {
    fn new(lhs: &VarCell, rhs: &VarCell) -> OperationCell {
        let op = SubOp {
            src: vec![lhs.clone(), rhs.clone()],
            dst: vec![None],
            uid: new_uid(),
            load_stats: None,
        };
        OperationCell(Rc::new(RefCell::new(Operation::SUB(op))))
    }
}

impl MacOp {
    fn new(mult: usize, lhs: &VarCell, rhs: &VarCell) -> OperationCell {
        let op = MacOp {
            src: vec![lhs.clone(), rhs.clone()],
            dst: vec![None],
            data: mult,
            uid: new_uid(),
            load_stats: None,
        };
        OperationCell(Rc::new(RefCell::new(Operation::MAC(op))))
    }
}

impl PbsOp {
    fn new(dst: &[VarCell], lut: &Pbs, lhs: &VarCell) -> OperationCell {
        let op = PbsOp {
            src: vec![lhs.clone()],
            dst: dst.into_iter().map(|_| None).collect(),
            data: lut.clone(),
            uid: new_uid(),
            load_stats: None,
        };
        OperationCell(Rc::new(RefCell::new(Operation::PBS(op))))
    }
}

impl StOp {
    fn new(src: &VarCell) -> OperationCell {
        let op = StOp {
            src: vec![src.clone()],
            dst: vec![None],
            uid: new_uid(),
            load_stats: None,
        };
        OperationCell(Rc::new(RefCell::new(Operation::ST(op))))
    }
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

    fn set_load_stats(&self, stats: LoadStats) -> LoadStats {
        self.0.borrow_mut().set_load_stats(stats.clone());
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
                .filter_map(|v| v)
                .map(|d| d.copy_load_stats().load_cnt + 1)
                .sum::<usize>(),
            depth: self
                .copy_dst()
                .into_iter()
                .filter_map(|v| v)
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
            .filter_map(|dst| dst.as_ref().and_then(|d| Some(d.copy_loads().into_iter())))
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
            .map(|d| d.0.get_all_ops())
            .flatten()
            .collect();
        ret.append(&mut other);
        ret
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
        match self.cmp(other) {
            std::cmp::Ordering::Equal => true,
            _ => false
        }
    }
}

impl std::ops::Add for &VarCell {
    type Output = VarCell;

    fn add(self, other: &VarCell) -> VarCell {
        let var = VarCell::new();
        let new_op = AddOp::new(self, other);
        var.set_driver(Some((new_op.clone(), 0)));
        var
    }
}

impl std::ops::Sub for &VarCell {
    type Output = VarCell;

    fn sub(self, other: &VarCell) -> VarCell {
        let var = VarCell::new();
        let new_op = SubOp::new(self, other);
        var.set_driver(Some((new_op.clone(), 0)));
        var
    }
}

impl std::ops::ShlAssign<&VarCell> for VarCell {
    fn shl_assign(&mut self, rhs: &VarCell) {
        let new_op = StOp::new(rhs);
        self.set_driver(Some((new_op.clone(), 0)));
    }
}

// Used to emulate the ALU store add instructions to the program and manipulate
// the register file
struct Arch {
    pe_store: PeStore,
    program: Option<Program>,
    reg_rc: HashMap<usize, (Option<MetaVarCellWeak>, usize)>,
    cycle: usize,
    events: BinaryHeap<isc_sim::Event>,
    rd_pdg: HashMap<usize, Vec<OperationCell>>,
    wr_pdg: HashMap<usize, Vec<OperationCell>>,
    ipip: bool,
}

// An interface to the target architecture
// Responsible for simulating the architecture and inserting operations into the
// program
impl Arch {
    // interface
    pub fn try_dispatch(&mut self, op: BinaryHeap<OperationCell>) -> BinaryHeap<OperationCell> {
        let ret = op
            .into_iter()
            .filter_map(|op| if let Some(id) = {
                    let op_borrow = op.borrow();
                    let kind = op_borrow.kind();

                    self.program.clone()
                    .and_then(|mut p| {
                        // Make sure all sources that are not already in
                        // registers can be allocated
                        let src = op_borrow
                            .src()
                            .iter()
                            .filter(|src| src.copy_meta()
                                    .is_some_and(|m| m.as_reg().is_none()))
                            .map(|_| 1);
                        // And all destinations too
                        let ranges: Vec<_> = [op_borrow.dst().len()]
                            .into_iter()
                            .chain(src)
                            .collect();
                        Some(p.reg_avail(ranges))
                    })
                    .unwrap_or(true)
                    .then_some(kind)
                    .and_then(|kind| self.pe_store.try_push(kind))
                } {
                    self.add(&op);
                    self.rd_pdg.entry(id)
                        .or_insert(Vec::new())
                        .push(op);
                    None
                } else {
                    Some(op)
                }
            )
            .collect::<BinaryHeap<_>>();

        // Flush if there's nothing else to do or ipip
        let flush = (ret.len() == 0 || self.ipip).then_some(PeFlush::ByFlush);
        self.pe_store.probe_for_exec(self.cycle, flush)
            .into_iter()
            .filter(|isc_sim::Event{at_cycle: _, event_type: ev}| match ev {
                isc_sim::EventType::ReqTimeout(_, _) => false,
                _ => true,
            })
            .for_each(|evt| self.events.push(evt));
        ret
    }

    pub fn done(&mut self) -> Option<OperationCell> {
        let isc_sim::Event {
            at_cycle,
            event_type,
        } = self.events.pop().expect("Event queue is empty");
        self.cycle = at_cycle;

        match event_type {
            isc_sim::EventType::RdUnlock(_, id) => {
                // update associated pe state
                self.pe_store.rd_unlock(id);
                let op = self.rd_pdg.get_mut(&id).unwrap().pop().unwrap();
                self.rd_unlock(&op);
                self.wr_pdg.entry(id)
                    .or_insert(Vec::new())
                    .push(op);
                None
            }
            isc_sim::EventType::WrUnlock(_, id) => {
                // update associated pe state
                self.pe_store.wr_unlock(id);
                let op = self.wr_pdg.get_mut(&id).unwrap().pop().unwrap();
                self.wr_unlock(&op);
                Some(op)
            }
            _ => panic!("Received an unexpected event")
        }
    }

    pub fn busy(&self) -> bool {
        self.pe_store.is_busy() || (self.events.len() != 0) 
                                || (self.pe_store.pending() != 0)
    }

    pub fn cycle(&self) -> usize {
        self.cycle
    }

    //internal

    // Adds it to the program
    fn add(&mut self, op: &OperationCell) {
        trace!(target: "rtl", "Adding {:?}", op);
        let results = op.borrow().get_meta_var(&mut self.program);
        op.copy_dst()
            .into_iter()
            .zip(results.into_iter())
            .filter_map(|(dst, meta)| dst.and_then(|d| Some((meta, d))))
            .for_each(|(meta, var)| {
                // Once the operation is added to the program and while it is
                // inflight, make sure all destination and source registers are
                // not used by anybody else to avoid stalling any posterior
                // operation
                self.reg_writting(&meta);
                var.set_meta(meta);
            });
        op.copy_src()
            .into_iter()
            .filter_map(|s| s.copy_meta())
            .for_each(|s| {
                self.reg_reading(&s);
            });
    }

    fn reg_reading(&mut self, meta: &MetaVarCell) {
        if let Some(prog) = &mut self.program {
            if let Some(rid) = meta.as_reg() {
                self.reg_rc
                    .entry(rid.0 as usize)
                    .and_modify(|e| {
                        e.1 += 1;
                    })
                    .or_insert_with(|| (prog.reg_pop(&rid), 1));
            }
        }
    }

    fn reg_writting(&mut self, meta: &MetaVarCell) {
        if let Some(prog) = &mut self.program {
            let rid = meta.as_reg().unwrap();
            prog.reg_pop(&rid);
            self.reg_rc
                .entry(rid.0 as usize)
                .or_insert_with(|| (meta.try_into().ok(), 1));
        }
    }

    fn reg_release(&mut self, meta: &MetaVarCell) {
        if let Some(prog) = &mut self.program {
            if let Some(rid) = meta.as_reg() {
                let entry = self.reg_rc.remove(&(rid.0 as usize));
                if let Some(mut e) = entry {
                    e.1 -= 1;
                    if e.1 != 0 {
                        self.reg_rc.insert(rid.0 as usize, e);
                    } else {
                        prog.reg_put(rid, e.0);
                    }
                }
            }
        }
    }

    fn rd_unlock(&mut self, op: &OperationCell) {
        op.copy_src()
            .into_iter()
            .filter_map(|x| x.copy_meta())
            .for_each(|m| {
                self.reg_release(&m);
            });
    }

    fn wr_unlock(&mut self, op: &OperationCell) {
        op.copy_dst()
            .into_iter()
            .filter_map(|d| d)
            .filter_map(|x| x.copy_meta())
            .for_each(|m| {
                self.reg_release(&m);
            });
    }

    fn report_usage(&self) -> PeStoreRpt {
        PeStoreRpt::from(&self.pe_store)
    }
}

impl From<&Program> for Arch {
    fn from(program: &Program) -> Self {
        let params = program.params();
        let mut pe_store = PeStore::from(params.sim_params.pe_cfg.clone());
        pe_store.set_batch_limit();
        Arch {
            pe_store,
            program: Some(program.clone()),
            reg_rc: HashMap::new(),
            cycle: 0,
            ipip: params.ipip,
            events: BinaryHeap::new(),
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
            .map(|(d, _)| d.get_all_ops().into_iter())
            .flatten()
            .for_each(|op| {
                op.unload();
            });
    }

    fn find_roots(from: &mut Vec<VarCell>) -> HashSet<OperationCell> {
        let res: HashSet<OperationCell> = from
            .iter()
            .filter_map(|v| v.copy_driver().and_then(|(d, _)| Some(d)))
            .map(|d| {
                if d.is_ready() {
                    HashSet::from([d]).into_iter()
                } else {
                    Rtl::find_roots(&mut d.copy_src()).into_iter()
                }
            })
            .flatten()
            .collect();

        res.iter().for_each(|op| {
            op.set_load_stats(op.copy_load_stats());
        });

        res
    }

    pub fn raw_add(mut self, prog: &Program, dry_run: bool) -> (usize, Vec<MetaVarCell>) {
        self.load();
        self.write_dot(0);

        let mut arch = Arch::from(prog);
        if dry_run {
            arch.program = None;
        };
        let mut todo: BinaryHeap<_> = 
            Rtl::find_roots(&mut self.0)
                .into_iter()
                .collect();

        trace!(target: "rtl", "todo: {:?}", &todo);

        while (todo.len() != 0) || arch.busy() {
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

    pub fn add(self, prog: &Program) -> Vec<MetaVarCell> {
        self.raw_add(prog, false).1
    }

    pub fn estimate(self, prog: &Program) -> usize {
        self.raw_add(prog, true).0
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

#[cfg(any(feature = "rtl_graph"))]
use dot2;
#[cfg(any(feature = "rtl_graph"))]
use std::borrow::Cow;

impl Rtl {
    #[cfg(any(feature = "rtl_graph"))]
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

#[cfg(any(feature = "rtl_graph"))]
struct Graph {
    cycle: usize,
    nodes: HashSet<OperationCell>,
}

#[cfg(any(feature = "rtl_graph"))]
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

#[cfg(any(feature = "rtl_graph"))]
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
struct GraphEdge {
    from: OperationCell,
    to: OperationCell,
    port_id: usize,
    loads: usize,
    uid: usize,
}

// Dot2 implementation for Operation
#[cfg(any(feature = "rtl_graph"))]
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

#[cfg(any(feature = "rtl_graph"))]
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
            .field("meta", &self.meta.is_some())
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
