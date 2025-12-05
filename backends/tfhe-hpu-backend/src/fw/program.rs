//!
//! Abstraction used to ease FW writing
//!
//! It provide a set of utilities used to help FW implementation
//! with a clean and easy to read API

use lru::LruCache;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use crate::asm;

use super::metavar::{MetaVarCell, MetaVarCellWeak, VarPos};
use super::FwParameters;

use tracing::trace;

use crate::fw::rtl::config::OpCfg;

#[derive(Debug, Clone)]
pub struct ProgramInner {
    uid: usize,
    pub(crate) params: FwParameters,
    pub(crate) regs: LruCache<asm::RegId, Option<MetaVarCellWeak>>,
    pub(crate) heap: LruCache<asm::MemId, Option<MetaVarCellWeak>>,
    pub(crate) vars: HashMap<usize, MetaVarCellWeak>,
    pub(crate) stmts: asm::Program<asm::DOp>,
}

/// ProgramInner constructors
impl ProgramInner {
    pub fn new(params: &FwParameters) -> Self {
        let nb_regs = match std::num::NonZeroUsize::try_from(params.register) {
            Ok(val) => val,
            _ => panic!("Error: Number of registers must be >= 0"),
        };
        let mut regs = LruCache::<asm::RegId, Option<MetaVarCellWeak>>::new(nb_regs);
        // At start regs cache is full of unused slot
        for rid in 0..params.register {
            regs.put(asm::RegId(rid as u8), None);
        }

        let nb_heap = match std::num::NonZeroUsize::try_from(params.heap_size) {
            Ok(val) => val,
            _ => panic!("Error: Number of heap slot must be >= 0"),
        };
        let mut heap = LruCache::<asm::MemId, Option<MetaVarCellWeak>>::new(nb_heap);
        // At start heap cache is full of unused slot
        for hid in 0..params.heap_size as u16 {
            heap.put(asm::MemId::new_heap(hid), None);
        }

        Self {
            uid: 0,
            params: params.clone(),
            regs,
            heap,
            vars: HashMap::new(),
            stmts: asm::Program::default(),
        }
    }
}

/// Cache handling
impl ProgramInner {
    /// Retrieved least-recent-used register entry
    /// Return associated register id and evicted variable if any
    /// Warn: Keep cache state unchanged ...
    pub(crate) fn reg_lru(&mut self) -> (asm::RegId, Option<MetaVarCell>) {
        let (rid, rdata) = self
            .regs
            .peek_lru()
            .expect("Error: register cache empty. Check register management");

        // Handle evicted slot if any
        // Convert it in strong reference for later handling
        let evicted = if let Some(weak_evicted) = rdata {
            weak_evicted.try_into().ok()
        } else {
            None
        };

        (*rid, evicted)
    }

    // Tries to get a range of consecutive aligned free registers and falls back
    // to the range starting a the LRU
    pub(crate) fn aligned_reg_range(&self, range: usize) -> Option<asm::RegId> {
        let range = range as u8;
        let log_size = asm::dop::ceil_ilog2(&range);
        let mask = (1 << log_size) - 1;
        let aligned = || {
            self.regs
                .iter()
                .rev()
                .filter(|(reg, _)| (reg.0 & mask) == 0)
        };
        let rid = aligned()
            .filter(|(reg, _)| {
                let reg = reg.0;
                (reg..reg + range).all(|reg| {
                    self.regs
                        .peek(&asm::RegId(reg))
                        .is_some_and(|r| r.is_none())
                })
            })
            .map(|(reg, _)| *reg)
            .next();
        rid.or_else(|| {
            aligned()
                .filter(|(reg, _)| {
                    let reg = reg.0;
                    (reg + 1..reg + range).all(|reg| self.regs.peek(&asm::RegId(reg)).is_some())
                })
                .map(|(i, _)| *i)
                .next()
        })
    }

    // Retrieves the indicated RID
    // The cache state is unchanged
    pub(crate) fn reg(&mut self, rid: &asm::RegId) -> Option<MetaVarCell> {
        let rdata = self
            .regs
            .peek(rid)
            .unwrap_or_else(|| panic!("Error register {rid:} is not available"));

        if let Some(weak_evicted) = rdata {
            weak_evicted.try_into().ok()
        } else {
            None
        }
    }

    // Insert the MetaVar in the indicated cache slot and return any evicted
    // value
    pub(crate) fn reg_swap_force(
        &mut self,
        rid: &asm::RegId,
        var: MetaVarCell,
    ) -> Option<MetaVarCell> {
        // Find lru slot
        let evicted = self.reg(rid);

        // Update cache state
        *(self.regs.get_mut(rid).expect("Update an `unused` register")) = Some((&var).into());

        evicted
    }

    /// Release register entry
    pub(crate) fn reg_promote(&mut self, rid: asm::RegId) {
        // Update cache state
        // Put this slot in front of all `empty` slot instead of in lru pos
        self.regs.promote(&rid);
        let demote_order = self
            .regs
            .iter()
            .filter(|(_, var)| var.is_none())
            .map(|(rid, _)| *rid)
            .collect::<Vec<_>>();
        demote_order
            .into_iter()
            .for_each(|rid| self.regs.demote(&rid));
    }

    /// Release register entry
    pub(crate) fn reg_release(&mut self, rid: asm::RegId) {
        trace!(target: "Program", "Release Reg {rid}");

        *(self
            .regs
            .get_mut(&rid)
            .expect("Release an `unused` register")) = None;

        self.reg_promote(rid);
    }

    /// Notify register access to update LRU state
    pub(crate) fn reg_access(&mut self, rid: asm::RegId) {
        self.regs.promote(&rid)
    }

    /// Retrieved least-recent-used heap entry
    /// Return associated heap id and evicted variable if any
    /// Warn: Keep cache state unchanged ...
    fn heap_lru(&mut self) -> (asm::MemId, Option<MetaVarCell>) {
        let (mid, rdata) = self
            .heap
            .peek_lru()
            .expect("Error: heap cache empty. Check register management");

        // Handle evicted slot if any
        // Convert it in strong reference for later handling
        let evicted = if let Some(weak_evicted) = rdata {
            weak_evicted.try_into().ok()
        } else {
            None
        };

        (*mid, evicted)
    }

    /// Release register entry
    pub(crate) fn heap_release(&mut self, mid: asm::MemId) {
        trace!(target: "Program", "Release Heap {mid}");
        match mid {
            asm::MemId::Heap { .. } => {
                *(self
                    .heap
                    .get_mut(&mid)
                    .expect("Release an `unused` heap slot")) = None;
                // Update cache state
                // Put this slot in front of all `empty` slot instead of in lru pos
                self.heap.promote(&mid);
                let demote_order = self
                    .heap
                    .iter()
                    .filter(|(_mid, var)| var.is_none())
                    .map(|(mid, _)| *mid)
                    .collect::<Vec<_>>();
                demote_order
                    .into_iter()
                    .for_each(|mid| self.heap.demote(&mid));
            }
            _ => { /*Only release Heap slot*/ }
        }
    }

    /// Notify heap access to update LRU state
    pub(crate) fn heap_access(&mut self, mid: asm::MemId) {
        match mid {
            asm::MemId::Heap { .. } => self.heap.promote(&mid),
            _ => { /* Do Nothing slot do not below to heap*/ }
        }
    }

    /// Insert MetaVar in cache and return evicted value if any
    pub(crate) fn heap_swap_lru(&mut self, var: MetaVarCell) -> (asm::MemId, Option<MetaVarCell>) {
        // Find lru slot
        let (mid, evicted) = self.heap_lru();

        // Update cache state
        *(self
            .heap
            .get_mut(&mid)
            .expect("Update an `unused` heap slot")) = Some((&var).into());

        (mid, evicted)
    }

    /// Adds the given register for use
    pub(super) fn reg_put(&mut self, rid: asm::RegId, meta: Option<MetaVarCellWeak>) {
        assert!(self.regs.peek(&rid).is_none());
        self.regs.put(rid, meta);
    }
}

/// MetaVar handling
impl ProgramInner {
    /// Create MetaVar from an optional argument
    fn var_from(&mut self, from: Option<VarPos>, ref_to_self: Program) -> MetaVarCell {
        // Create MetaVar
        let uid = self.uid;
        self.uid += 1;

        // Construct tfhe params
        let tfhe_params: asm::DigitParameters = self.params.clone().into();
        let var = MetaVarCell::new(ref_to_self, uid, from, tfhe_params);

        // Register in var store
        self.vars.insert(uid, (&var).into());

        var
    }

    pub fn new_var(&mut self, ref_to_self: Program) -> MetaVarCell {
        self.var_from(None, ref_to_self)
    }
}

#[derive(Clone)]
pub struct Program {
    inner: Rc<RefCell<ProgramInner>>,
}

impl std::ops::Deref for Program {
    type Target = Rc<RefCell<ProgramInner>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(Clone)]
pub struct StmtLink {
    prog: Program,
    pos: Vec<usize>,
}

impl std::fmt::Debug for StmtLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("StmtLink").field("pos", &self.pos).finish()
    }
}

impl StmtLink {
    pub fn empty(prog: Program) -> StmtLink {
        StmtLink {
            prog,
            pos: Vec::new(),
        }
    }

    pub fn to_flush(&mut self) {
        if let Some(pos) = self.pos.first() {
            let mut borrow = self.prog.borrow_mut();
            let dop = borrow.stmts.get_stmt_mut(*pos);
            dop.to_flush();
        }
    }
}

impl Program {
    pub fn new(params: &FwParameters) -> Self {
        Self {
            inner: Rc::new(RefCell::new(ProgramInner::new(params))),
        }
    }

    pub fn params(&self) -> FwParameters {
        self.inner.borrow().params.clone()
    }

    pub fn op_cfg(&self) -> OpCfg {
        self.inner.borrow().params.op_cfg()
    }

    pub fn op_name(&self) -> Option<String> {
        self.inner.borrow().params.op_name.clone()
    }

    pub fn set_op(&mut self, opname: &str) {
        self.inner.borrow_mut().params.set_op(opname);
    }

    pub fn push_comment(&mut self, comment: String) {
        self.inner.borrow_mut().stmts.push_comment(comment)
    }

    // pub fn get_stmts(&self) -> Vec<asm::DOp> {
    //     self.inner.borrow().stmts.clone()
    // }

    pub fn var_from(&mut self, from: Option<VarPos>) -> MetaVarCell {
        self.inner.borrow_mut().var_from(from, self.clone())
    }

    pub fn new_var(&mut self) -> MetaVarCell {
        self.var_from(None)
    }

    /// Easy way to create new imm value
    pub fn new_imm(&mut self, imm: usize) -> MetaVarCell {
        let arg = Some(VarPos::Imm(asm::ImmId::Cst(imm as u16)));
        self.var_from(arg)
    }

    /// Easy way to create constant backed in register
    pub fn new_cst(&mut self, cst: usize) -> MetaVarCell {
        let mut var = self.var_from(None);
        var.reg_alloc_mv();
        // Force val to 0 then add cst value
        var -= var.clone();
        if cst != 0 {
            let imm = self.new_imm(cst);
            var += imm;
        }

        var
    }

    /// Create templated arguments
    /// kind is used to specify if it's bind to src/dst or immediate template
    /// pos_id is used to bind the template to an IOp operand position
    // TODO pass the associated operand or immediate to obtain the inner blk properties instead of
    // using the global one
    pub fn iop_template_var(&mut self, kind: asm::OperandKind, pos_id: u8) -> Vec<MetaVarCell> {
        let nb_blk = self.params().blk_w() as u8;
        match kind {
            asm::OperandKind::Src => {
                // Digit in iop arg are contiguous
                (0..nb_blk)
                    .map(|bid| {
                        let mid = asm::MemId::new_src(pos_id, bid);
                        self.var_from(Some(VarPos::Mem(mid)))
                    })
                    .collect::<Vec<_>>()
            }
            asm::OperandKind::Dst => {
                // Digit in iop arg are contiguous
                (0..nb_blk)
                    .map(|bid| {
                        let mid = asm::MemId::new_dst(pos_id, bid);
                        self.var_from(Some(VarPos::Mem(mid)))
                    })
                    .collect::<Vec<_>>()
            }
            asm::OperandKind::Imm => (0..nb_blk)
                .map(|bid| {
                    let iid = asm::ImmId::new_var(pos_id, bid);
                    self.var_from(Some(VarPos::Imm(iid)))
                })
                .collect::<Vec<_>>(),
            asm::OperandKind::Unknown => panic!("Template var required a known kind"),
        }
    }

    pub fn push_stmt(&mut self, asm: asm::dop::DOp) -> StmtLink {
        let pos = self.borrow_mut().stmts.push_stmt_pos(asm);
        StmtLink {
            prog: self.clone(),
            pos: vec![pos],
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum AtomicRegType {
    NewRange(usize),
    Existing(asm::RegId),
    None,
}

// Register utilities
impl Program {
    /// Bulk reserve
    /// Evict value from cache in a bulk manner. This enable to prevent false dependency of bulk
    /// operations when cache is almost full Enforce that at least bulk_size register is `free`
    pub(crate) fn reg_bulk_reserve(&self, bulk_size: usize) {
        // Iter from Lru -> MRu and take bulk_size regs
        let to_evict = self
            .inner
            .borrow()
            .regs
            .iter()
            .rev()
            .take(bulk_size)
            .filter(|(_, var)| var.is_some())
            .map(|(_, var)| var.as_ref().unwrap().clone())
            .collect::<Vec<_>>();

        // Evict metavar to heap and release
        to_evict.into_iter().for_each(|var| {
            // Evict in memory if needed
            if let Ok(cell) = MetaVarCell::try_from(&var) {
                cell.heap_alloc_mv(true);
            }
        });
    }

    /// Removes the given register from use
    pub fn reg_pop(&self, rid: &asm::RegId) -> Option<MetaVarCellWeak> {
        self.inner.borrow_mut().regs.pop(rid).unwrap()
    }

    /// Adds the given register for use
    pub fn reg_put(&self, rid: asm::RegId, meta: Option<MetaVarCellWeak>) {
        self.inner.borrow_mut().reg_put(rid, meta);
    }

    // Inspects the register cache and yields the requested register ranges, if
    // possible. This does not touch the cache state.
    pub fn atomic_reg_range(&self, ranges: &[AtomicRegType]) -> Option<Vec<asm::RegId>> {
        let mut borrow = self.inner.borrow_mut();

        // Clone the register cache to restore it at the end
        let backup = borrow.regs.clone();

        // Remove first all already allocated ranges
        ranges.iter().for_each(|r| {
            if let AtomicRegType::Existing(rid) = r {
                borrow.regs.pop(rid);
            }
        });

        let result: Option<Vec<_>> = ranges
            .iter()
            .map(|r| {
                match r {
                    AtomicRegType::NewRange(r) => borrow.aligned_reg_range(*r).inspect(|rid| {
                        borrow.regs.pop(rid);
                    }),
                    AtomicRegType::Existing(rid) => Some(*rid),
                    // To ignore
                    AtomicRegType::None => Some(asm::RegId::default()),
                }
            })
            .collect();

        // Restore the cache state
        borrow.regs = backup;

        result
    }
}

impl From<Program> for asm::Program<asm::DOp> {
    fn from(value: Program) -> Self {
        let inner = value.inner.borrow();
        inner.stmts.clone()
    }
}

/// Syntax sugar to help user wrap PbsLut in MetaVarCell
#[macro_export]
macro_rules! new_pbs {
    (
        $prog:ident, $pbs: literal
    ) => {
        ::paste::paste! {
            $prog.var_from(Some(metavar::VarPos::Pbs(asm::dop::[<Pbs $pbs:camel>]::default().into())))
        }
    };
}

/// To get an asm PBS from its name
#[macro_export]
macro_rules! pbs_by_name {
    (
        $pbs: literal
    ) => {
        ::paste::paste! {
            asm::Pbs::[<$pbs:camel>](asm::dop::[<Pbs $pbs:camel>]::default())
        }
    };
}
