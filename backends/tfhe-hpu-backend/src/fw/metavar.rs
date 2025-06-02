//!
//! Abstraction over Digit
//! Enable to write code that translate into firmwave in an easy-way
//!
//! Wrap asm::Arg with metadata and overload std::ops on it

use super::*;

use crate::asm::dop::DOp;
use crate::asm::{self, DigitParameters, ImmId, PbsLut};
use crate::fw::program::StmtLink;
use tracing::{debug, error, trace};

use std::cell::RefCell;
use std::ops::{Add, AddAssign, Mul, MulAssign, ShlAssign, Sub, SubAssign};
use std::rc::{Rc, Weak};

use bitflags::bitflags;

// Used to filter on multiple position at once
bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct PosKind: usize {
        const EMPTY   = 0x0;
        const REG   = 0x1;
        const MEM   = 0x2;
        const IMM   = 0x4;
        const PBS   = 0x8;
    }
}

/// Wrap any kind of DOp operand in an enum
/// Enable to depict the position of the associated data in the architecture
#[derive(Debug, Clone)]
pub enum VarPos {
    Reg(asm::dop::RegId),
    Mem(asm::dop::MemId),
    Imm(asm::dop::ImmId),
    Pbs(asm::dop::Pbs),
}

#[derive(Clone)]
struct RegLock(MetaVarCell);

impl std::fmt::Debug for RegLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "Lock: {}", self.0.as_reg().unwrap())
    }
}

#[derive(Debug, Clone)]
struct RegLockWeakPtr(Weak<RegLock>);

#[derive(Debug, Clone)]
pub struct RegLockPtr(Option<Rc<RegLock>>);

impl Drop for RegLock {
    fn drop(&mut self) {
        let rid = self.0.as_reg().unwrap();
        let mut meta_inner = self.0 .0.borrow_mut();
        {
            trace!(target: "MetaOp", "Unlocking register {}", rid);
            let mut prog = meta_inner.prog.borrow_mut();
            prog.reg_put(rid, Some(MetaVarCellWeak::from(&self.0)));
            prog.reg_promote(rid);
        }
        meta_inner.reg_lock = None;
    }
}

impl From<RegLock> for RegLockPtr {
    fn from(value: RegLock) -> Self {
        RegLockPtr(Some(Rc::new(value)))
    }
}

impl From<&RegLockPtr> for RegLockWeakPtr {
    fn from(value: &RegLockPtr) -> Self {
        RegLockWeakPtr(std::rc::Rc::downgrade(value.0.as_ref().unwrap()))
    }
}

impl From<&RegLockWeakPtr> for RegLockPtr {
    fn from(value: &RegLockWeakPtr) -> Self {
        RegLockPtr(Some(value.0.upgrade().unwrap()))
    }
}

impl From<&RegLockPtr> for MetaVarCell {
    fn from(value: &RegLockPtr) -> Self {
        value.0.as_ref().unwrap().0.clone()
    }
}

/// Wrap asm::Arg with metadata
/// asm::Arg is used to know position of the associated value
#[derive(Clone)]
struct MetaVar {
    prog: program::Program,
    #[allow(unused)]
    uid: usize,
    pos: Option<VarPos>,
    degree: usize,
    reg_lock: Option<RegLockWeakPtr>,
}

/// Don't show ref to prog in Debug message
impl std::fmt::Debug for MetaVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MetaVar{{uid: {}, pos: {:?}, degree: {}}}",
            self.uid, self.pos, self.degree
        )
    }
}

impl Drop for MetaVar {
    fn drop(&mut self) {
        trace!(target: "MetaDrop", "Drop::{self:?}");
        if let Some(pos) = &self.pos {
            let mut prog = self.prog.borrow_mut();
            // Release resource attached to inner
            match pos {
                VarPos::Reg(rid) => {
                    assert!(
                        self.reg_lock.is_none(),
                        "Dropping a metavariable with a locked register!"
                    );
                    prog.reg_release(*rid);
                }
                VarPos::Mem(mid) => {
                    prog.heap_release(*mid);
                }
                VarPos::Imm(_) | VarPos::Pbs(_) => {}
            }
        }
    }
}

/// Weak Wrapped type
/// Use to keep reference on MetaVar without breaking lifetime analyses
#[derive(Debug, Clone)]
pub struct MetaVarCellWeak(Weak<RefCell<MetaVar>>);

impl TryFrom<&MetaVarCellWeak> for MetaVarCell {
    type Error = String;

    fn try_from(value: &MetaVarCellWeak) -> Result<Self, Self::Error> {
        if let Some(inner_cell) = value.0.upgrade() {
            Ok(Self(inner_cell))
        } else {
            Err("Not allocated anymore".to_string())
        }
    }
}

/// Wrapped type
/// Define std::ops directly on the wrapper to have clean FW writing syntax
#[derive(Clone)]
pub struct MetaVarCell(Rc<RefCell<MetaVar>>);

impl std::fmt::Debug for MetaVarCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.borrow().fmt(f)
    }
}

impl From<&MetaVarCell> for MetaVarCellWeak {
    fn from(value: &MetaVarCell) -> Self {
        Self(std::rc::Rc::downgrade(&(value.0)))
    }
}

/// MetaVarCell Constructors
impl MetaVarCell {
    pub fn new(
        prog: program::Program,
        uid: usize,
        from: Option<VarPos>,
        tfhe_params: DigitParameters,
    ) -> Self {
        let degree = if let Some(pos) = from.as_ref() {
            match pos {
                VarPos::Reg(_) | VarPos::Mem(_) | VarPos::Imm(_) => tfhe_params.msg_mask(),
                VarPos::Pbs(lut) =>
                // TODO Apply degree analyses later for many-lut case
                {
                    (0..lut.lut_nb() as usize)
                        .map(|pos| lut.fn_at(pos, &tfhe_params, tfhe_params.msg_mask()))
                        .max()
                        .unwrap()
                }
            }
        } else {
            0
        };
        let metavar = MetaVar {
            prog,
            uid,
            pos: from,
            degree,
            reg_lock: None,
        };

        Self(Rc::new(RefCell::new(metavar)))
    }

    pub fn clone_on(&self, prog: &program::Program) -> Self {
        let borrow = self.0.borrow();
        MetaVarCell::new(
            prog.clone(),
            borrow.uid,
            borrow.pos.clone(),
            DigitParameters::from(prog.params()),
        )
    }
}

/// MetaVarCell Reg/Heap management
impl MetaVarCell {
    /// Allocate in register and moved MetaVar content if any
    /// In case of register eviction, this function handle the offloading in memory
    pub(super) fn reg_alloc_mv(&self) {
        trace!(target: "MetaOp", "RegAlloc::{self:?}");

        // Early return if already in Reg or Imm like var
        if self.is_in(PosKind::REG) {
            // Update LRU and return
            self.0
                .borrow()
                .prog
                .borrow_mut()
                .reg_access(self.as_reg().unwrap());
            return;
        } else if self.is_cst() || self.is_in(PosKind::PBS) {
            return;
        }

        let (rid, _) = self.0.borrow().prog.borrow_mut().reg_lru();
        self.force_reg_alloc(rid);
    }

    // Forces allocation in register regid.
    pub(super) fn force_reg_alloc(&self, rid: asm::RegId) {
        trace!(target: "MetaOp", "ForceRegAlloc::{self:?} <= {:?}", rid);

        // Early return if already in Reg or Imm like var
        if self.is_in(PosKind::REG) && self.as_reg().unwrap() == rid {
            // Update LRU and return
            self.0
                .borrow()
                .prog
                .borrow_mut()
                .reg_access(self.as_reg().unwrap());
            return;
        } else if self.is_cst() || self.is_in(PosKind::PBS) {
            return;
        }

        // Get cache entry and update state
        let evicted = self
            .0
            .borrow()
            .prog
            .borrow_mut()
            .reg_swap_force(&rid, self.clone());

        // Move evicted value in Memory if any
        if let Some(var) = evicted {
            var.heap_alloc_mv(false);
        }

        // Move Self content and update metadata
        match self.get_pos() {
            PosKind::EMPTY => {
                // Only update associated metadata
            }
            PosKind::MEM => {
                // Physically moved value in register
                let src = self.as_mem().unwrap();
                // Acquire prog Cell
                let inner = self.0.borrow();
                let mut prog = inner.prog.borrow_mut();

                assert!(
                    !matches!(src, asm::MemId::Dst { .. }),
                    "Load from UserDst register"
                );
                let asm: DOp = asm::dop::DOpLd::new(rid, src).into();
                prog.stmts.push_stmt(asm);

                // Release associated heap slot and update reg cache
                prog.heap_release(src);
                prog.reg_access(rid);
            }
            PosKind::IMM => {
                let imm = self.as_imm().unwrap();
                let inner = self.0.borrow();
                let mut prog = inner.prog.borrow_mut();
                prog.stmts
                    .push_stmt(asm::dop::DOpSub::new(rid, rid, rid).into());
                prog.stmts
                    .push_stmt(asm::dop::DOpAdds::new(rid, rid, imm).into());
                prog.reg_access(rid);
                trace!(target: "MetaOp", "ForceRegAlloc:: {:?} <= {:?}", rid, imm);
            }
            _ => {
                panic!("{self:?} must have been filter before register alloc/eviction")
            }
        }
        // Update associated metadata
        self.updt_pos(Some(VarPos::Reg(rid)));
    }

    /// Allocate in heap and moved MetaVar content if any
    /// In case of heap eviction, this function `panic` since there is no way to properly handle
    /// this case (i.e. heap full)
    pub(crate) fn heap_alloc_mv(&self, reg_release: bool) {
        // Early return if already in Mem or Imm like var
        if self.is_in(PosKind::EMPTY | PosKind::MEM | PosKind::IMM | PosKind::PBS) {
            return;
        }
        trace!(target: "Fw", "Evict {self:?} in heap");

        // Get cache entry and update state
        let (mid, evicted) = self
            .0
            .borrow()
            .prog
            .borrow_mut()
            .heap_swap_lru(self.clone());
        // Check state of heap -> No value was dropped due to overflow
        if let Some(_slot) = evicted {
            panic!("Error: Heap overflow.");
        }

        // Move Self content and update metadata
        match self.get_pos() {
            PosKind::REG => {
                // Physically moved value in memory
                let src = self.as_reg().unwrap();

                // Acquire prog Cell
                let inner = self.0.borrow();
                let mut prog = inner.prog.borrow_mut();
                prog.heap_access(mid);
                let asm: DOp = asm::dop::DOpSt::new(mid, src).into();
                prog.stmts.push_stmt(asm);

                if reg_release {
                    prog.reg_release(src);
                }
            }
            _ => {
                panic!("{self:?} must have been filter before heap alloc")
            }
        }
        // Update associated metadata
        self.updt_pos(Some(VarPos::Mem(mid)));
    }
}

/// Utilities to manipulate and check position
impl MetaVarCell {
    /// Return MetaVar position in an easy to reason about form
    pub fn get_pos(&self) -> PosKind {
        if let Some(pos) = self.0.borrow().pos.as_ref() {
            match pos {
                VarPos::Reg(_) => PosKind::REG,
                VarPos::Mem(_) => PosKind::MEM,
                VarPos::Imm(_) => PosKind::IMM,
                VarPos::Pbs(_) => PosKind::PBS,
            }
        } else {
            PosKind::empty()
        }
    }

    /// Check if MetaVar is one of many position
    pub fn is_in(&self, position: PosKind) -> bool {
        if let Some(pos) = self.0.borrow().pos.as_ref() {
            match pos {
                VarPos::Reg(_) => position.contains(PosKind::REG),
                VarPos::Mem(_) => position.contains(PosKind::MEM),
                VarPos::Imm(_) => position.contains(PosKind::IMM),
                VarPos::Pbs(_) => position.contains(PosKind::PBS),
            }
        } else {
            position.is_empty()
        }
    }

    /// Check if MetaVar is a compile time constant
    pub fn is_cst(&self) -> bool {
        matches!(self.0.borrow().pos, Some(VarPos::Imm(ImmId::Cst(_))))
    }

    /// Update MetaVar position
    fn updt_pos(&self, pos: Option<VarPos>) {
        trace!(target: "MetaOp", "UpdatePos::{self:?} => {:?}", pos);
        let mut inner = self.0.borrow_mut();
        inner.pos = pos;
    }
}

/// Utilities to manipulate and check degree
impl MetaVarCell {
    pub fn updt_degree(&self, degree: usize) {
        let mut inner = self.0.borrow_mut();
        inner.degree = degree;
    }

    pub fn get_degree(&self) -> usize {
        self.0.borrow().degree
    }

    pub fn check_degree(&self) {
        let max_degree = {
            let msg_w = self.0.borrow().prog.params().msg_w;
            let carry_w = self.0.borrow().prog.params().carry_w;
            (1 << (msg_w + carry_w + 1/* padding */)) - 1
        };

        assert!(self.get_degree() <= max_degree)
    }
}

/// Utilities for uncheck field extraction
impl MetaVarCell {
    pub(crate) fn as_reg(&self) -> Option<asm::RegId> {
        if let Some(VarPos::Reg(id)) = self.0.borrow().pos {
            Some(id)
        } else {
            None
        }
    }

    pub(crate) fn as_mem(&self) -> Option<asm::MemId> {
        if let Some(VarPos::Mem(mid)) = self.0.borrow().pos {
            Some(mid)
        } else {
            None
        }
    }

    pub(crate) fn as_imm(&self) -> Option<asm::ImmId> {
        if let Some(VarPos::Imm(val)) = self.0.borrow().pos {
            Some(val)
        } else {
            None
        }
    }

    pub(crate) fn as_pbs(&self) -> Option<asm::Pbs> {
        if let Some(VarPos::Pbs(lut)) = self.0.borrow().pos.as_ref() {
            Some(lut.clone())
        } else {
            None
        }
    }
}

impl MetaVarCell {
    pub(super) fn pbs_raw(
        dst_slice: &[&MetaVarCell],
        src: &MetaVarCell,
        lut: &MetaVarCell,
        flush: bool,
        tfhe_params: &DigitParameters,
    ) -> StmtLink {
        assert!(
            src.is_in(PosKind::REG | PosKind::MEM),
            "Pbs src must be of kind Reg|Mem MetaVar {src:?}"
        );

        assert!(
            lut.is_in(PosKind::PBS),
            "Pbs lut must be of kind Reg|Mem MetaVar"
        );

        // Enforce that operand are in Register
        // and that all destinations are consecutive
        let dst = &dst_slice[0];

        let in_reg = dst_slice.iter().any(|d| d.get_pos() == PosKind::REG);

        if !in_reg {
            // Get the best possible range of registers
            let dst_rid = dst
                .0
                .borrow()
                .prog
                .borrow()
                .aligned_reg_range(dst_slice.len())
                .unwrap();
            // Evict whatever is in the range
            dst_slice
                .iter()
                .enumerate()
                .for_each(|(i, d)| d.force_reg_alloc(asm::RegId(dst_rid.0 + i as u8)));
        } else {
            let lut_lg = lut.as_pbs().unwrap().lut_lg();
            let mask = u8::MAX << lut_lg;
            assert!(
                dst.as_reg().is_some()
                    && dst_slice
                        .iter()
                        .fold(
                            (dst.as_reg().unwrap().0 & mask, true),
                            |(prev, acc), this| {
                                (prev + 1, acc && (prev == this.as_reg().unwrap().0))
                            }
                        )
                        .1,
                "ManyLUT PBS register indexes must be consecutive and aligned to \
            the respective power of two, current indexes: {:?}",
                dst_slice
                    .iter()
                    .map(|d| d.as_reg().unwrap())
                    .collect::<Vec<_>>()
            );
        }
        src.reg_alloc_mv();

        // The first destination is used as the source of all information
        let dst_rid = dst.as_reg().unwrap();
        let src_rid = src.as_reg().unwrap();
        let pbs = lut.as_pbs().unwrap();

        assert!(
            pbs.lut_nb() == dst_slice.len() as u8,
            "No enough destinations specified to receive all outputs in the PBS"
        );

        // Select between standard and flushed Pbs
        // Also select correct opcode based lut width
        let asm = if flush {
            match pbs.lut_nb() {
                1 => asm::dop::DOpPbsF::new(dst_rid, src_rid, pbs.gid()).into(),
                2 => asm::dop::DOpPbsMl2F::new(dst_rid, src_rid, pbs.gid()).into(),
                4 => asm::dop::DOpPbsMl4F::new(dst_rid, src_rid, pbs.gid()).into(),
                8 => asm::dop::DOpPbsMl8F::new(dst_rid, src_rid, pbs.gid()).into(),
                _ => panic!("PbsF with {} entries lut are not supported", pbs.lut_nb()),
            }
        } else {
            match pbs.lut_nb() {
                1 => asm::dop::DOpPbs::new(dst_rid, src_rid, pbs.gid()).into(),
                2 => asm::dop::DOpPbsMl2::new(dst_rid, src_rid, pbs.gid()).into(),
                4 => asm::dop::DOpPbsMl4::new(dst_rid, src_rid, pbs.gid()).into(),
                8 => asm::dop::DOpPbsMl8::new(dst_rid, src_rid, pbs.gid()).into(),
                _ => panic!("PbsF with {} entries lut are not supported", pbs.lut_nb()),
            }
        };
        let stmtlink = dst.0.borrow_mut().prog.push_stmt(asm);

        dst_slice
            .iter()
            .enumerate()
            .for_each(|(i, dst)| dst.updt_degree(pbs.deg_at(i, tfhe_params, src.get_degree())));

        trace!(
            target: "MetaOp",
            "PbsRaw:: {:?} <= {:?}, {:?}{}",
            vec![dst_slice.iter().map(|dst| dst.0.borrow())],
            src.0.borrow(),
            lut.0.borrow(),
            if flush { "[Flush]" } else { ""},
        );

        dst_slice.iter().for_each(|d| d.check_degree());

        stmtlink
    }

    pub fn pbs_assign(&mut self, lut: &MetaVarCell, flush: bool) {
        // Construct tfhe params
        let tfhe_params = self.0.borrow().prog.params().clone().into();
        // Deferred to default logic
        Self::pbs_raw(&[self], self, lut, flush, &tfhe_params);
    }

    pub fn pbs(&self, lut: &MetaVarCell, flush: bool) -> Self {
        // Allocate output variable
        let prog = &self.0.borrow().prog.clone();
        let dst = prog.borrow_mut().new_var(prog.clone());

        // NB: No need to move the destination to a register here, it is done in
        // pbs_raw already

        // Construct tfhe params
        let tfhe_params = prog.params().clone().into();

        // Deferred to default logic
        Self::pbs_raw(&[&dst], self, lut, flush, &tfhe_params);
        dst
    }

    pub fn pbs_many(&self, lut: &MetaVarCell, flush: bool) -> Vec<Self> {
        // Allocate output variable
        let lut_nb = lut.as_pbs().unwrap().lut_nb();
        let out_vec = (0..lut_nb)
            .map(|_| {
                let prog = &self.0.borrow().prog;
                let var = prog.borrow_mut().new_var(prog.clone());
                var
            })
            .collect::<Vec<_>>();

        // Construct tfhe params
        let tfhe_params = self.0.borrow().prog.params().clone().into();

        // Deferred to default logic
        Self::pbs_raw(
            &out_vec.iter().collect::<Vec<_>>(),
            self,
            lut,
            flush,
            &tfhe_params,
        );
        out_vec
    }

    // TODO define bivariant version of Pbs
}

/// Implement mac operator
impl MetaVarCell {
    /// Raw Mac implementation
    /// MAC output= (rhs_0 * mul_factor) + rhs_1
    pub(super) fn mac_raw(
        &self,
        rhs_0: &MetaVarCell,
        mul_factor: u8,
        rhs_1: &MetaVarCell,
    ) -> StmtLink {
        // Check operand type
        assert!(
            rhs_0.is_in(PosKind::REG | PosKind::MEM | PosKind::IMM),
            "Add src must be of kind Reg|Mem|IMM MetaVar"
        );
        assert!(
            rhs_1.is_in(PosKind::REG | PosKind::MEM | PosKind::IMM),
            "Add src must be of kind Reg|Mem|IMM MetaVar"
        );
        assert!(
            mul_factor
                <= (1
                    << (rhs_0.0.borrow().prog.params().carry_w
                        + rhs_0.0.borrow().prog.params().msg_w)),
            "mul_factor must be <= carry_mask to prevent overflow"
        );

        // Move variables to registers if needed
        rhs_0.reg_alloc_mv();
        rhs_1.reg_alloc_mv();

        // Check rhs operands type and position
        let rhs_0_imm = rhs_0.is_in(PosKind::IMM);
        let rhs_1_imm = rhs_1.is_in(PosKind::IMM);

        match (rhs_0_imm, rhs_1_imm) {
            (false, false) => {
                // (Ct x Const) + Ct
                // -> dst must be in ALU
                self.reg_alloc_mv();
                let dst_rid = self.as_reg().unwrap();
                let rhs_rid = (rhs_0.as_reg().unwrap(), rhs_1.as_reg().unwrap());
                let degree = (rhs_0.get_degree() * mul_factor as usize) + rhs_1.get_degree();

                let asm = asm::dop::DOpMac::new(
                    dst_rid,
                    rhs_rid.0,
                    rhs_rid.1,
                    crate::asm::dop::MulFactor(mul_factor),
                )
                .into();

                self.updt_degree(degree);
                rhs_0.0.borrow_mut().prog.push_stmt(asm)
            }
            (false, true) => {
                // (Ct * Const) + Imm
                // -> dst must be in ALU
                // MAC anti-pattern, add comment in the generated stream
                self.0.borrow().prog.borrow_mut().stmts.push_comment(
                    "mac_raw anti-pattern. Expand on two DOps [Muls, Adds]".to_string(),
                );

                self.reg_alloc_mv();
                let dst_rid = self.as_reg().unwrap();
                let rhs_rid = rhs_0.as_reg().unwrap();
                let msg_cst = rhs_1.as_imm().unwrap();

                // First DOp -> Muls
                let mut degree = rhs_0.get_degree() * mul_factor as usize;
                self.0.borrow().prog.borrow_mut().stmts.push_stmt(
                    asm::dop::DOpMuls::new(dst_rid, rhs_rid, ImmId::Cst(mul_factor as u16)).into(),
                );

                // Second DOp -> Adds
                degree += match msg_cst {
                    ImmId::Cst(cst) => cst as usize,
                    ImmId::Var { .. } => {
                        let tfhe_params: asm::DigitParameters =
                            rhs_0.0.borrow().prog.borrow().params.clone().into();
                        tfhe_params.msg_mask()
                    }
                };
                self.updt_degree(degree);
                self.0
                    .borrow_mut()
                    .prog
                    .push_stmt(asm::dop::DOpAdds::new(dst_rid, dst_rid, msg_cst).into())
            }
            (true, false) => {
                // (Imm x Const) + Ct
                // -> dst must be in ALU
                self.reg_alloc_mv();
                let dst_rid = self.as_reg().unwrap();
                let rhs_rid = rhs_1.as_reg().unwrap();
                let msg_cst = rhs_0.as_imm().unwrap();

                match msg_cst {
                    asm::ImmId::Cst(imm) => {
                        // Imm x mul_factor could be computed offline
                        let msg_cst = imm * mul_factor as u16;
                        let degree = rhs_0.get_degree() + msg_cst as usize;

                        let asm =
                            asm::dop::DOpAdds::new(dst_rid, rhs_rid, asm::ImmId::Cst(msg_cst))
                                .into();

                        self.updt_degree(degree);
                        rhs_0.0.borrow_mut().prog.push_stmt(asm)
                    }
                    asm::ImmId::Var { .. } => {
                        // TODO add a warning, since it's not the native pattern expected by MAC ?
                        // Move templated constant in register and recurse
                        // Allocate extra register
                        // Force it's value to Imm::Var
                        let mut reg_0 = {
                            let prog = &self.0.borrow().prog;
                            let var = prog.borrow_mut().new_var(prog.clone());
                            var
                        };
                        reg_0.reg_alloc_mv();
                        reg_0.mv_assign(rhs_0);
                        self.mac_raw(&reg_0, mul_factor, rhs_1)
                    }
                }
            }
            (true, true) => {
                // (Imm x Const) + Imm -> compile time computation
                match (rhs_0.as_imm().unwrap(), rhs_1.as_imm().unwrap()) {
                    (ImmId::Cst(cst_a), ImmId::Cst(cst_b)) => {
                        // Compile time constant
                        let imm = cst_a + (cst_b * mul_factor as u16);
                        self.updt_pos(Some(VarPos::Imm(ImmId::Cst(imm))));
                        self.updt_degree(imm as usize);
                        StmtLink::empty(self.0.borrow().prog.clone())
                    }
                    (ImmId::Var { .. }, _) => {
                        // Move templated constant in register and recurse
                        // Allocate extra register
                        // Force it's value to Imm::Var
                        let mut reg_0 = {
                            let prog = &self.0.borrow().prog;
                            let var = prog.borrow_mut().new_var(prog.clone());
                            var
                        };
                        reg_0.reg_alloc_mv();
                        reg_0.mv_assign(rhs_0);
                        self.mac_raw(&reg_0, mul_factor, rhs_1)
                    }
                    (_, ImmId::Var { .. }) => {
                        // Move templated constant in register and recurse
                        // Allocate extra register
                        // Force it's value to Imm::Var
                        let mut reg_1 = {
                            let prog = &self.0.borrow().prog;
                            let var = prog.borrow_mut().new_var(prog.clone());
                            var
                        };
                        reg_1.reg_alloc_mv();
                        reg_1.mv_assign(rhs_1);
                        self.mac_raw(rhs_0, mul_factor, &reg_1)
                    }
                }
            }
        }
    }

    pub fn pack_carry(&self, msb: &MetaVarCell) -> MetaVarCell {
        let tfhe_params: asm::DigitParameters = self.0.borrow().prog.params().clone().into();
        msb.mac(tfhe_params.msg_range() as u8, self)
    }

    pub fn mac(&self, mul_factor: u8, rhs: &MetaVarCell) -> MetaVarCell {
        // Allocate output variable
        let dst = {
            let prog = &self.0.borrow().prog;
            let var = prog.borrow_mut().new_var(prog.clone());
            var
        };
        MetaVarCell::mac_raw(&dst, self, mul_factor, rhs);
        dst
    }

    pub fn mac_assign(&mut self, mul_factor: u8, rhs: &MetaVarCell) {
        MetaVarCell::mac_raw(self, self, mul_factor, rhs);
    }
}

/// Implement move operator
impl MetaVarCell {
    /// Move around value
    /// Support following configuration
    ///  * Reg <- Reg|Mem|Imm
    ///  * Mem <- Reg
    ///  * Uninit <- Reg|Mem|Imm
    ///
    /// NB: Option Mem <- Mem isn't provided.
    ///   Indeed, this operation induce useless LD/ST and could be replaced by
    //    MetaVarCell swapping [0 cost at runtime]
    pub fn mv_assign(&mut self, rhs: &Self) {
        // Case of self is uninit => Alloc and same as Reg
        if self.is_in(PosKind::empty()) {
            self.reg_alloc_mv();
        }

        let self_pos = self.get_pos();
        let rhs_pos = rhs.get_pos();

        match (self_pos, rhs_pos) {
            (PosKind::REG, PosKind::REG) => {
                let dst = self.as_reg().unwrap();
                let src = rhs.as_reg().unwrap();
                let inner = self.0.borrow();
                let mut prog = inner.prog.borrow_mut();
                //Update reg cache
                prog.reg_access(src);
                prog.reg_access(dst);
                let asm = asm::dop::DOpAdds::new(dst, src, asm::ImmId::Cst(0)).into();

                prog.stmts.push_stmt(asm);
            }
            (PosKind::REG, PosKind::MEM) => {
                let dst = self.as_reg().unwrap();
                let src = rhs.as_mem().unwrap();
                assert!(
                    !matches!(src, asm::MemId::Dst { .. }),
                    "Load from UserDst register"
                );
                let asm: DOp = asm::dop::DOpLd::new(dst, src).into();
                self.0.borrow().prog.borrow_mut().stmts.push_stmt(asm);
            }
            (PosKind::REG, PosKind::IMM) => {
                // Way to Trivial encrypt Imm is to do:
                // A <- A - A
                // A <- A + Imm

                let dst = self.as_reg().unwrap();
                let imm = rhs.as_imm().unwrap();
                let inner = self.0.borrow();
                let mut prog = inner.prog.borrow_mut();
                prog.stmts
                    .push_stmt(asm::dop::DOpSub::new(dst, dst, dst).into());
                prog.stmts
                    .push_stmt(asm::dop::DOpAdds::new(dst, dst, imm).into());
            }
            (PosKind::MEM, PosKind::REG) => {
                let dst = self.as_mem().unwrap();
                let src = rhs.as_reg().unwrap();
                assert!(
                    !matches!(dst, asm::MemId::Src { .. }),
                    "Store into UserSrc register"
                );

                // Update heap if required
                self.0.borrow().prog.borrow_mut().heap_access(dst);
                let asm: DOp = asm::dop::DOpSt::new(dst, src).into();
                self.0.borrow().prog.borrow_mut().stmts.push_stmt(asm);
            }
            _ => panic!("Unsupported MOVE {self:?} <- {rhs:?}"),
        }
        // Update degree
        self.updt_degree(rhs.get_degree());
    }
}

/// Overload <<= for syntaxic sugar around it
impl ShlAssign for MetaVarCell {
    fn shl_assign(&mut self, rhs: Self) {
        self.mv_assign(&rhs)
    }
}

/// Implement raw addition and derive Add/AddAsign from it
impl MetaVarCell {
    pub(super) fn add_raw(
        &self,
        rhs_0: &MetaVarCell,
        rhs_1: &MetaVarCell,
        upd_degree: bool,
    ) -> StmtLink {
        // Check operand type
        assert!(
            rhs_0.is_in(PosKind::REG | PosKind::MEM | PosKind::IMM),
            "Add src must be of kind Reg|Mem|IMM MetaVar"
        );
        assert!(
            rhs_1.is_in(PosKind::REG | PosKind::MEM | PosKind::IMM),
            "Add src must be of kind Reg|Mem|IMM MetaVar"
        );

        // Move variables to registers if required
        rhs_0.reg_alloc_mv();
        rhs_1.reg_alloc_mv();

        // Check rhs operands type and position
        let rhs_0_imm = rhs_0.is_in(PosKind::IMM);
        let rhs_1_imm = rhs_1.is_in(PosKind::IMM);

        let link = match (rhs_0_imm, rhs_1_imm) {
            (false, false) => {
                // Ct x Ct
                // -> dst must be in ALU
                self.reg_alloc_mv();
                let dst_rid = self.as_reg().unwrap();
                let rhs_rid = (rhs_0.as_reg().unwrap(), rhs_1.as_reg().unwrap());
                let degree = rhs_0.get_degree() + rhs_1.get_degree();

                let asm = asm::dop::DOpAdd::new(dst_rid, rhs_rid.0, rhs_rid.1).into();

                if upd_degree {
                    self.updt_degree(degree);
                }
                rhs_0.0.borrow_mut().prog.push_stmt(asm)
            }
            (false, true) => {
                // Ct x Imm
                // -> dst must be in ALU
                self.reg_alloc_mv();
                let dst_rid = self.as_reg().unwrap();
                let rhs_rid = rhs_0.as_reg().unwrap();
                let msg_cst = rhs_1.as_imm().unwrap();
                let degree = match msg_cst {
                    ImmId::Cst(cst) => rhs_0.get_degree() + cst as usize,
                    ImmId::Var { .. } => {
                        let tfhe_params: asm::DigitParameters =
                            rhs_1.0.borrow().prog.borrow().params.clone().into();
                        rhs_0.get_degree() + tfhe_params.msg_mask()
                    }
                };

                let asm = asm::dop::DOpAdds::new(dst_rid, rhs_rid, msg_cst).into();
                if upd_degree {
                    self.updt_degree(degree);
                }
                rhs_0.0.borrow_mut().prog.push_stmt(asm)
            }
            (true, false) => {
                // Imm x Ct
                // -> dst must be in ALU
                self.reg_alloc_mv();
                let dst_rid = self.as_reg().unwrap();
                let rhs_rid = rhs_1.as_reg().unwrap();
                let msg_cst = rhs_0.as_imm().unwrap();
                // let degree = rhs_1.get_degree() + msg_cst;
                let degree = match msg_cst {
                    ImmId::Cst(cst) => rhs_1.get_degree() + cst as usize,
                    ImmId::Var { .. } => {
                        let tfhe_params: asm::DigitParameters =
                            rhs_0.0.borrow().prog.borrow().params.clone().into();
                        rhs_1.get_degree() + tfhe_params.msg_mask()
                    }
                };

                if upd_degree {
                    self.updt_degree(degree);
                }

                let asm = asm::dop::DOpAdds::new(dst_rid, rhs_rid, msg_cst).into();
                rhs_0.0.borrow_mut().prog.push_stmt(asm)
            }
            (true, true) => {
                // Imm x Imm -> Check if this could be a compiled time constant
                match (rhs_0.as_imm().unwrap(), rhs_1.as_imm().unwrap()) {
                    (ImmId::Cst(cst_a), ImmId::Cst(cst_b)) => {
                        // Compile time constant
                        let imm = cst_a + cst_b;
                        self.updt_pos(Some(VarPos::Imm(ImmId::Cst(imm))));
                        if upd_degree {
                            self.updt_degree(imm as usize);
                        }
                        StmtLink::empty(self.0.borrow().prog.clone())
                    }
                    (ImmId::Var { .. }, _) => {
                        // Move templated constant in register and recurse
                        // Allocate extra register
                        // Force it's value to Imm::Var
                        let mut reg_0 = {
                            let prog = &self.0.borrow().prog;
                            let var = prog.borrow_mut().new_var(prog.clone());
                            var
                        };
                        reg_0.reg_alloc_mv();
                        reg_0.mv_assign(rhs_0);
                        self.add_raw(&reg_0, rhs_1, upd_degree)
                    }
                    (_, ImmId::Var { .. }) => {
                        // Move templated constant in register and recurse
                        // Allocate extra register
                        // Force it's value to Imm::Var
                        let mut reg_1 = {
                            let prog = &self.0.borrow().prog;
                            let var = prog.borrow_mut().new_var(prog.clone());
                            var
                        };
                        reg_1.reg_alloc_mv();
                        reg_1.mv_assign(rhs_1);
                        self.add_raw(rhs_0, &reg_1, upd_degree)
                    }
                }
            }
        };
        trace!(
            target: "MetaOp",
            "AddRaw:: {:?} <= {:?}, {:?}",
            self.0.borrow(),
            rhs_0.0.borrow(),
            rhs_1.0.borrow()
        );
        self.check_degree();
        link
    }
}

impl Add for &MetaVarCell {
    type Output = MetaVarCell;

    fn add(self, rhs: Self) -> Self::Output {
        // Allocate output variable
        let dst = {
            let prog = &self.0.borrow().prog;
            let var = prog.borrow_mut().new_var(prog.clone());
            var
        };

        MetaVarCell::add_raw(&dst, self, rhs, true);
        dst
    }
}

impl AddAssign for MetaVarCell {
    fn add_assign(&mut self, rhs: Self) {
        Self::add_raw(self, self, &rhs, true);
    }
}

/// Implement raw subtraction and derive Sub/SubAssign from it
impl MetaVarCell {
    pub(super) fn sub_raw(
        &self,
        rhs_0: &MetaVarCell,
        rhs_1: &MetaVarCell,
        upd_degree: bool,
    ) -> StmtLink {
        // Check operand type
        assert!(
            rhs_0.is_in(PosKind::REG | PosKind::MEM | PosKind::IMM),
            "Sub src must be of kind Reg|Mem|IMM MetaVar"
        );
        assert!(
            rhs_1.is_in(PosKind::REG | PosKind::MEM | PosKind::IMM),
            "Sub src must be of kind Reg|Mem|IMM MetaVar"
        );

        // Move variables to registers if required
        rhs_0.reg_alloc_mv();
        rhs_1.reg_alloc_mv();

        // Check rhs operands type and position
        let rhs_0_imm = rhs_0.is_in(PosKind::IMM);
        let rhs_1_imm = rhs_1.is_in(PosKind::IMM);

        let link = match (rhs_0_imm, rhs_1_imm) {
            (false, false) => {
                // Ct x Ct
                // -> dst must be in ALU
                self.reg_alloc_mv();
                let dst_rid = self.as_reg().unwrap();
                let rhs_rid = (rhs_0.as_reg().unwrap(), rhs_1.as_reg().unwrap());
                let degree = rhs_0.get_degree() - rhs_1.get_degree();

                if upd_degree {
                    self.updt_degree(degree);
                }

                let asm = asm::dop::DOpSub::new(dst_rid, rhs_rid.0, rhs_rid.1).into();
                rhs_0.0.borrow_mut().prog.push_stmt(asm)
            }
            (false, true) => {
                // Ct x Imm
                // -> dst must be in ALU
                self.reg_alloc_mv();
                let dst_rid = self.as_reg().unwrap();
                let rhs_rid = rhs_0.as_reg().unwrap();
                let msg_cst = rhs_1.as_imm().unwrap();
                let degree = match msg_cst {
                    ImmId::Cst(cst) => rhs_0.get_degree() - cst as usize,
                    ImmId::Var { .. } => {
                        let tfhe_params: asm::DigitParameters =
                            rhs_1.0.borrow().prog.borrow().params.clone().into();
                        rhs_0.get_degree() - tfhe_params.msg_mask()
                    }
                };

                if upd_degree {
                    self.updt_degree(degree);
                }
                rhs_0
                    .0
                    .borrow_mut()
                    .prog
                    .push_stmt(asm::dop::DOpSubs::new(dst_rid, rhs_rid, msg_cst).into())
            }
            (true, false) => {
                // Imm x Ct
                // -> dst must be in ALU
                self.reg_alloc_mv();
                let dst_rid = self.as_reg().unwrap();
                let rhs_rid = rhs_1.as_reg().unwrap();
                let msg_cst = rhs_0.as_imm().unwrap();
                let degree = match msg_cst {
                    ImmId::Cst(cst) => cst as usize - rhs_1.get_degree(),
                    ImmId::Var { .. } => {
                        let tfhe_params: asm::DigitParameters =
                            rhs_0.0.borrow().prog.borrow().params.clone().into();
                        tfhe_params.msg_mask() - rhs_0.get_degree()
                    }
                };

                if upd_degree {
                    self.updt_degree(degree);
                }

                rhs_0
                    .0
                    .borrow_mut()
                    .prog
                    .push_stmt(asm::dop::DOpSsub::new(dst_rid, rhs_rid, msg_cst).into())
            }
            (true, true) => {
                // Imm x Imm -> Check if this could be a compiled time constant
                match (rhs_0.as_imm().unwrap(), rhs_1.as_imm().unwrap()) {
                    (ImmId::Cst(cst_a), ImmId::Cst(cst_b)) => {
                        // Compile time constant
                        let imm = cst_a - cst_b;
                        self.updt_pos(Some(VarPos::Imm(ImmId::Cst(imm))));
                        self.updt_degree(imm as usize);
                        StmtLink::empty(self.0.borrow().prog.clone())
                    }
                    (ImmId::Var { .. }, _) => {
                        // Move templated constant in register and recurse
                        // Allocate extra register
                        // Force it's value to Imm::Var
                        let mut reg_0 = {
                            let prog = &self.0.borrow().prog;
                            let var = prog.borrow_mut().new_var(prog.clone());
                            var
                        };
                        reg_0.reg_alloc_mv();
                        reg_0.mv_assign(rhs_0);
                        self.sub_raw(&reg_0, rhs_1, upd_degree)
                    }
                    (_, ImmId::Var { .. }) => {
                        // Move templated constant in register and recurse
                        // Allocate extra register
                        // Force it's value to Imm::Var
                        let mut reg_1 = {
                            let prog = &self.0.borrow().prog;
                            let var = prog.borrow_mut().new_var(prog.clone());
                            var
                        };
                        reg_1.reg_alloc_mv();
                        reg_1.mv_assign(rhs_1);
                        self.sub_raw(rhs_0, &reg_1, upd_degree)
                    }
                }
            }
        };
        trace!(
            target: "MetaOp",
            "SubRaw:: {:?} <= {:?}, {:?}",
            self.0.borrow(),
            rhs_0.0.borrow(),
            rhs_1.0.borrow()
        );
        self.check_degree();
        link
    }
}

impl Sub for &MetaVarCell {
    type Output = MetaVarCell;

    fn sub(self, rhs: Self) -> Self::Output {
        // Allocate output variable
        let dst = {
            let prog = &self.0.borrow().prog;
            let var = prog.borrow_mut().new_var(prog.clone());
            var
        };

        dst.sub_raw(self, rhs, true);
        dst
    }
}

impl SubAssign for MetaVarCell {
    fn sub_assign(&mut self, rhs: Self) {
        self.sub_raw(self, &rhs, true);
    }
}
/// Implement raw subtraction and derive Mul/MulAssign from it
impl MetaVarCell {
    fn mul_raw(dst: &MetaVarCell, rhs_0: &MetaVarCell, rhs_1: &MetaVarCell) {
        // Check operand type
        assert!(
            rhs_0.is_in(PosKind::REG | PosKind::MEM | PosKind::IMM),
            "Mul src must be of kind Reg|Mem|IMM MetaVar"
        );
        assert!(
            rhs_1.is_in(PosKind::REG | PosKind::MEM | PosKind::IMM),
            "Mul src must be of kind Reg|Mem|IMM MetaVar"
        );

        // Move variables to registers if needed
        rhs_0.reg_alloc_mv();
        rhs_1.reg_alloc_mv();

        // Check rhs operands type and position
        let rhs_0_imm = rhs_0.is_in(PosKind::IMM);
        let rhs_1_imm = rhs_1.is_in(PosKind::IMM);

        match (rhs_0_imm, rhs_1_imm) {
            (false, false) => {
                error!("Try to multiply two Ciphertext together. This is not supported by TFHE, used Pbs instead");
                debug!(target: "Fw", "{rhs_0:?} x {rhs_1:?}");
                panic!("Invalid operation on MetaVar");
            }
            (false, true) => {
                // Ct x Imm
                // -> dst must be in ALU
                dst.reg_alloc_mv();
                let dst_rid = dst.as_reg().unwrap();
                let rhs_rid = rhs_0.as_reg().unwrap();
                let msg_cst = rhs_1.as_imm().unwrap();
                let degree = match msg_cst {
                    ImmId::Cst(cst) => rhs_0.get_degree() * cst as usize,
                    ImmId::Var { .. } => {
                        let tfhe_params: asm::DigitParameters =
                            rhs_1.0.borrow().prog.borrow().params.clone().into();
                        rhs_0.get_degree() * tfhe_params.msg_mask()
                    }
                };

                rhs_0
                    .0
                    .borrow()
                    .prog
                    .borrow_mut()
                    .stmts
                    .push_stmt(asm::dop::DOpMuls::new(dst_rid, rhs_rid, msg_cst).into());
                dst.updt_degree(degree);
            }
            (true, false) => {
                // Imm x Ct
                // -> dst must be in ALU
                dst.reg_alloc_mv();
                let dst_rid = dst.as_reg().unwrap();
                let rhs_rid = rhs_1.as_reg().unwrap();
                let msg_cst = rhs_0.as_imm().unwrap();
                let degree = match msg_cst {
                    ImmId::Cst(cst) => rhs_1.get_degree() * cst as usize,
                    ImmId::Var { .. } => {
                        let tfhe_params: asm::DigitParameters =
                            rhs_0.0.borrow().prog.borrow().params.clone().into();
                        rhs_1.get_degree() + tfhe_params.msg_mask()
                    }
                };

                rhs_0
                    .0
                    .borrow()
                    .prog
                    .borrow_mut()
                    .stmts
                    .push_stmt(asm::dop::DOpMuls::new(dst_rid, rhs_rid, msg_cst).into());
                dst.updt_degree(degree);
            }
            (true, true) => {
                // Imm x Imm -> Check if this could be a compiled time constant
                match (rhs_0.as_imm().unwrap(), rhs_1.as_imm().unwrap()) {
                    (ImmId::Cst(cst_a), ImmId::Cst(cst_b)) => {
                        // Compile time constant
                        let imm = cst_a * cst_b;
                        dst.updt_pos(Some(VarPos::Imm(ImmId::Cst(imm))));
                        dst.updt_degree(imm as usize);
                    }
                    (ImmId::Var { .. }, _) => {
                        // Move templated constant in register and recurse
                        // Allocate extra register
                        // Force it's value to Imm::Var
                        let mut reg_0 = {
                            let prog = &dst.0.borrow().prog;
                            let var = prog.borrow_mut().new_var(prog.clone());
                            var
                        };
                        reg_0.reg_alloc_mv();
                        reg_0.mv_assign(rhs_0);
                        Self::mul_raw(dst, &reg_0, rhs_1)
                    }
                    (_, ImmId::Var { .. }) => {
                        // Move templated constant in register and recurse
                        // Allocate extra register
                        // Force it's value to Imm::Var
                        let mut reg_1 = {
                            let prog = &dst.0.borrow().prog;
                            let var = prog.borrow_mut().new_var(prog.clone());
                            var
                        };
                        reg_1.reg_alloc_mv();
                        reg_1.mv_assign(rhs_1);
                        Self::mul_raw(dst, rhs_0, &reg_1)
                    }
                }
            }
        }
        trace!(
            target: "MetaOp",
            "MulRaw:: {:?} <= {:?}, {:?}",
            dst.0.borrow(),
            rhs_0.0.borrow(),
            rhs_1.0.borrow()
        );
        dst.check_degree();
    }

    pub fn mul(&self, rhs_0: &MetaVarCell, rhs_1: &MetaVarCell) {
        Self::mul_raw(self, rhs_0, rhs_1)
    }
}

impl Mul for &MetaVarCell {
    type Output = MetaVarCell;

    fn mul(self, rhs: Self) -> Self::Output {
        // Allocate output variable
        let dst = {
            let prog = &self.0.borrow().prog;
            let var = prog.borrow_mut().new_var(prog.clone());
            var
        };
        MetaVarCell::mul_raw(&dst, self, rhs);
        dst
    }
}

impl MulAssign for MetaVarCell {
    fn mul_assign(&mut self, rhs: Self) {
        Self::mul_raw(self, self, &rhs);
    }
}

// Utilities for finer register control
impl MetaVarCell {
    pub(super) fn reg_lock(&mut self) -> RegLockPtr {
        let rid = self.as_reg();
        let mut inner = self.0.borrow_mut();

        inner
            .reg_lock
            .as_ref()
            .map(|lock| lock.into())
            .unwrap_or_else(|| {
                rid.map(|rid| {
                    trace!(target: "MetaOp", "Locking register {}", rid);
                    inner.prog.reg_pop(&rid);
                    let lock_ptr = RegLockPtr::from(RegLock(self.clone()));
                    inner.reg_lock = Some((&lock_ptr).into());
                    lock_ptr
                })
                .unwrap_or(RegLockPtr(None))
            })
    }
}
