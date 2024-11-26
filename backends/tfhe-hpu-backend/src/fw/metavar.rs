//!
//! Abstraction over Digit
//! Enable to write code that translate into firmwave in an easy-way
//!
//! Wrap asm::Arg with metadata and overload std::ops on it

use super::*;

use crate::asm::dop::DOp;
use crate::asm::{self, DigitParameters, ImmId, PbsLut};
use tracing::{debug, error, trace, warn};

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

/// Wrap asm::Arg with metadata
/// asm::Arg is used to know position of the associated value
#[derive(Clone)]
struct MetaVar {
    prog: Rc<RefCell<program::ProgramInner>>,
    #[allow(unused)]
    uid: usize,
    pos: Option<VarPos>,
    degree: usize,
}

/// Don't show ref to prog in Debug message
impl std::fmt::Debug for MetaVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MetaVar{{pos: {:?}, degree: {}}}", self.pos, self.degree)
    }
}

impl Drop for MetaVar {
    fn drop(&mut self) {
        trace!(target: "MetaDrop", "Drop::{self:?}");
        if let Some(pos) = &self.pos {
            let mut prog = self.prog.borrow_mut();
            // Release ressource attached to inner
            match pos {
                VarPos::Reg(rid) => {
                    trace!(target: "MetaDrop", "Release Reg {rid}");
                    prog.reg_release(*rid);
                }

                VarPos::Mem(mid) => {
                    trace!(target: "MetaDrop", "Release Heap {mid}");
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
#[derive(Debug, Clone)]
pub struct MetaVarCell(Rc<RefCell<MetaVar>>);

impl From<&MetaVarCell> for MetaVarCellWeak {
    fn from(value: &MetaVarCell) -> Self {
        Self(std::rc::Rc::downgrade(&(value.0)))
    }
}

/// MetaVarCell Constructors
impl MetaVarCell {
    pub fn new(
        prog: Rc<RefCell<program::ProgramInner>>,
        uid: usize,
        from: Option<VarPos>,
        tfhe_params: DigitParameters,
    ) -> Self {
        let degree = if let Some(pos) = from.as_ref() {
            match pos {
                VarPos::Reg(_) | VarPos::Mem(_) | VarPos::Imm(_) => tfhe_params.msg_mask(),
                VarPos::Pbs(lut) => lut.degree(&tfhe_params, tfhe_params.msg_mask()),
            }
        } else {
            0
        };
        let metavar = MetaVar {
            prog,
            uid,
            pos: from,
            degree,
        };

        Self(Rc::new(RefCell::new(metavar)))
    }
}

/// MetaVarCell Reg/Heap management
impl MetaVarCell {
    /// Allocate in register and moved MetaVar content if any
    /// In case of register eviction, this function handle the offloading in memory
    pub(super) fn reg_alloc_mv(&self) {
        // Early return if already in Reg or Imm like var
        if self.is_in(PosKind::REG) {
            // Update LRU and return
            self.0
                .borrow()
                .prog
                .borrow_mut()
                .reg_access(self.as_reg().unwrap());
            return;
        } else if self.is_in(PosKind::IMM | PosKind::PBS) {
            return;
        }

        // Get cache entry and update state
        let (rid, evicted) = self.0.borrow().prog.borrow_mut().reg_swap_lru(self.clone());

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
        debug!(target: "Fw", "Evict {self:?} in heap");

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

    /// Update MetaVar position
    fn updt_pos(&self, pos: Option<VarPos>) {
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
            let msg_w = self.0.borrow().prog.borrow().params.msg_w;
            let carry_w = self.0.borrow().prog.borrow().params.carry_w;
            (1 << (msg_w + carry_w + 1/* padding */)) - 1
        };

        assert!(self.get_degree() <= max_degree)
    }
}

/// Utilities for uncheck field extraction
impl MetaVarCell {
    fn as_reg(&self) -> Option<asm::RegId> {
        if let Some(VarPos::Reg(id)) = self.0.borrow().pos {
            Some(id)
        } else {
            None
        }
    }

    fn as_mem(&self) -> Option<asm::MemId> {
        if let Some(VarPos::Mem(mid)) = self.0.borrow().pos {
            Some(mid)
        } else {
            None
        }
    }

    fn as_imm(&self) -> Option<asm::ImmId> {
        if let Some(VarPos::Imm(val)) = self.0.borrow().pos {
            Some(val)
        } else {
            None
        }
    }

    fn as_pbs(&self) -> Option<asm::Pbs> {
        if let Some(VarPos::Pbs(lut)) = self.0.borrow().pos.as_ref() {
            Some(lut.clone())
        } else {
            None
        }
    }
}

impl MetaVarCell {
    fn pbs_raw(
        dst: &MetaVarCell,
        src: &MetaVarCell,
        lut: &MetaVarCell,
        flush: bool,
        tfhe_params: &DigitParameters,
    ) {
        // Check operand type
        assert!(
            dst.is_in(PosKind::REG | PosKind::MEM),
            "Pbs dst must be of kind Reg|Mem MetaVar"
        );

        assert!(
            src.is_in(PosKind::REG | PosKind::MEM),
            "Pbs src must be of kind Reg|Mem MetaVar"
        );

        assert!(
            lut.is_in(PosKind::PBS),
            "Pbs lut must be of kind Reg|Mem MetaVar"
        );

        // Enforce that operand are in Register
        dst.reg_alloc_mv();
        src.reg_alloc_mv();

        let dst_rid = dst.as_reg().unwrap();
        let src_rid = src.as_reg().unwrap();
        let pbs = lut.as_pbs().unwrap();
        let degree = pbs.degree(tfhe_params, src.get_degree());

        // Select between standard and flushed Pbs
        if flush {
            let asm = asm::dop::DOpPbsF::new(dst_rid, src_rid, pbs.gid()).into();
            dst.0.borrow().prog.borrow_mut().stmts.push_stmt(asm);
        } else {
            let asm = asm::dop::DOpPbs::new(dst_rid, src_rid, pbs.gid()).into();
            dst.0.borrow().prog.borrow_mut().stmts.push_stmt(asm);
        }

        dst.updt_degree(degree);
        trace!(
            target: "MetaOp",
            "PbsRaw:: {:?} <= {:?}, {:?}{}",
            dst.0.borrow(),
            src.0.borrow(),
            lut.0.borrow(),
            if flush { "[Flush]" } else { ""},
        );
        dst.check_degree();
    }

    pub fn pbs_assign(&mut self, lut: &MetaVarCell, flush: bool) {
        // Construct tfhe params
        let tfhe_params = self.0.borrow().prog.borrow().params.clone().into();
        // Deffered to default logic
        Self::pbs_raw(self, self, lut, flush, &tfhe_params);
    }

    pub fn pbs(&self, lut: &MetaVarCell, flush: bool) -> Self {
        // Allocate output variable
        let prog_clone = self.0.borrow().prog.clone();
        let out = self.0.borrow().prog.borrow_mut().new_var(prog_clone);
        // Allocate it in register
        out.reg_alloc_mv();

        // Construct tfhe params
        let tfhe_params = self.0.borrow().prog.borrow().params.clone().into();

        // Deffered to default logic
        Self::pbs_raw(&out, self, lut, flush, &tfhe_params);
        out
    }

    // TODO define bivariant version of Pbs
}

/// Implement mac operator
impl MetaVarCell {
    fn mac_raw(dst: &MetaVarCell, rhs_0: &MetaVarCell, mul_factor: u8, rhs_1: &MetaVarCell) {
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
            mul_factor <= (1 << rhs_0.0.borrow().prog.borrow().params.carry_w),
            "mul_factor must be <= carry_mask to prevent overflow"
        );

        // Check rhs operands type and position
        // And move them in ALU if required
        let rhs_0_imm = rhs_0.is_in(PosKind::IMM);
        let rhs_1_imm = rhs_1.is_in(PosKind::IMM);
        rhs_0.reg_alloc_mv();
        rhs_1.reg_alloc_mv();

        match (rhs_0_imm, rhs_1_imm) {
            (false, false) => {
                // Ct x Ct
                // -> dst must be in ALU
                dst.reg_alloc_mv();
                let dst_rid = dst.as_reg().unwrap();
                let rhs_rid = (rhs_0.as_reg().unwrap(), rhs_1.as_reg().unwrap());
                let degree = rhs_0.get_degree() + (rhs_1.get_degree() * mul_factor as usize);

                let asm = asm::dop::DOpMac::new(
                    dst_rid,
                    rhs_rid.0,
                    rhs_rid.1,
                    crate::asm::dop::MulFactor(mul_factor),
                )
                .into();

                rhs_0.0.borrow().prog.borrow_mut().stmts.push_stmt(asm);
                dst.updt_degree(degree);
            }
            (false, true) => {
                // Imm x Ct
                // -> dst must be in ALU
                warn!("mac_raw anti-pattern. Expand on two DOps [Muls, Adds]");

                dst.reg_alloc_mv();
                let dst_rid = dst.as_reg().unwrap();
                let rhs_rid = rhs_0.as_reg().unwrap();
                let msg_cst = rhs_1.as_imm().unwrap();

                // First DOp -> Muls
                let mut degree = rhs_0.get_degree() * mul_factor as usize;
                dst.0.borrow().prog.borrow_mut().stmts.push_stmt(
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
                dst.0
                    .borrow()
                    .prog
                    .borrow_mut()
                    .stmts
                    .push_stmt(asm::dop::DOpAdds::new(dst_rid, dst_rid, msg_cst).into());
                dst.updt_degree(degree);
            }
            (true, false) => {
                // Ct x Imm
                // -> dst must be in ALU
                dst.reg_alloc_mv();
                let dst_rid = dst.as_reg().unwrap();
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

                        rhs_0.0.borrow().prog.borrow_mut().stmts.push_stmt(asm);
                        dst.updt_degree(degree);
                    }
                    asm::ImmId::Var { .. } => {
                        // TODO add a warning, since it's not the native pattern expected by MAC ?
                        // Move templated constant in register and recurse
                        // Allocate extra register
                        // Force it's value to Imm::Var
                        let prog = dst.0.borrow().prog.clone();
                        let prog_clone = prog.clone();
                        let mut reg_0 = prog.borrow_mut().new_var(prog_clone);
                        reg_0.reg_alloc_mv();
                        reg_0.mv_assign(rhs_0);
                        Self::mac_raw(dst, &reg_0, mul_factor, rhs_1)
                    }
                }
            }
            (true, true) => {
                // Imm x Imm -> compile time computation
                match (rhs_0.as_imm().unwrap(), rhs_1.as_imm().unwrap()) {
                    (ImmId::Cst(cst_a), ImmId::Cst(cst_b)) => {
                        // Compile time constant
                        let imm = cst_a + (cst_b * mul_factor as u16);
                        dst.updt_pos(Some(VarPos::Imm(ImmId::Cst(imm))));
                        dst.updt_degree(imm as usize);
                    }
                    (ImmId::Var { .. }, _) => {
                        // Move templated constant in register and recurse
                        // Allocate extra register
                        // Force it's value to Imm::Var
                        let prog = dst.0.borrow().prog.clone();
                        let prog_clone = prog.clone();
                        let mut reg_0 = prog.borrow_mut().new_var(prog_clone);
                        reg_0.reg_alloc_mv();
                        reg_0.mv_assign(rhs_0);
                        Self::mac_raw(dst, &reg_0, mul_factor, rhs_1)
                    }
                    (_, ImmId::Var { .. }) => {
                        // Move templated constant in register and recurse
                        // Allocate extra register
                        // Force it's value to Imm::Var
                        let prog = dst.0.borrow().prog.clone();
                        let prog_clone = prog.clone();
                        let mut reg_1 = prog.borrow_mut().new_var(prog_clone);
                        reg_1.reg_alloc_mv();
                        reg_1.mv_assign(rhs_1);
                        Self::mac_raw(dst, rhs_0, mul_factor, &reg_1)
                    }
                }
            }
        }
        trace!(
            target: "MetaOp",
            "MacRaw:: {:?} <= {:?}*{mul_factor}+ {:?}",
            dst.0.borrow(),
            rhs_0.0.borrow(),
            rhs_1.0.borrow()
        );
        dst.check_degree();
    }

    pub fn mac(&self, mul_factor: u8, rhs: &MetaVarCell) -> MetaVarCell {
        // Allocate output variable
        let prog_clone = self.0.borrow().prog.clone();
        let dst = self.0.borrow().prog.borrow_mut().new_var(prog_clone);
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
    fn add_raw(dst: &MetaVarCell, rhs_0: &MetaVarCell, rhs_1: &MetaVarCell) {
        // Check operand type
        assert!(
            rhs_0.is_in(PosKind::REG | PosKind::MEM | PosKind::IMM),
            "Add src must be of kind Reg|Mem|IMM MetaVar"
        );
        assert!(
            rhs_1.is_in(PosKind::REG | PosKind::MEM | PosKind::IMM),
            "Add src must be of kind Reg|Mem|IMM MetaVar"
        );

        // Check rhs operands type and position
        // And move them in ALU if required
        let rhs_0_imm = rhs_0.is_in(PosKind::IMM);
        let rhs_1_imm = rhs_1.is_in(PosKind::IMM);
        rhs_0.reg_alloc_mv();
        rhs_1.reg_alloc_mv();

        match (rhs_0_imm, rhs_1_imm) {
            (false, false) => {
                // Ct x Ct
                // -> dst must be in ALU
                dst.reg_alloc_mv();
                let dst_rid = dst.as_reg().unwrap();
                let rhs_rid = (rhs_0.as_reg().unwrap(), rhs_1.as_reg().unwrap());
                let degree = rhs_0.get_degree() + rhs_1.get_degree();

                let asm = asm::dop::DOpAdd::new(dst_rid, rhs_rid.0, rhs_rid.1).into();

                rhs_0.0.borrow().prog.borrow_mut().stmts.push_stmt(asm);
                dst.updt_degree(degree);
            }
            (false, true) => {
                // Ct x Imm
                // -> dst must be in ALU
                dst.reg_alloc_mv();
                let dst_rid = dst.as_reg().unwrap();
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
                rhs_0.0.borrow().prog.borrow_mut().stmts.push_stmt(asm);
                dst.updt_degree(degree);
            }
            (true, false) => {
                // Imm x Ct
                // -> dst must be in ALU
                dst.reg_alloc_mv();
                let dst_rid = dst.as_reg().unwrap();
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

                let asm = asm::dop::DOpAdds::new(dst_rid, rhs_rid, msg_cst).into();
                rhs_0.0.borrow().prog.borrow_mut().stmts.push_stmt(asm);
                dst.updt_degree(degree);
            }
            (true, true) => {
                // Imm x Imm -> Check if this could be a compiled time constant
                match (rhs_0.as_imm().unwrap(), rhs_1.as_imm().unwrap()) {
                    (ImmId::Cst(cst_a), ImmId::Cst(cst_b)) => {
                        // Compile time constant
                        let imm = cst_a + cst_b;
                        dst.updt_pos(Some(VarPos::Imm(ImmId::Cst(imm))));
                        dst.updt_degree(imm as usize);
                    }
                    (ImmId::Var { .. }, _) => {
                        // Move templated constant in register and recurse
                        // Allocate extra register
                        // Force it's value to Imm::Var
                        let prog = dst.0.borrow().prog.clone();
                        let prog_clone = prog.clone();
                        let mut reg_0 = prog.borrow_mut().new_var(prog_clone);
                        reg_0.reg_alloc_mv();
                        reg_0.mv_assign(rhs_0);
                        Self::add_raw(dst, &reg_0, rhs_1)
                    }
                    (_, ImmId::Var { .. }) => {
                        // Move templated constant in register and recurse
                        // Allocate extra register
                        // Force it's value to Imm::Var
                        let prog = dst.0.borrow().prog.clone();
                        let prog_clone = prog.clone();
                        let mut reg_1 = prog.borrow_mut().new_var(prog_clone);
                        reg_1.reg_alloc_mv();
                        reg_1.mv_assign(rhs_1);
                        Self::add_raw(dst, rhs_0, &reg_1)
                    }
                }
            }
        }
        trace!(
            target: "MetaOp",
            "AddRaw:: {:?} <= {:?}, {:?}",
            dst.0.borrow(),
            rhs_0.0.borrow(),
            rhs_1.0.borrow()
        );
        dst.check_degree();
    }
}

impl Add for &MetaVarCell {
    type Output = MetaVarCell;

    fn add(self, rhs: Self) -> Self::Output {
        // Allocate output variable
        let prog_clone = self.0.borrow().prog.clone();
        let dst = self.0.borrow().prog.borrow_mut().new_var(prog_clone);

        MetaVarCell::add_raw(&dst, self, rhs);
        dst
    }
}

impl AddAssign for MetaVarCell {
    fn add_assign(&mut self, rhs: Self) {
        Self::add_raw(self, self, &rhs);
    }
}

/// Implement raw substraction and derive Sub/SubAssign from it
impl MetaVarCell {
    fn sub_raw(dst: &MetaVarCell, rhs_0: &MetaVarCell, rhs_1: &MetaVarCell) {
        // Check operand type
        assert!(
            rhs_0.is_in(PosKind::REG | PosKind::MEM | PosKind::IMM),
            "Sub src must be of kind Reg|Mem|IMM MetaVar"
        );
        assert!(
            rhs_1.is_in(PosKind::REG | PosKind::MEM | PosKind::IMM),
            "Sub src must be of kind Reg|Mem|IMM MetaVar"
        );

        // Check rhs operands type and position
        // And move them in ALU if required
        let rhs_0_imm = rhs_0.is_in(PosKind::IMM);
        let rhs_1_imm = rhs_1.is_in(PosKind::IMM);
        rhs_0.reg_alloc_mv();
        rhs_1.reg_alloc_mv();

        match (rhs_0_imm, rhs_1_imm) {
            (false, false) => {
                // Ct x Ct
                // -> dst must be in ALU
                dst.reg_alloc_mv();
                let dst_rid = dst.as_reg().unwrap();
                let rhs_rid = (rhs_0.as_reg().unwrap(), rhs_1.as_reg().unwrap());
                let degree = rhs_0.get_degree() - rhs_1.get_degree();

                let asm = asm::dop::DOpSub::new(dst_rid, rhs_rid.0, rhs_rid.1).into();
                rhs_0.0.borrow().prog.borrow_mut().stmts.push_stmt(asm);
                dst.updt_degree(degree);
            }
            (false, true) => {
                // Ct x Imm
                // -> dst must be in ALU
                dst.reg_alloc_mv();
                let dst_rid = dst.as_reg().unwrap();
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

                rhs_0
                    .0
                    .borrow()
                    .prog
                    .borrow_mut()
                    .stmts
                    .push_stmt(asm::dop::DOpSubs::new(dst_rid, rhs_rid, msg_cst).into());
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
                    ImmId::Cst(cst) => cst as usize - rhs_1.get_degree(),
                    ImmId::Var { .. } => {
                        let tfhe_params: asm::DigitParameters =
                            rhs_0.0.borrow().prog.borrow().params.clone().into();
                        tfhe_params.msg_mask() - rhs_0.get_degree()
                    }
                };

                rhs_0
                    .0
                    .borrow()
                    .prog
                    .borrow_mut()
                    .stmts
                    .push_stmt(asm::dop::DOpSsub::new(dst_rid, rhs_rid, msg_cst).into());
                dst.updt_degree(degree);
            }
            (true, true) => {
                // Imm x Imm -> Check if this could be a compiled time constant
                match (rhs_0.as_imm().unwrap(), rhs_1.as_imm().unwrap()) {
                    (ImmId::Cst(cst_a), ImmId::Cst(cst_b)) => {
                        // Compile time constant
                        let imm = cst_a - cst_b;
                        dst.updt_pos(Some(VarPos::Imm(ImmId::Cst(imm))));
                        dst.updt_degree(imm as usize);
                    }
                    (ImmId::Var { .. }, _) => {
                        // Move templated constant in register and recurse
                        // Allocate extra register
                        // Force it's value to Imm::Var
                        let prog = dst.0.borrow().prog.clone();
                        let prog_clone = prog.clone();
                        let mut reg_0 = prog.borrow_mut().new_var(prog_clone);
                        reg_0.reg_alloc_mv();
                        reg_0.mv_assign(rhs_0);
                        Self::sub_raw(dst, &reg_0, rhs_1)
                    }
                    (_, ImmId::Var { .. }) => {
                        // Move templated constant in register and recurse
                        // Allocate extra register
                        // Force it's value to Imm::Var
                        let prog = dst.0.borrow().prog.clone();
                        let prog_clone = prog.clone();
                        let mut reg_1 = prog.borrow_mut().new_var(prog_clone);
                        reg_1.reg_alloc_mv();
                        reg_1.mv_assign(rhs_1);
                        Self::sub_raw(dst, rhs_0, &reg_1)
                    }
                }
            }
        }
        trace!(
            target: "MetaOp",
            "SubRaw:: {:?} <= {:?}, {:?}",
            dst.0.borrow(),
            rhs_0.0.borrow(),
            rhs_1.0.borrow()
        );
        dst.check_degree();
    }
}

impl Sub for &MetaVarCell {
    type Output = MetaVarCell;

    fn sub(self, rhs: Self) -> Self::Output {
        // Allocate output variable
        let prog_clone = self.0.borrow().prog.clone();
        let dst = self.0.borrow().prog.borrow_mut().new_var(prog_clone);

        MetaVarCell::sub_raw(&dst, self, rhs);
        dst
    }
}

impl SubAssign for MetaVarCell {
    fn sub_assign(&mut self, rhs: Self) {
        Self::sub_raw(self, self, &rhs);
    }
}
/// Implement raw substraction and derive Mul/MulAssign from it
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

        // Check rhs operands type and position
        // And move them in ALU if required
        let rhs_0_imm = rhs_0.is_in(PosKind::IMM);
        let rhs_1_imm = rhs_1.is_in(PosKind::IMM);
        rhs_0.reg_alloc_mv();
        rhs_1.reg_alloc_mv();

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
                        let prog = dst.0.borrow().prog.clone();
                        let prog_clone = prog.clone();
                        let mut reg_0 = prog.borrow_mut().new_var(prog_clone);
                        reg_0.reg_alloc_mv();
                        reg_0.mv_assign(rhs_0);
                        Self::mul_raw(dst, &reg_0, rhs_1)
                    }
                    (_, ImmId::Var { .. }) => {
                        // Move templated constant in register and recurse
                        // Allocate extra register
                        // Force it's value to Imm::Var
                        let prog = dst.0.borrow().prog.clone();
                        let prog_clone = prog.clone();
                        let mut reg_1 = prog.borrow_mut().new_var(prog_clone);
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
}

impl Mul for &MetaVarCell {
    type Output = MetaVarCell;

    fn mul(self, rhs: Self) -> Self::Output {
        // Allocate output variable
        let prog_clone = self.0.borrow().prog.clone();
        let dst = self.0.borrow().prog.borrow_mut().new_var(prog_clone);

        MetaVarCell::mul_raw(&dst, self, rhs);
        dst
    }
}

impl MulAssign for MetaVarCell {
    fn mul_assign(&mut self, rhs: Self) {
        Self::mul_raw(self, self, &rhs);
    }
}
