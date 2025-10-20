use super::*;

pub mod kogge;
pub mod vardeg;

use super::rtl::{Rtl, VarCell};
use kogge::{Carry, RippleCarry};
use vardeg::*;

use crate::asm::iop::opcode::*;
use crate::asm::{self, OperandKind, Pbs};
use crate::fw::metavar::MetaVarCell;
use crate::fw::program::Program;
use crate::pbs_by_name;
use fw_impl::ilp::{CondPos, ShiftKind};
use itertools::{EitherOrBoth, Itertools, Position};
use std::collections::HashMap;
use tracing::{instrument, trace};

crate::impl_fw!("Llt" [
    ADD => fw_impl::llt::iop_add;
    SUB => fw_impl::llt::iop_sub;
    MUL => fw_impl::llt::iop_mul;
    DIV => fw_impl::ilp_div::iop_div;
    MOD => fw_impl::ilp_div::iop_mod;

    // NB: fallback to ilp
    // TODO: Add dedicated llt implementation
    OVF_ADD => fw_impl::ilp::iop_overflow_add;
    OVF_SUB => fw_impl::ilp::iop_overflow_sub;
    OVF_MUL => fw_impl::ilp::iop_overflow_mul;

    ROT_R => fw_impl::llt::iop_rotate_right;
    ROT_L => fw_impl::llt::iop_rotate_left;
    SHIFT_R => fw_impl::llt::iop_shift_right;
    SHIFT_L => fw_impl::llt::iop_shift_left;

    ADDS => fw_impl::llt::iop_adds;
    SUBS => fw_impl::llt::iop_subs;
    SSUB => fw_impl::llt::iop_ssub;
    MULS => fw_impl::llt::iop_muls;
    DIVS => fw_impl::ilp_div::iop_divs;
    MODS => fw_impl::ilp_div::iop_mods;

    // NB: fallback to ilp
    // TODO: Add dedicated llt implementation
    ROTS_R => fw_impl::llt::iop_rotate_scalar_right;
    ROTS_L => fw_impl::llt::iop_rotate_scalar_left;
    SHIFTS_R => fw_impl::llt::iop_shift_scalar_right;
    SHIFTS_L => fw_impl::llt::iop_shift_scalar_left;

    // NB: fallback to ilp
    // TODO: Add dedicated llt implementation
    OVF_ADDS => fw_impl::ilp::iop_overflow_adds;
    OVF_SUBS => fw_impl::ilp::iop_overflow_subs;
    OVF_SSUB => fw_impl::ilp::iop_overflow_ssub;
    OVF_MULS => fw_impl::ilp::iop_overflow_muls;

    BW_AND       => (|prog| {fw_impl::ilp::iop_bw(prog, asm::dop::PbsBwAnd::default().into())});
    BW_OR        => (|prog| {fw_impl::ilp::iop_bw(prog, asm::dop::PbsBwOr::default().into())});
    BW_XOR       => (|prog| {fw_impl::ilp::iop_bw(prog, asm::dop::PbsBwXor::default().into())});

    CMP_GT       => (|prog| {fw_impl::llt::iop_cmp(prog, pbs_by_name!("CmpGtMrg"), pbs_by_name!("CmpGt"))});
    CMP_GTE      => (|prog| {fw_impl::llt::iop_cmp(prog, pbs_by_name!("CmpGteMrg"), pbs_by_name!("CmpGte"))});
    CMP_LT       => (|prog| {fw_impl::llt::iop_cmp(prog, pbs_by_name!("CmpLtMrg"), pbs_by_name!("CmpLt"))});
    CMP_LTE      => (|prog| {fw_impl::llt::iop_cmp(prog, pbs_by_name!("CmpLteMrg"), pbs_by_name!("CmpLte"))});
    CMP_EQ       => (|prog| {fw_impl::llt::iop_cmp(prog, pbs_by_name!("CmpEqMrg"), pbs_by_name!("CmpEq"))});
    CMP_NEQ      => (|prog| {fw_impl::llt::iop_cmp(prog, pbs_by_name!("CmpNeqMrg"), pbs_by_name!("CmpNeq"))});

    IF_THEN_ZERO => fw_impl::ilp::iop_if_then_zero;
    IF_THEN_ELSE => fw_impl::ilp::iop_if_then_else;

    ERC_20 => fw_impl::llt::iop_erc_20;
    MEMCPY => fw_impl::ilp::iop_memcpy;

    COUNT0 => fw_impl::ilp_log::iop_count0;
    COUNT1 => fw_impl::ilp_log::iop_count1;
    ILOG2 => fw_impl::ilp_log::iop_ilog2;
    LEAD0 => fw_impl::ilp_log::iop_lead0;
    LEAD1 => fw_impl::ilp_log::iop_lead1;
    TRAIL0 => fw_impl::ilp_log::iop_trail0;
    TRAIL1 => fw_impl::ilp_log::iop_trail1;

    // SIMD Implementations
    ADD_SIMD     => fw_impl::llt::iop_add_simd;
    ERC_20_SIMD  => fw_impl::llt::iop_erc_20_simd;
]);

// ----------------------------------------------------------------------------
// API
// ----------------------------------------------------------------------------

#[instrument(level = "trace", skip(prog))]
pub fn iop_add(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment("ADD Operand::Dst Operand::Src Operand::Src".to_string());
    iop_addx(prog, dst, src_a, src_b);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_add_simd(prog: &mut Program) {
    // Add Comment header
    prog.push_comment("ADD_SIMD Operand::Dst Operand::Src Operand::Src".to_string());
    simd(
        prog,
        crate::asm::iop::SIMD_N,
        fw_impl::llt::iop_add_ripple_rtl,
    );
}

pub fn iop_adds(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Imm, 0);

    // Add Comment header
    prog.push_comment("ADDS Operand::Dst Operand::Src Operand::Immediate".to_string());
    iop_addx(prog, dst, src_a, src_b);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_sub(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment("SUB Operand::Dst Operand::Src Operand::Src".to_string());
    iop_subx(prog, dst, src_a, src_b);
}

pub fn iop_subs(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Imm, 0);

    // Add Comment header
    prog.push_comment("SUBS Operand::Dst Operand::Src Operand::Immediate".to_string());
    iop_subx(prog, dst, src_a, src_b);
}

pub fn iop_ssub(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Imm, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Src, 0);

    // Add Comment header
    prog.push_comment("SSUB Operand::Dst Operand::Src Operand::Immediate".to_string());
    iop_subx(prog, dst, src_a, src_b);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_cmp(prog: &mut Program, mrg_op: Pbs, cmp_op: Pbs) {
    // Dest -> Operand
    let dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Operand
    let src_b = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment(format!(
        "CMP_{cmp_op} Operand::Dst Operand::Src Operand::Src"
    ));

    // Deferred implementation to generic cmpx function
    iop_cmpx(prog, &dst[0], &src_a, &src_b, mrg_op, cmp_op).add_to_prog(prog);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_mul(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment("MUL Operand::Dst Operand::Src Operand::Src".to_string());

    iop_mulx(prog, dst, src_a, src_b).add_to_prog(prog);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_muls(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Imm, 0);

    // Add Comment header
    prog.push_comment("MULS Operand::Dst Operand::Src Operand::Immediate".to_string());

    iop_mulx(prog, dst, src_a, src_b).add_to_prog(prog);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_erc_20(prog: &mut Program) {
    // Add Comment header
    prog.push_comment("ERC_20 (new_from, new_to) <- (from, to, amount)".to_string());
    iop_erc_20_rtl(prog, 0).add_to_prog(prog);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_erc_20_simd(prog: &mut Program) {
    // Add Comment header
    prog.push_comment("ERC_20_SIMD (new_from, new_to) <- (from, to, amount)".to_string());
    simd(prog, crate::asm::iop::SIMD_N, fw_impl::llt::iop_erc_20_rtl);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_shift_right(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let dst = VarCell::from_vec(prog.iop_template_var(OperandKind::Dst, 0));
    // Src -> Operand
    let src = VarCell::from_vec(prog.iop_template_var(OperandKind::Src, 0));
    // Amount -> Operand
    let amount = VarCell::from_vec(prog.iop_template_var(OperandKind::Src, 1));

    // Add Comment header
    prog.push_comment("SHIFT_R Operand::Dst Operand::Src Operand::Src".to_string());
    // Deferred implementation to generic rotx function
    iop_shiftrotx(prog, ShiftKind::ShiftRight, dst, src, amount).add_to_prog(prog);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_shift_left(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let dst = VarCell::from_vec(prog.iop_template_var(OperandKind::Dst, 0));
    // Src -> Operand
    let src = VarCell::from_vec(prog.iop_template_var(OperandKind::Src, 0));
    // ShiftAmount -> Operand
    let amount = VarCell::from_vec(prog.iop_template_var(OperandKind::Src, 1));

    // Add Comment header
    prog.push_comment("SHIFT_L Operand::Dst Operand::Src Operand::Src".to_string());
    // Deferred implementation to generic rotx function
    iop_shiftrotx(prog, ShiftKind::ShiftLeft, dst, src, amount).add_to_prog(prog);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_rotate_right(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let dst = VarCell::from_vec(prog.iop_template_var(OperandKind::Dst, 0));
    // Src -> Operand
    let src = VarCell::from_vec(prog.iop_template_var(OperandKind::Src, 0));
    // ShiftAmount -> Operand
    let rot_amount = VarCell::from_vec(prog.iop_template_var(OperandKind::Src, 1));

    // Add Comment header
    prog.push_comment("ROT_R Operand::Dst Operand::Src Operand::Src".to_string());
    // Deferred implementation to generic rotx function
    iop_shiftrotx(prog, ShiftKind::RotRight, dst, src, rot_amount).add_to_prog(prog);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_rotate_left(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let dst = VarCell::from_vec(prog.iop_template_var(OperandKind::Dst, 0));
    // Src -> Operand
    let src = VarCell::from_vec(prog.iop_template_var(OperandKind::Src, 0));
    // ShiftAmount -> Operand
    let rot_amount = VarCell::from_vec(prog.iop_template_var(OperandKind::Src, 1));

    // Add Comment header
    prog.push_comment("ROT_L Operand::Dst Operand::Src Operand::Src".to_string());
    // Deferred implementation to generic rotx function
    iop_shiftrotx(prog, ShiftKind::RotLeft, dst, src, rot_amount).add_to_prog(prog);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_shift_scalar_right(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let dst = VarCell::from_vec(prog.iop_template_var(OperandKind::Dst, 0));
    // Src -> Operand
    let src = VarCell::from_vec(prog.iop_template_var(OperandKind::Src, 0));
    // ShiftAmount -> Operand
    let amount = VarCell::from_vec(prog.iop_template_var(OperandKind::Imm, 0));

    // Add Comment header
    prog.push_comment("SHIFT_R Operand::Dst Operand::Src Immediate::Src".to_string());
    // Deferred implementation to generic rotx function
    iop_shiftrotx(prog, ShiftKind::ShiftRight, dst, src, amount).add_to_prog(prog);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_shift_scalar_left(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let dst = VarCell::from_vec(prog.iop_template_var(OperandKind::Dst, 0));
    // Src -> Operand
    let src = VarCell::from_vec(prog.iop_template_var(OperandKind::Src, 0));
    // ShiftAmount -> Operand
    let amount = VarCell::from_vec(prog.iop_template_var(OperandKind::Imm, 0));

    // Add Comment header
    prog.push_comment("SHIFT_L Operand::Dst Operand::Src Immediate::Src".to_string());
    // Deferred implementation to generic rotx function
    iop_shiftrotx(prog, ShiftKind::ShiftLeft, dst, src, amount).add_to_prog(prog);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_rotate_scalar_right(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let dst = VarCell::from_vec(prog.iop_template_var(OperandKind::Dst, 0));
    // Src -> Operand
    let src = VarCell::from_vec(prog.iop_template_var(OperandKind::Src, 0));
    // ShiftAmount -> Operand
    let rot_amount = VarCell::from_vec(prog.iop_template_var(OperandKind::Imm, 0));

    // Add Comment header
    prog.push_comment("ROT_R Operand::Dst Operand::Src Immediate::Src".to_string());
    // Deferred implementation to generic rotx function
    iop_shiftrotx(prog, ShiftKind::RotRight, dst, src, rot_amount).add_to_prog(prog);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_rotate_scalar_left(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let dst = VarCell::from_vec(prog.iop_template_var(OperandKind::Dst, 0));
    // Src -> Operand
    let src = VarCell::from_vec(prog.iop_template_var(OperandKind::Src, 0));
    // ShiftAmount -> Operand
    let rot_amount = VarCell::from_vec(prog.iop_template_var(OperandKind::Imm, 0));

    // Add Comment header
    prog.push_comment("ROT_L Operand::Dst Operand::Src Operand::Immediate".to_string());
    // Deferred implementation to generic rotx function
    iop_shiftrotx(prog, ShiftKind::RotLeft, dst, src, rot_amount).add_to_prog(prog);
}

// ----------------------------------------------------------------------------
// Helper Functions
// ----------------------------------------------------------------------------

/// Implement erc_20 fund xfer
/// Targeted algorithm is as follow:
/// 1. Check that from has enough funds
/// 2. Compute real_amount to xfer (i.e. amount or 0)
/// 3. Compute new amount (from - new_amount, to + new_amount)
///
/// The input operands are:
///     (from[0], to[0], amount[0], ..., from[N-1], to[N-1], amount[N-1])
/// The output operands are:
///     (dst_from[0], dst_to[0], ..., dst_from[N-1], dst_to[N-1])
/// Where N is the batch size
#[instrument(level = "trace", skip(prog))]
pub fn iop_erc_20_rtl(prog: &mut Program, batch_index: u8) -> Rtl {
    // Allocate metavariables:
    // Dest -> Operand
    let dst_from = prog.iop_template_var(OperandKind::Dst, 2 * batch_index);
    let dst_to = prog.iop_template_var(OperandKind::Dst, 2 * batch_index + 1);
    // Src -> Operand
    let src_from = prog.iop_template_var(OperandKind::Src, 3 * batch_index);
    let src_to = prog.iop_template_var(OperandKind::Src, 3 * batch_index + 1);
    // Src Amount -> Operand
    let src_amount = prog.iop_template_var(OperandKind::Src, 3 * batch_index + 2);

    // TODO: Make this a parameter or sweep this
    // All these little parameters would be very handy to write an
    // exploration/compilation program which would try to minimize latency by
    // playing with these.
    let kogge_blk_w = 10;
    let ripple = true;

    {
        let props = prog.params();
        let tfhe_params: asm::DigitParameters = props.clone().into();
        let lut = pbs_by_name!("IfFalseZeroed");
        let dst_to = VarCell::from_vec(dst_to);
        let dst_from = VarCell::from_vec(dst_from);
        let src_to = VarCell::from_vec(src_to);
        let src_from = VarCell::from_vec(src_from);
        let src_amount = VarCell::from_vec(src_amount);

        // Check if from has enough funds
        let enough_fund = iop_cmpx_rtl(
            prog,
            src_from.clone(),
            src_amount.clone(),
            pbs_by_name!("CmpGteMrg"),
            pbs_by_name!("CmpGte"),
        );

        let src_amount = src_amount
            .into_iter()
            .map(|x| {
                x.mac(tfhe_params.msg_range(), &enough_fund)
                    .pbs(&lut)
                    .into_iter()
                    .next()
                    .unwrap()
            })
            .collect::<Vec<_>>();

        if ripple {
            kogge::ripple_add(dst_to, src_to, src_amount.clone(), None)
                + kogge::ripple_sub(prog, dst_from, src_from, src_amount)
        } else {
            kogge::add(prog, dst_to, src_to, src_amount.clone(), None, kogge_blk_w)
                + kogge::sub(prog, dst_from, src_from, src_amount, kogge_blk_w)
        }
    }
}

/// A SIMD implementation of add for maximum throughput
#[instrument(level = "trace", skip(prog))]
pub fn iop_add_ripple_rtl(prog: &mut Program, i: u8) -> Rtl {
    // Allocate metavariables:
    let dst = prog.iop_template_var(OperandKind::Dst, i);
    let src_a = prog.iop_template_var(OperandKind::Src, 2 * i);
    let src_b = prog.iop_template_var(OperandKind::Src, 2 * i + 1);

    // Convert MetaVarCell in VarCell for Rtl analysis
    let a = VarCell::from_vec(src_a);
    let b = VarCell::from_vec(src_b);
    let d = VarCell::from_vec(dst);

    // Do a + b with the ripple carry adder
    kogge::ripple_add(d, a, b, None)
}

fn iop_addx(
    prog: &mut Program,
    dst: Vec<MetaVarCell>,
    src_a: Vec<MetaVarCell>,
    src_b: Vec<MetaVarCell>,
) {
    {
        // Convert MetaVarCell in VarCell for Rtl analysis
        let a = VarCell::from_vec(src_a);
        let b = VarCell::from_vec(src_b);
        // Do a + b with the kogge stone adder
        kogge::cached_add(prog, a, b, None, dst)
    } // Any reference to any metavar not linked to the RTL is dropped here
    .add_to_prog(prog);
}

fn iop_subx(
    prog: &mut Program,
    dst: Vec<MetaVarCell>,
    src_a: Vec<MetaVarCell>,
    src_b: Vec<MetaVarCell>,
) {
    {
        // Convert MetaVarCell in VarCell for Rtl analysis
        let a = VarCell::from_vec(src_a);
        let b = VarCell::from_vec(src_b);
        let b_inv = bw_inv(prog, b);
        let one = Carry::Ripple(RippleCarry(VarCell::from(prog.new_imm(1))));
        kogge::cached_add(prog, a, b_inv, Some(one), dst)
    }
    .add_to_prog(prog);
}

/// Generic mul operation for massively parallel HPUs
#[instrument(level = "trace", skip(prog))]
pub fn iop_mulx_par(
    prog: &mut Program,
    dst: Vec<metavar::MetaVarCell>,
    src_a: Vec<metavar::MetaVarCell>,
    src_b: Vec<metavar::MetaVarCell>,
) -> Rtl {
    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();
    let blk_w = props.blk_w();

    // Transform metavars into RTL vars
    let mut dst = VarCell::from_vec(dst);
    let src_a = VarCell::from_vec(src_a);
    let src_b = VarCell::from_vec(src_b);
    let max_deg = VarDeg {
        deg: props.max_val(),
        nu: props.nu,
    };

    let pbs_mul_lsb = pbs_by_name!("MultCarryMsgLsb");
    let pbs_mul_msb = pbs_by_name!("MultCarryMsgMsb");
    let max_carry = (props.max_msg() * props.max_msg()) >> props.msg_w;
    let max_msg = props.max_msg();

    let mut mul_map: HashMap<usize, Vec<VarCellDeg>> = HashMap::new();
    itertools::iproduct!(0..blk_w, 0..blk_w).for_each(|(i, j)| {
        let pp = src_a[i].mac(tfhe_params.msg_range(), &src_b[j]);
        let lsb = pp.single_pbs(&pbs_mul_lsb);
        let msb = pp.single_pbs(&pbs_mul_msb);
        mul_map
            .entry(i + j)
            .or_default()
            .push(VarCellDeg::new(max_msg, lsb));
        mul_map
            .entry(i + j + 1)
            .or_default()
            .push(VarCellDeg::new(max_carry, msb));
    });

    let mut pp: Vec<VecVarCellDeg> = (0..dst.len())
        .map(|i| mul_map.remove(&i).unwrap().into())
        .collect();

    // Reduce dada tree like
    while pp.iter().any(|x| x.len() > 1) {
        trace!(
            target: "llt::mul",
            "pp length: {:?}",
            pp.iter().map(|x| x.len()).collect::<Vec<_>>()
        );
        for c in (0..dst.len()).rev() {
            let mut col_len = pp[c].len();
            let mut reduced = Vec::new();
            let mut chunks = pp[c].deg_chunks(&max_deg).peekable();
            let max_col = if c == (dst.len() - 1) {
                0
            } else {
                dst.len() - 1
            };

            while chunks.peek().is_some() && col_len > pp[max_col].len() {
                let mut chunk = chunks.next().unwrap();
                let chunk_len = chunk.len();
                col_len -= chunk.len();

                // sum the chunk
                while chunk.len() > 1 {
                    chunk = chunk
                        .chunks(2)
                        .map(|chunk| match chunk.len() {
                            1 => chunk[0].clone(),
                            2 => &chunk[0] + &chunk[1],
                            _ => panic!("Invalid chunk size"),
                        })
                        .collect()
                }

                // And bootstrap if needed
                let element = chunk
                    .into_iter()
                    .next()
                    .map(|sum| {
                        assert!(sum.deg.nu <= props.nu);
                        if sum.deg == max_deg || chunk_len == 1 {
                            let (data, carry) = sum.bootstrap(&props);
                            if let (Some(carry), Some(elm)) = (carry, pp.get_mut(c + 1)) {
                                elm.push(carry);
                            }
                            data
                        } else {
                            sum
                        }
                    })
                    .unwrap();

                reduced.push(element);
            }

            pp[c] = reduced
                .into_iter()
                .chain(chunks.flatten())
                .collect::<Vec<_>>()
                .into();
        }
    }

    trace!(
        target: "llt::mul",
        "final pp: {:?}", pp
    );

    // Extract carry and message and do carry propagation
    let mut a: Vec<Option<VarCell>> = (0..dst.len() + 1).map(|_| None).collect();
    let mut b: Vec<Option<VarCell>> = (0..dst.len() + 1).map(|_| None).collect();

    pp.into_iter().enumerate().for_each(|(i, pp)| {
        assert!(pp.len() == 1);
        let vardeg = pp.first().unwrap();
        let (msg, carry) = vardeg.bootstrap(&props);
        a[i] = Some(msg.var);
        if let Some(carry) = carry {
            b[i + 1] = Some(carry.var);
        }
    });

    let cs: Vec<_> = a
        .into_iter()
        .take(dst.len())
        .zip(b.into_iter())
        .map(|(a, b)| match (a, b) {
            (Some(a), Some(b)) => &a + &b,
            (Some(a), None) => a,
            (None, Some(b)) => b,
            _ => panic!("Fix your code"),
        })
        .collect();

    // Do fully parallel carry propagation
    kogge::propagate_carry(prog, dst.as_mut_slice(), cs.as_slice(), &None);

    Rtl::from(dst)
}

/// multiplier wrapper, to choose between parallel and serial implementations
#[instrument(level = "trace", skip(prog))]
pub fn iop_mulx(
    prog: &mut Program,
    dst: Vec<metavar::MetaVarCell>,
    src_a: Vec<metavar::MetaVarCell>,
    src_b: Vec<metavar::MetaVarCell>,
) -> Rtl {
    // When the batch size is enough to do a full stage in parallel, do parallel
    // mul.
    // Note: The break-even point might not be this one, but choosing the right
    // point is uninportant since we'll leap imensely the number of batches from
    // FPGA to ASIC.
    let parallel = prog
        .op_cfg()
        .parallel
        .unwrap_or_else(|| prog.params().pbs_batch_w >= dst.len());

    if parallel {
        iop_mulx_par(prog, dst, src_a, src_b)
    } else {
        iop_mulx_ser(prog, dst, src_a, src_b)
    }
}

/// Generic mul operation
/// One destination and two sources operation
/// Source could be Operand or Immediate
#[instrument(level = "trace", skip(prog))]
pub fn iop_mulx_ser(
    prog: &mut Program,
    dst: Vec<metavar::MetaVarCell>,
    src_a: Vec<metavar::MetaVarCell>,
    src_b: Vec<metavar::MetaVarCell>,
) -> Rtl {
    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();
    let blk_w = props.blk_w();

    // Transform metavars into RTL vars
    let mut dst = VarCell::from_vec(dst);
    let src_a = VarCell::from_vec(src_a);
    let src_b = VarCell::from_vec(src_b);
    let max_deg = VarDeg {
        deg: props.max_val(),
        nu: props.nu,
    };

    let pbs_msg = pbs_by_name!("MsgOnly");
    let pbs_carry = pbs_by_name!("CarryInMsg");
    let pbs_mul_lsb = pbs_by_name!("MultCarryMsgLsb");
    let pbs_mul_msb = pbs_by_name!("MultCarryMsgMsb");
    let max_carry = (props.max_msg() * props.max_msg()) >> props.msg_w;

    let mut mul_map: HashMap<usize, Vec<VarCellDeg>> = HashMap::new();
    itertools::iproduct!(0..blk_w, 0..blk_w).for_each(|(i, j)| {
        let pp = src_a[i].mac(tfhe_params.msg_range(), &src_b[j]);
        let lsb = pp.single_pbs(&pbs_mul_lsb);
        let msb = pp.single_pbs(&pbs_mul_msb);
        mul_map
            .entry(i + j)
            .or_default()
            .push(VarCellDeg::new(max_carry, lsb));
        mul_map
            .entry(i + j + 1)
            .or_default()
            .push(VarCellDeg::new(max_carry, msb));
    });

    for (blk, dst) in dst.iter_mut().enumerate() {
        let mut to_sum: VecVarCellDeg = mul_map.remove(&blk).unwrap().into();
        let mut bootstrap = |sum: &VarCellDeg| -> VarCellDeg {
            trace!(target: "llt:mulx:bootstrap", "bootstrap: {:?}", sum);
            if sum.deg.deg > props.max_msg() {
                mul_map.entry(blk + 1).or_default().push(VarCellDeg::new(
                    sum.deg.deg >> props.msg_w,
                    sum.var.single_pbs(&pbs_carry),
                ));
            }
            VarCellDeg::new(
                sum.deg.deg.min(props.max_msg()),
                sum.var.single_pbs(&pbs_msg),
            )
        };

        while to_sum.len() > 1 {
            let prev_len = to_sum.len();

            to_sum = to_sum
                .deg_chunks(&max_deg)
                // Leveled Sum
                .map(|mut chunk| {
                    trace!(target: "ilp:mulx", "leveled chunk: {:?}", chunk);

                    while chunk.len() > 1 {
                        chunk = chunk
                            .chunks(2)
                            .map(|chunk| match chunk.len() {
                                1 => chunk[0].clone(),
                                2 => &chunk[0] + &chunk[1],
                                _ => panic!("Invalid chunk size"),
                            })
                            .collect()
                    }

                    chunk.into_iter().next().unwrap()
                })
                // Bootstrap
                .map(|sum| {
                    assert!(sum.deg.nu <= props.nu);
                    if sum.deg == max_deg {
                        bootstrap(&sum)
                    } else {
                        sum
                    }
                })
                .collect::<Vec<_>>()
                .into();

            // If no element has been bootstrapped, bootstrap the worst case
            // This will be very unlikely, but if it ever happened it would have hanged
            // the whole loop. Also, the output needs to be bootstrapped,
            // anyway.
            (to_sum.0.iter().all(|x| x.deg.nu > 1) || prev_len == to_sum.len()).then(|| {
                let max = to_sum.max_mut().unwrap();
                *max = bootstrap(max);
            });
        }

        let out = to_sum.first().unwrap();

        assert!(
            {
                let deg = out.deg.clone();
                deg.deg <= props.max_msg() && deg.nu == 1
            },
            "Output variable {blk} is not bootstrapped"
        );

        *dst <<= &out.var;
    }

    Rtl::from(dst)
}

/// Generic Cmp operation
/// One destination block and two sources operands
/// Source could be Operand or Immediate
#[instrument(level = "trace", skip(prog))]
pub fn iop_cmpx(
    prog: &mut Program,
    dst: &metavar::MetaVarCell,
    src_a: &[metavar::MetaVarCell],
    src_b: &[metavar::MetaVarCell],
    mrg_lut: Pbs,
    cmp_lut: Pbs,
) -> Rtl {
    let mut dst = VarCell::from(dst);
    let src_a = src_a.iter().map(VarCell::from).collect();
    let src_b = src_b.iter().map(VarCell::from).collect();
    dst <<= &iop_cmpx_rtl(prog, src_a, src_b, mrg_lut, cmp_lut);
    Rtl::from(vec![dst])
}

/// Generic Cmp operation
/// One destination block and two sources operands
/// Source could be Operand or Immediate
#[instrument(level = "trace", skip(prog))]
pub fn iop_cmpx_rtl(
    prog: &mut Program,
    src_a: Vec<VarCell>,
    src_b: Vec<VarCell>,
    mrg_lut: Pbs,
    cmp_lut: Pbs,
) -> VarCell {
    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    // Wrapped given cmp_op and comp_sign lookup table in MetaVar
    let pbs_none = pbs_by_name!("None");
    let cmp_sign = pbs_by_name!("CmpSign");
    let cmp_reduce = pbs_by_name!("CmpReduce");

    // Pack A and B elements by pairs
    let packed = std::iter::zip(src_a.chunks(2), src_b.chunks(2))
        .map(|(a, b)| {
            let pack_a = if a.len() > 1 {
                // Reset noise for future block merge through sub
                a[0].mac(tfhe_params.msg_range(), &a[1])
                    .single_pbs(&pbs_none)
            } else {
                a[0].clone()
            };

            let pack_b = if b.len() > 1 {
                b[0].mac(tfhe_params.msg_range(), &b[1])
                    .single_pbs(&pbs_none)
            } else {
                b[0].clone()
            };
            (pack_a, pack_b)
        })
        .collect::<Vec<_>>();

    let mut merged = packed
        .into_iter()
        .map(|(a, b)| &(&a - &b).single_pbs(&cmp_sign) + 1)
        .collect::<Vec<_>>();

    while merged.len() > 2 {
        merged = merged
            .into_iter()
            .chunks(2)
            .into_iter()
            .map(|mut chunk| {
                let left = chunk.next();
                let right = chunk.next();
                match (left, right) {
                    (Some(l), None) => l,
                    (Some(l), Some(r)) => {
                        l.mac(tfhe_params.msg_range(), &r).single_pbs(&cmp_reduce)
                    }
                    _ => panic!("Chunk misbehaved"),
                }
            })
            .collect()
    }

    match merged.len() {
        2 => merged[0]
            .mac(tfhe_params.msg_range(), &merged[1])
            .single_pbs(&mrg_lut),
        1 => merged[0].single_pbs(&cmp_lut),
        _ => panic!("Fix your bugs!"),
    }
}

fn bw_inv(prog: &mut Program, b: Vec<VarCell>) -> Vec<VarCell> {
    let blk_w = prog.params().blk_w();
    let imm = (0..blk_w).map(|_| VarCell::from(prog.new_imm((1 << prog.params().msg_w) - 1)));
    b.iter()
        .zip_longest(imm)
        .map(|r| match r {
            EitherOrBoth::Right(i) => i,
            EitherOrBoth::Both(b, i) => &i - b,
            EitherOrBoth::Left(_) => {
                panic!(
                    "The input to be inverted is greater than blk_w({}): {}",
                    blk_w,
                    b.len()
                )
            }
        })
        .collect::<Vec<_>>()
}

/// Creates a SIMD version of the closure
/// Make sure that the closure is a PBS optimized version of the operation
/// The closure receives as inputs the program and the batch index.
/// How the ASM operands are actually organized is defined by the closure
/// itself.
///
/// Maybe this should go into a SIMD firmware implementation... At some point we
/// would need a mechanism to choose between implementations on the fly to make
/// real good use of all of this.
fn simd<F>(prog: &mut Program, batch_size: usize, rtl_closure: F)
where
    F: Fn(&mut Program, u8) -> Rtl,
{
    (0..batch_size)
        .map(|i| i as u8)
        .map(|i| rtl_closure(prog, i))
        .sum::<Rtl>()
        .add_to_prog(prog);
}

// Comupute inner-shift
// input:
// * src: clean ciphertext with only message
// * amount: ciphertext encoding amount to Shift/Rotate. Only Lsb of msg will be considered
// output:
//  Tuple of msg and msg_next.
//   msg_next is the contribution of next ct block in the shift direction
fn inner_shift(
    prog: &Program,
    dir: ShiftKind,
    src: &VarCell,
    amount: &VarCell,
) -> (VarCell, VarCell) {
    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    let (pbs_msg, pbs_msg_next) = match dir {
        ShiftKind::ShiftRight | ShiftKind::RotRight => (
            pbs_by_name!("ShiftRightByCarryPos0Msg"),
            pbs_by_name!("ShiftRightByCarryPos0MsgNext"),
        ),
        ShiftKind::ShiftLeft | ShiftKind::RotLeft => (
            pbs_by_name!("ShiftLeftByCarryPos0Msg"),
            pbs_by_name!("ShiftLeftByCarryPos0MsgNext"),
        ),
    };

    let pack = src.mac(tfhe_params.msg_range(), amount);
    let msg = pack.single_pbs(&pbs_msg);
    let msg_next = pack.single_pbs(&pbs_msg_next);
    (msg, msg_next)
}

fn block_swap(
    prog: &Program,
    src_orig: &VarCell,
    src_swap: Option<&VarCell>,
    cond: &VarCell,
    cond_mask: CondPos,
) -> VarCell {
    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    let (pbs_orig, pbs_swap) = match cond_mask {
        CondPos::Pos0 => (
            pbs_by_name!("IfPos0TrueZeroed"),
            pbs_by_name!("IfPos0FalseZeroed"),
        ),
        CondPos::Pos1 => (
            pbs_by_name!("IfPos1TrueZeroed"),
            pbs_by_name!("IfPos1FalseZeroed"),
        ),
    };
    let pack_orig = src_orig.mac(tfhe_params.msg_range(), cond);
    if let Some(swap) = src_swap {
        let pack_swap = swap.mac(tfhe_params.msg_range(), cond);
        &pack_orig.single_pbs(&pbs_orig) + &pack_swap.single_pbs(&pbs_swap)
    } else {
        pack_orig.single_pbs(&pbs_orig)
    }
}

/// Generic shift function operation
#[instrument(level = "trace", skip(prog))]
fn iop_shiftrotx(
    prog: &Program,
    kind: ShiftKind,
    mut dst: Vec<VarCell>,
    src: Vec<VarCell>,
    amount: Vec<VarCell>,
) -> Rtl {
    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();
    let blk_w = props.blk_w();

    // First apply inner shift
    let (shiftrot, shiftrot_next): (Vec<_>, Vec<_>) = src
        .iter()
        .map(|ct| inner_shift(prog, kind, ct, &amount[0]))
        .unzip();

    // Fuse msg and next msg based on direction/kind
    let mut merge_shiftrot = shiftrot
        .into_iter()
        .enumerate()
        .with_position()
        .map(|(pos, (i, ct))| match kind {
            ShiftKind::ShiftRight => {
                if !matches!(pos, Position::Last | Position::Only) {
                    &ct + &shiftrot_next[i + 1]
                } else {
                    ct
                }
            }
            ShiftKind::ShiftLeft => {
                if !matches!(pos, Position::First | Position::Only) {
                    &ct + &shiftrot_next[i - 1]
                } else {
                    ct
                }
            }
            ShiftKind::RotRight => {
                let rot_idx = (i + 1) % shiftrot_next.len();
                &ct + &shiftrot_next[rot_idx]
            }
            ShiftKind::RotLeft => {
                let rot_idx = ((i + shiftrot_next.len()) - 1) % shiftrot_next.len();
                &ct + &shiftrot_next[rot_idx]
            }
        })
        .collect::<Vec<_>>();

    // Second apply block swap
    // Block swapping done with successive buterflies with log2 stages
    // NB: each block encode msg_w bits thus:
    //     * First shiftrot is already done with inner_shiftrot
    //     * Two swap is done for each amount blk
    for stg in 1..(2 * blk_w).ilog2() as usize {
        merge_shiftrot = (0..blk_w)
            .map(|i| {
                let stride = 1 << (stg - 1);
                let swap = match kind {
                    ShiftKind::ShiftRight => merge_shiftrot.get(i + stride),
                    ShiftKind::ShiftLeft => {
                        if i >= stride {
                            merge_shiftrot.get(i - stride)
                        } else {
                            None
                        }
                    }
                    ShiftKind::RotRight => {
                        let swap_idx = (i + stride) % merge_shiftrot.len();
                        merge_shiftrot.get(swap_idx)
                    }
                    ShiftKind::RotLeft => {
                        let swap_idx = (i + merge_shiftrot.len() - stride) % merge_shiftrot.len();
                        merge_shiftrot.get(swap_idx)
                    }
                };
                // Based on stage index shiftrot condition is in amount msg at pos0 or pos1
                block_swap(
                    prog,
                    &merge_shiftrot[i],
                    swap,
                    &amount[stg / tfhe_params.msg_w],
                    if stg % 2 == 1 {
                        CondPos::Pos1
                    } else {
                        CondPos::Pos0
                    },
                )
            })
            .collect::<Vec<_>>();
    }
    dst.iter_mut()
        .zip(merge_shiftrot.iter())
        .for_each(|(d, r)| {
            *d <<= r;
        });
    dst.into()
}
