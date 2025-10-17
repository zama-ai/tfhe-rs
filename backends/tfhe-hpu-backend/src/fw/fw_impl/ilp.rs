//!
//! Implementation of Ilp firmware
//!
//! In this version of the Fw focus is done on Instruction Level Parallelism
use std::collections::VecDeque;

use super::*;
use crate::asm::{self, OperandKind, Pbs};
use crate::fw::program::Program;
use crate::fw::FwParameters;
use itertools::{Itertools, Position};
use tracing::{instrument, trace, warn};

use crate::asm::iop::opcode::*;
use crate::new_pbs;

crate::impl_fw!("Ilp" [
    ADD => fw_impl::ilp::iop_add;
    SUB => fw_impl::ilp::iop_sub;
    MUL => fw_impl::ilp::iop_mul;
    DIV => fw_impl::ilp_div::iop_div;
    MOD => fw_impl::ilp_div::iop_mod;

    OVF_ADD => fw_impl::ilp::iop_overflow_add;
    OVF_SUB => fw_impl::ilp::iop_overflow_sub;
    OVF_MUL => fw_impl::ilp::iop_overflow_mul;

    ROT_R => fw_impl::ilp::iop_rotate_right;
    ROT_L => fw_impl::ilp::iop_rotate_left;
    SHIFT_R => fw_impl::ilp::iop_shift_right;
    SHIFT_L => fw_impl::ilp::iop_shift_left;

    ADDS => fw_impl::ilp::iop_adds;
    SUBS => fw_impl::ilp::iop_subs;
    SSUB => fw_impl::ilp::iop_ssub;
    MULS => fw_impl::ilp::iop_muls;
    DIVS => fw_impl::ilp_div::iop_divs;
    MODS => fw_impl::ilp_div::iop_mods;

    OVF_ADDS => fw_impl::ilp::iop_overflow_adds;
    OVF_SUBS => fw_impl::ilp::iop_overflow_subs;
    OVF_SSUB => fw_impl::ilp::iop_overflow_ssub;
    OVF_MULS => fw_impl::ilp::iop_overflow_muls;

    ROTS_R => fw_impl::ilp::iop_rotate_scalar_right;
    ROTS_L => fw_impl::ilp::iop_rotate_scalar_left;
    SHIFTS_R => fw_impl::ilp::iop_shift_scalar_right;
    SHIFTS_L => fw_impl::ilp::iop_shift_scalar_left;

    BW_AND => (|prog| {fw_impl::ilp::iop_bw(prog, asm::dop::PbsBwAnd::default().into())});
    BW_OR  => (|prog| {fw_impl::ilp::iop_bw(prog, asm::dop::PbsBwOr::default().into())});
    BW_XOR => (|prog| {fw_impl::ilp::iop_bw(prog, asm::dop::PbsBwXor::default().into())});

    CMP_GT  => (|prog| {fw_impl::ilp::iop_cmp(prog, asm::dop::PbsCmpGt::default().into())});
    CMP_GTE => (|prog| {fw_impl::ilp::iop_cmp(prog, asm::dop::PbsCmpGte::default().into())});
    CMP_LT  => (|prog| {fw_impl::ilp::iop_cmp(prog, asm::dop::PbsCmpLt::default().into())});
    CMP_LTE => (|prog| {fw_impl::ilp::iop_cmp(prog, asm::dop::PbsCmpLte::default().into())});
    CMP_EQ  => (|prog| {fw_impl::ilp::iop_cmp(prog, asm::dop::PbsCmpEq::default().into())});
    CMP_NEQ => (|prog| {fw_impl::ilp::iop_cmp(prog, asm::dop::PbsCmpNeq::default().into())});

    IF_THEN_ZERO => fw_impl::ilp::iop_if_then_zero;
    IF_THEN_ELSE => fw_impl::ilp::iop_if_then_else;

    ERC_20 => fw_impl::ilp::iop_erc_20;

    MEMCPY => fw_impl::ilp::iop_memcpy;

    COUNT0 => fw_impl::ilp_log::iop_count0;
    COUNT1 => fw_impl::ilp_log::iop_count1;
    ILOG2  => fw_impl::ilp_log::iop_ilog2;
    LEAD0  => fw_impl::ilp_log::iop_lead0;
    LEAD1  => fw_impl::ilp_log::iop_lead1;
    TRAIL0 => fw_impl::ilp_log::iop_trail0;
    TRAIL1 => fw_impl::ilp_log::iop_trail1;
    // SIMD Implementations
    ADD_SIMD     => fw_impl::llt::iop_add_simd;
    ERC_20_SIMD  => fw_impl::llt::iop_erc_20_simd;
]);

#[instrument(level = "trace", skip(prog))]
pub fn iop_add(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Operand
    let src_b = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment("ADD Operand::Dst Operand::Src Operand::Src".to_string());
    // Deferred implementation to generic addx function
    iop_addx(prog, &mut dst, None, &src_a, &src_b);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_adds(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Imm, 0);

    // Add Comment header
    prog.push_comment("ADDS Operand::Dst Operand::Src Operand::Immediate".to_string());
    // Deferred implementation to generic addx function
    iop_addx(prog, &mut dst, None, &src_a, &src_b);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_overflow_add(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    let mut flag = prog.iop_template_var(OperandKind::Dst, 1);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Operand
    let src_b = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment("ADD Operand::Dst Operand::Src Operand::Src".to_string());
    // Deferred implementation to generic addx function
    iop_addx(prog, &mut dst, Some(&mut flag[0]), &src_a, &src_b);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_overflow_adds(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    let mut flag = prog.iop_template_var(OperandKind::Dst, 1);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Imm, 0);

    // Add Comment header
    prog.push_comment("ADDS Operand::Dst Operand::Src Operand::Immediate".to_string());
    // Deferred implementation to generic addx function
    iop_addx(prog, &mut dst, Some(&mut flag[0]), &src_a, &src_b);
}

/// Generic Add operation
/// One destination and two sources operation
/// Source could be Operand or Immediate
#[instrument(level = "trace", skip(prog))]
pub fn iop_addx(
    prog: &mut Program,
    dst: &mut [metavar::MetaVarCell],
    mut flag: Option<&mut metavar::MetaVarCell>,
    src_a: &[metavar::MetaVarCell],
    src_b: &[metavar::MetaVarCell],
) {
    let props = prog.params();

    // Wrapped required lookup table in MetaVar
    let pbs_msg = new_pbs!(prog, "MsgOnly");
    let pbs_carry = new_pbs!(prog, "CarryInMsg");
    let pbs_carry_is_some = new_pbs!(prog, "CarryIsSome");

    let mut carry: Option<metavar::MetaVarCell> = None;

    (0..prog.params().blk_w()).for_each(|blk| {
        prog.push_comment(format!(" ==> Work on output block {blk}"));

        let mut msg = &src_a[blk] + &src_b[blk];
        if let Some(cin) = &carry {
            msg += cin.clone();
        }
        if blk < (props.blk_w() - 1) {
            carry = Some(msg.pbs(&pbs_carry, false));
        } else if let Some(f) = flag.as_mut() {
            let is_some = msg.pbs(&pbs_carry_is_some, false);
            f.mv_assign(&is_some);
        }
        // Force allocation of new reg to allow carry/msg pbs to run in //
        let msg = msg.pbs(&pbs_msg, true);

        // Store result
        dst[blk].mv_assign(&msg);
    });
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_sub(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment("SUB Operand::Dst Operand::Src Operand::Src".to_string());
    // Deferred implementation to generic subx function
    iop_subx(prog, &mut dst, None, &src_a, &src_b);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_subs(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Imm, 0);

    // Add Comment header
    prog.push_comment("SUBS Operand::Dst Operand::Src Operand::Immediate".to_string());
    // Deferred implementation to generic subx function
    iop_subx(prog, &mut dst, None, &src_a, &src_b);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_overflow_sub(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    let mut flag = prog.iop_template_var(OperandKind::Dst, 1);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment("SUB Operand::Dst Operand::Src Operand::Src".to_string());
    // Deferred implementation to generic subx function
    iop_subx(prog, &mut dst, Some(&mut flag[0]), &src_a, &src_b);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_overflow_subs(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    let mut flag = prog.iop_template_var(OperandKind::Dst, 1);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Imm, 0);

    // Add Comment header
    prog.push_comment("SUBS Operand::Dst Operand::Src Operand::Immediate".to_string());
    // Deferred implementation to generic subx function
    iop_subx(prog, &mut dst, Some(&mut flag[0]), &src_a, &src_b);
}

/// Generic sub operation
/// One destination and two sources operation
/// Source could be Operand or Immediate
#[instrument(level = "trace", skip(prog))]
pub fn iop_subx(
    prog: &mut Program,
    dst: &mut [metavar::MetaVarCell],
    mut flag: Option<&mut metavar::MetaVarCell>,
    src_a: &[metavar::MetaVarCell],
    src_b: &[metavar::MetaVarCell],
) {
    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    // Wrapped required lookup table in MetaVar
    let pbs_msg = new_pbs!(prog, "MsgOnly");
    let pbs_carry = new_pbs!(prog, "CarryInMsg");
    let pbs_carry_is_none = new_pbs!(prog, "CarryIsNone");

    let mut z_cor: Option<usize> = None;
    let mut carry: Option<metavar::MetaVarCell> = None;

    (0..prog.params().blk_w()).for_each(|blk| {
        // Compute -b
        // Algo is based on neg_from + correction factor
        // neg_from - b + z_cor
        // Trick here is to merge imm before SSub to reduce operation number
        let neg_from = if let Some(z) = &z_cor {
            prog.new_imm(tfhe_params.msg_range() - *z)
        } else {
            prog.new_imm(tfhe_params.msg_range())
        };
        let b_neg = &neg_from - &src_b[blk];

        // TODO check correction factor computation
        // From the context it seems that it could be a constant 1
        z_cor = Some(
            src_b[blk]
                .get_degree()
                .div_ceil(tfhe_params.msg_range())
                .max(1),
        );

        // Compute a + (-b)
        let mut msg = &src_a[blk] + &b_neg;

        // Handle input/output carry and extract msg
        if let Some(cin) = &carry {
            msg += cin.clone();
        }
        if blk < (props.blk_w() - 1) {
            carry = Some(msg.pbs(&pbs_carry, false));
        } else if let Some(f) = flag.as_mut() {
            // TODO understand properly how to borrow z_cor from next block for overflowing check
            let is_some = msg.pbs(&pbs_carry_is_none, false);
            f.mv_assign(&is_some);
        }
        // Force allocation of new reg to allow carry/msg pbs to run in //
        let msg = msg.pbs(&pbs_msg, true);

        // Store result
        dst[blk] <<= msg;
    });
}

/// Implementation of SSUB
/// Provide its own implementation to match SUBS perfs
#[instrument(level = "trace", skip(prog))]
pub fn iop_ssub(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Imm, 0);

    // Add Comment header
    prog.push_comment("SSUB Operand::Dst Operand::Src Operand::Immediate".to_string());
    // Deferred implementation to generic subx function
    iop_ssubx(prog, &mut dst, None, &src_a, &src_b);
}

/// Generic SSUB operation
/// One destination and two sources operation
/// Source could be Operand or Immediate
#[instrument(level = "trace", skip(prog))]
pub fn iop_ssubx(
    prog: &mut Program,
    dst: &mut [metavar::MetaVarCell],
    mut flag: Option<&mut metavar::MetaVarCell>,
    src_a: &[metavar::MetaVarCell],
    src_b: &[metavar::MetaVarCell],
) {
    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    // Wrapped required lookup table in MetaVar
    let pbs_msg = new_pbs!(prog, "MsgOnly");
    let pbs_carry = new_pbs!(prog, "CarryInMsg");
    let pbs_carry_is_none = new_pbs!(prog, "CarryIsNone");

    let mut z_cor: Option<usize> = None;
    let mut carry: Option<metavar::MetaVarCell> = None;

    (0..prog.params().blk_w()).for_each(|blk| {
        // Compute -a
        // Algo is based on neg_from + correction factor
        // neg_from - a + z_cor
        // Trick here is to merge imm before SSub to reduce operation number
        let neg_from = if let Some(z) = &z_cor {
            prog.new_imm(tfhe_params.msg_range() - *z)
        } else {
            prog.new_imm(tfhe_params.msg_range())
        };
        let a_neg = &neg_from - &src_a[blk];

        // TODO check correction factor computation
        // From the context it seems that it could be a constant 1
        z_cor = Some(
            src_a[blk]
                .get_degree()
                .div_ceil(tfhe_params.msg_range())
                .max(1),
        );

        // Compute b + (-a)
        let mut msg = &src_b[blk] + &a_neg;

        // Handle input/output carry and extract msg
        if let Some(cin) = &carry {
            msg += cin.clone();
        }
        if blk < (props.blk_w() - 1) {
            carry = Some(msg.pbs(&pbs_carry, false));
        } else if let Some(f) = flag.as_mut() {
            // TODO understand properly how to borrow z_cor from next block for overflowing check
            let is_some = msg.pbs(&pbs_carry_is_none, false);
            f.mv_assign(&is_some);
        }

        // Force allocation of new reg to allow carry/msg pbs to run in //
        let msg = msg.pbs(&pbs_msg, true);

        // Store result
        dst[blk] <<= msg;
    });
}

pub fn iop_overflow_ssub(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    let mut flag = prog.iop_template_var(OperandKind::Dst, 1);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Imm, 0);

    // Add Comment header
    prog.push_comment("SUBS Operand::Dst Operand::Src Operand::Immediate".to_string());
    // Deferred implementation to generic ssubx function
    iop_ssubx(prog, &mut dst, Some(&mut flag[0]), &src_a, &src_b);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_mul(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment("MUL Operand::Dst Operand::Src Operand::Src".to_string());
    // Deferred implementation to generic mulx function
    iop_mulx(prog, &mut dst, None, &src_a, &src_b);
}

pub fn iop_muls(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Imm, 0);

    // Add Comment header
    prog.push_comment("MULS Operand::Dst Operand::Src Operand::Immediate".to_string());
    // Deferred implementation to generic mulx function
    iop_mulx(prog, &mut dst, None, &src_a, &src_b);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_overflow_mul(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    let mut flag = prog.iop_template_var(OperandKind::Dst, 1);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment("MUL Operand::Dst Operand::Src Operand::Src".to_string());
    // Deferred implementation to generic mulx function
    iop_mulx(prog, &mut dst, Some(&mut flag[0]), &src_a, &src_b);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_overflow_muls(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    let mut flag = prog.iop_template_var(OperandKind::Dst, 1);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Imm, 0);

    // Add Comment header
    prog.push_comment("MULS Operand::Dst Operand::Src Operand::Immediate".to_string());
    // Deferred implementation to generic mulx function
    iop_mulx(prog, &mut dst, Some(&mut flag[0]), &src_a, &src_b);
}

/// Generic mul operation
/// One destination and two sources operation
/// Source could be Operand or Immediate
#[instrument(level = "trace", skip(prog))]
pub fn iop_mulx(
    prog: &mut Program,
    dst: &mut [metavar::MetaVarCell],
    flag: Option<&mut metavar::MetaVarCell>,
    src_a: &[metavar::MetaVarCell],
    src_b: &[metavar::MetaVarCell],
) {
    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();
    let blk_w = props.blk_w();

    // Wrapped required lookup table in MetaVar
    let pbs_msg = new_pbs!(prog, "MsgOnly");
    let pbs_carry = new_pbs!(prog, "CarryInMsg");
    let pbs_carry_is_some = new_pbs!(prog, "CarryIsSome");
    let pbs_mul_lsb = new_pbs!(prog, "MultCarryMsgLsb");
    let pbs_mul_msb = new_pbs!(prog, "MultCarryMsgMsb");
    let pbs_mult_is_some = new_pbs!(prog, "MultCarryMsgIsSome");
    let pbs_mult_msb_is_some = new_pbs!(prog, "MultCarryMsgMsbIsSome");
    let pbs_is_some = new_pbs!(prog, "IsSome");

    // Used for overflow computation only
    let mut ovf_non_zero_vars = Vec::new();

    // Compute list of partial product for each blk ---------------------------------
    // First compute the list of required partial product. Filter out product with
    // degree higher than output one
    // NB: Targeted multiplication is nBits*nBits -> nBits [i.e. LSB only]
    let pp_deg_idx = (0..blk_w)
        .flat_map(|blk| {
            itertools::iproduct!(0..blk_w, 0..blk_w)
                .filter(move |(i, j)| i + j == blk)
                .map(move |(i, j)| (blk, i, j))
        })
        .collect::<Vec<_>>();

    // Compute all partial product by chunk
    // And store result in a Deque with associated weight (i.e. blk)
    let mut pp_vars = VecDeque::new();

    for pp in pp_deg_idx.chunks(props.pbs_batch_w) {
        // Pack
        let pack = pp
            .iter()
            .map(|(w, i, j)| {
                let mac = src_a[*i].mac(tfhe_params.msg_range() as u8, &src_b[*j]);
                trace!(target: "Fw", "@{w}[{i}, {j}] -> {mac:?}",);
                (w, mac)
            })
            .collect::<Vec<_>>();

        // Pbs Mul
        // Reserve twice as pbs_w since 2 pbs could be generated for a given block
        prog.reg_bulk_reserve(2 * props.pbs_batch_w);
        pack.into_iter().for_each(|(w, pp)| {
            let lsb = pp.pbs(&pbs_mul_lsb, false);
            trace!(target: "Fw", "Pbs generate @{w} -> {lsb:?}");
            pp_vars.push_back((*w, lsb));

            // Extract msb if needed
            if *w < (blk_w - 1) {
                // Force allocation of new reg to allow lsb/msb pbs to run in //
                let msb = pp.pbs(&pbs_mul_msb, false);
                trace!(target: "Fw", "Pbs generate @{} -> {msb:?}", w + 1);
                pp_vars.push_back((*w + 1, msb));
            } else if flag.is_some() {
                // Last carry must be extracted for overflow computation
                let ovf_lsb_nz = pp.pbs(&pbs_mult_msb_is_some, false);
                ovf_non_zero_vars.push(ovf_lsb_nz);
            }
        });
    }

    // Merged partial product together ---------------------------------------------
    let mut acc_wh = vec![Vec::with_capacity(props.nu); blk_w];
    let mut pdg_acc = Vec::new();
    let mut pdg_pbs = Vec::new();

    // Use to writeback in order and prevent digits drop during propagation
    let mut wb_idx = 0;

    pp_vars
        .make_contiguous()
        .sort_by(|x, y| x.0.partial_cmp(&y.0).unwrap());

    while let Some((w, var)) = pp_vars.pop_front() {
        acc_wh[w].push(var);

        // Trace internal state
        trace!(target: "Fw", "{:#<80}","");
        trace!(target: "Fw", "pp_vars[{}] -> {pp_vars:?}", pp_vars.len(),);
        trace!(target: "Fw", "pdg_acc[{}] -> {pdg_acc:?}", pdg_acc.len(),);
        trace!(target: "Fw", "pdg_pbs[{}] -> {pdg_pbs:?}", pdg_pbs.len(),);

        // For each acc_wh slot check flushing condition
        trace!(target: "Fw", "Acc_wh: Check flushing condition {:#<20}","");
        for (w, acc) in acc_wh.iter_mut().enumerate() {
            if w < wb_idx {
                // Skip position w if already committed
                assert_eq!(0, acc.len(), "Error committed incomplete digit");
                continue;
            }
            // Check if other deg_w var are in the pp_vars store or in pbs_pipe
            let winf_in_pipe = pp_vars.iter().filter(|(d, _)| *d <= w).count()
                + pdg_pbs.iter().filter(|(d, _)| *d <= w).count()
                + pdg_acc.iter().filter(|(d, _)| *d <= w).count();

            trace!(
                target: "Fw",
                "acc {w}: [len:{}; winf:{winf_in_pipe}] -> {:?}",
                acc.len(),
                acc
            );

            // Trigger Add if acc warehouse is full of if no more deg_w (or previous) is in pipe
            if (acc.len() == props.nu) || ((winf_in_pipe == 0) && (!acc.is_empty())) {
                trace!(target: "Fw", "Flush acc_wh[{w}]",);
                let mut acc_chunks = std::mem::take(acc);
                match acc_chunks.len() {
                    1 => {
                        // Try to commit directly
                        // Skipped acc reduction tree
                        if wb_idx == w {
                            // Finish computation for digit @w
                            acc_chunks[0].reg_alloc_mv();
                            trace!(target:"Fw", "Commit {w} <- {:?}", acc_chunks[0]);
                            dst[w] <<= acc_chunks.swap_remove(0);
                            wb_idx += 1;
                        } else {
                            // not my turn, enqueue back
                            trace!(target:"Fw", "{w}::{wb_idx}: insert backed in pp_vars {:?}", acc_chunks[0]);
                            pp_vars.push_back((w, acc_chunks.swap_remove(0)));
                        }
                    }
                    _ => {
                        // Go through the acc reduction tree
                        pdg_acc.push((w, acc_chunks));
                    }
                }
            }
        }

        trace!(
            target: "Fw",
            "pdg_acc[{}], pp_vars[{}]: flush pdg_acc",
            pdg_acc.len(),
            pp_vars.len()
        );
        while let Some((w, acc_chunks)) = pdg_acc.pop() {
            trace!(target: "Fw", "Reduce @{w}[{}] <- {acc_chunks:?}",acc_chunks.len());
            // Hand-written tree reduction for up to 5
            match acc_chunks.len() {
                1 => {
                    unreachable!("This case must not go through acc reduction tree. In should have take the fast pass in acc_wh flushing.");
                }

                2 => {
                    let sum = &acc_chunks[0] + &acc_chunks[1];
                    pdg_pbs.push((w, sum));
                }

                3 => {
                    let sum_a = &acc_chunks[0] + &acc_chunks[1];
                    let sum_b = &sum_a + &acc_chunks[2];
                    pdg_pbs.push((w, sum_b));
                }

                4 => {
                    let sum_a = &acc_chunks[0] + &acc_chunks[1];
                    let mut sum_b = &acc_chunks[2] + &acc_chunks[3];
                    sum_b += sum_a;
                    pdg_pbs.push((w, sum_b));
                }
                5 => {
                    let sum_a = &acc_chunks[0] + &acc_chunks[1];
                    let sum_b = &acc_chunks[2] + &acc_chunks[3];
                    let mut sum_c = &sum_b + &acc_chunks[4];
                    sum_c += sum_a;
                    pdg_pbs.push((w, sum_c));
                }
                _ => panic!("Currently only support nu <= 5"),
            }
        }

        if pdg_pbs.len() == props.pbs_batch_w || (pp_vars.is_empty()) {
            trace!(target: "Fw", "pdg_pbs[{}] <- {pdg_pbs:?}", pdg_pbs.len());
            prog.reg_bulk_reserve(pdg_pbs.len());
            while let Some((w, var)) = pdg_pbs.pop() {
                let lsb = var.pbs(&pbs_msg, false);
                trace!(target: "Fw", "Pbs generate @{w} -> {lsb:?}");
                // TODO These explicit flush enhance perf for large MUL but degrade them for small
                // one Find a proper way to arbitrait their used
                // Furthermore, it induce error with current ISC without LD/ST ordering
                // lsb.heap_alloc_mv(true);
                pp_vars.push_back((w, lsb));

                // Extract msb if needed
                if w < (blk_w - 1) {
                    // Force allocation of new reg to allow carry/msg pbs to run in //
                    let msb = var.pbs(&pbs_carry, false);
                    trace!(target: "Fw", "Pbs generate @{} -> {msb:?}", w + 1);
                    // TODO These explicit flush enhance perf for large MUL but degrade them for
                    // small one Find a proper way to arbitrait their used
                    // Furthermore, it induce error with current ISC without LD/ST ordering
                    // msb.heap_alloc_mv(true);
                    pp_vars.push_back((w + 1, msb));
                } else if flag.is_some() {
                    // Last carry must be extracted for overflow computation
                    let ovf_lsb_nz = var.pbs(&pbs_carry_is_some, false);
                    ovf_non_zero_vars.push(ovf_lsb_nz);
                }
            }
            // Compute LSB ASAP
            pp_vars
                .make_contiguous()
                .sort_by(|x, y| x.0.partial_cmp(&y.0).unwrap());
        }
    }

    // Compute list of partial product for high part blk ----------------------
    // Those blk aren't used for result but only for overflow flag computation
    if let Some(f) = flag {
        let pp_high_part_idx = (blk_w..2 * blk_w)
            .flat_map(|blk| {
                itertools::iproduct!(0..blk_w, 0..blk_w).filter(move |(i, j)| i + j == blk)
            })
            .collect::<Vec<_>>();

        // Check if any high_part pp is non-zero
        for pp in pp_high_part_idx.chunks(props.pbs_batch_w) {
            // Pack
            let pack = pp
                .iter()
                .map(|(i, j)| {
                    let mac = src_a[*i].mac(tfhe_params.msg_range() as u8, &src_b[*j]);
                    trace!(target: "Fw", "HighPart[{i}, {j}] -> {mac:?}",);
                    mac
                })
                .collect::<Vec<_>>();

            // Pbs HighPart non-zero
            prog.reg_bulk_reserve(props.pbs_batch_w);
            pack.into_iter().for_each(|x| {
                let non_zero = x.pbs(&pbs_mult_is_some, false);
                trace!(target: "Fw", "Pbs non-zero -> {non_zero:?}");
                ovf_non_zero_vars.push(non_zero);
            });
        }
        // Simple nu-based tree reduction
        while ovf_non_zero_vars.len() > 1 {
            let mut next_stg = Vec::with_capacity(ovf_non_zero_vars.len().div_ceil(props.nu));
            for chunk in ovf_non_zero_vars.into_iter().chunks(props.nu).into_iter() {
                let mut acc = chunk
                    .into_iter()
                    .reduce(|acc, x| &acc + &x)
                    .expect("Chunk shouldn't be empty");
                acc.pbs_assign(&pbs_is_some, false);
                next_stg.push(acc);
            }
            ovf_non_zero_vars = next_stg;
        }
        f.mv_assign(&ovf_non_zero_vars[0]);
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum ShiftKind {
    ShiftRight,
    ShiftLeft,
    RotRight,
    RotLeft,
}
#[derive(Debug, Clone, Copy)]
pub(super) enum CondPos {
    Pos0,
    Pos1,
}

// Comupute inner-shift
// input:
// * src: clean ciphertext with only message
// * amount: ciphertext encoding amount to Shift/Rotate. Only Lsb of msg will be considered
// output:
//  Tuple of msg and msg_next.
//   msg_next is the contribution of next ct block in the shift direction
fn inner_shift(
    prog: &mut Program,
    dir: ShiftKind,
    src: &metavar::MetaVarCell,
    amount: &metavar::MetaVarCell,
) -> (metavar::MetaVarCell, metavar::MetaVarCell) {
    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    let (pbs_msg, pbs_msg_next) = match dir {
        ShiftKind::ShiftRight | ShiftKind::RotRight => (
            new_pbs!(prog, "ShiftRightByCarryPos0Msg"),
            new_pbs!(prog, "ShiftRightByCarryPos0MsgNext"),
        ),
        ShiftKind::ShiftLeft | ShiftKind::RotLeft => (
            new_pbs!(prog, "ShiftLeftByCarryPos0Msg"),
            new_pbs!(prog, "ShiftLeftByCarryPos0MsgNext"),
        ),
    };

    let pack = amount.mac(tfhe_params.msg_range() as u8, src);
    let msg = pack.pbs(&pbs_msg, false);
    let msg_next = pack.pbs(&pbs_msg_next, false);
    (msg, msg_next)
}

// Conditional block swap
// Based on cond/cond_mask select block A (true) or block B (false);
fn block_swap(
    prog: &mut Program,
    src_orig: &metavar::MetaVarCell,
    src_swap: Option<&metavar::MetaVarCell>,
    cond: &metavar::MetaVarCell,
    cond_mask: CondPos,
) -> metavar::MetaVarCell {
    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    let (pbs_orig, pbs_swap) = match cond_mask {
        CondPos::Pos0 => (
            new_pbs!(prog, "IfPos0TrueZeroed"),
            new_pbs!(prog, "IfPos0FalseZeroed"),
        ),
        CondPos::Pos1 => (
            new_pbs!(prog, "IfPos1TrueZeroed"),
            new_pbs!(prog, "IfPos1FalseZeroed"),
        ),
    };
    let pack_orig = cond.mac(tfhe_params.msg_range() as u8, src_orig);
    if let Some(swap) = src_swap {
        let pack_swap = cond.mac(tfhe_params.msg_range() as u8, swap);
        &pack_orig.pbs(&pbs_orig, false) + &pack_swap.pbs(&pbs_swap, false)
    } else {
        pack_orig.pbs(&pbs_orig, false)
    }
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_shift_right(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // Src -> Operand
    let src = prog.iop_template_var(OperandKind::Src, 0);
    // Amount -> Operand
    let amount = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment("SHIFT_R Operand::Dst Operand::Src Operand::Src".to_string());
    // Deferred implementation to generic rotx function
    iop_shiftrotx(prog, ShiftKind::ShiftRight, &mut dst, &src, &amount);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_shift_left(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // Src -> Operand
    let src = prog.iop_template_var(OperandKind::Src, 0);
    // ShiftAmount -> Operand
    let amount = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment("SHIFT_L Operand::Dst Operand::Src Operand::Src".to_string());
    // Deferred implementation to generic rotx function
    iop_shiftrotx(prog, ShiftKind::ShiftLeft, &mut dst, &src, &amount);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_rotate_right(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // Src -> Operand
    let src = prog.iop_template_var(OperandKind::Src, 0);
    // ShiftAmount -> Operand
    let rot_amount = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment("ROT_R Operand::Dst Operand::Src Operand::Src".to_string());
    // Deferred implementation to generic rotx function
    iop_shiftrotx(prog, ShiftKind::RotRight, &mut dst, &src, &rot_amount);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_rotate_left(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // Src -> Operand
    let src = prog.iop_template_var(OperandKind::Src, 0);
    // ShiftAmount -> Operand
    let rot_amount = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment("ROT_L Operand::Dst Operand::Src Operand::Src".to_string());
    // Deferred implementation to generic rotx function
    iop_shiftrotx(prog, ShiftKind::RotLeft, &mut dst, &src, &rot_amount);
}

/// Generic shift function operation
#[instrument(level = "trace", skip(prog))]
fn iop_shiftrotx(
    prog: &mut Program,
    kind: ShiftKind,
    dst: &mut [metavar::MetaVarCell],
    src: &[metavar::MetaVarCell],
    amount: &[metavar::MetaVarCell],
) {
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
    for (d, s) in std::iter::zip(dst.iter_mut(), merge_shiftrot.iter()).rev() {
        s.reg_alloc_mv();
        d.mv_assign(s);
    }
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_shift_scalar_right(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // Src -> Operand
    let src = prog.iop_template_var(OperandKind::Src, 0);
    // Amount-> Immediate
    let amount = prog.iop_template_var(OperandKind::Imm, 0);

    // Add Comment header
    prog.push_comment("SHIFTS_R Operand::Dst Operand::Src Operand::Immediate".to_string());
    // Deferred implementation to generic rotx function
    iop_scalar_shiftrotx(prog, ShiftKind::ShiftRight, &mut dst, &src, &amount);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_shift_scalar_left(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // Src -> Operand
    let src = prog.iop_template_var(OperandKind::Src, 0);
    // Amount-> Immediate
    let amount = prog.iop_template_var(OperandKind::Imm, 0);

    // Add Comment header
    prog.push_comment("SHIFTS_L Operand::Dst Operand::Src Operand::Immediate".to_string());
    // Deferred implementation to generic rotx function
    iop_scalar_shiftrotx(prog, ShiftKind::ShiftLeft, &mut dst, &src, &amount);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_rotate_scalar_right(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // Src -> Operand
    let src = prog.iop_template_var(OperandKind::Src, 0);
    // Amount-> Immediate
    let amount = prog.iop_template_var(OperandKind::Imm, 0);

    // Add Comment header
    prog.push_comment("ROTS_R Operand::Dst Operand::Src Operand::Immediate".to_string());
    // Deferred implementation to generic rotx function
    iop_scalar_shiftrotx(prog, ShiftKind::RotRight, &mut dst, &src, &amount);
}
#[instrument(level = "trace", skip(prog))]
pub fn iop_rotate_scalar_left(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // Src -> Operand
    let src = prog.iop_template_var(OperandKind::Src, 0);
    // Amount-> Immediate
    let amount = prog.iop_template_var(OperandKind::Imm, 0);

    // Add Comment header
    prog.push_comment("ROTS_L Operand::Dst Operand::Src Operand::Immediate".to_string());
    // Deferred implementation to generic rotx function
    iop_scalar_shiftrotx(prog, ShiftKind::RotRight, &mut dst, &src, &amount);
}

/// Generic shift function over scalar
#[instrument(level = "trace", skip(prog))]
fn iop_scalar_shiftrotx(
    prog: &mut Program,
    dir: ShiftKind,
    dst: &mut [metavar::MetaVarCell],
    src: &[metavar::MetaVarCell],
    amount: &[metavar::MetaVarCell],
) {
    for i in 0..prog.params().min_iop_size {
        let _ = prog.new_cst(i);
    }
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_bw(prog: &mut Program, bw_op: Pbs) {
    // Dest -> Operand
    let dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Operand
    let src_b = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment(format!("BW_{bw_op} Operand::Dst Operand::Src Operand::Src"));

    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    // Wrapped given bw_op lookup table in MetaVar
    let bw_op = prog.var_from(Some(metavar::VarPos::Pbs(bw_op)));

    itertools::izip!(dst, src_a, src_b)
        .enumerate()
        .chunks(props.pbs_batch_w)
        .into_iter()
        .for_each(|chunk| {
            let chunk_pack = chunk
                .into_iter()
                .map(|(pos, (d, a, b))| (pos, d, a.mac(tfhe_params.msg_range() as u8, &b)))
                .collect::<Vec<_>>();
            chunk_pack.into_iter().for_each(|(pos, mut d, mut pack)| {
                pack.pbs_assign(&bw_op, pos == props.blk_w() - 1);
                d <<= pack;
            });
        });
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_cmp(prog: &mut Program, cmp_op: Pbs) {
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Operand
    let src_b = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment(format!(
        "CMP_{cmp_op} Operand::Dst Operand::Src Operand::Src"
    ));

    // Deferred implementation to generic cmpx function
    iop_cmpx(prog, &mut dst[0], &src_a, &src_b, cmp_op);
}

/// Generic Cmp operation
/// One destination block and two sources operands
/// Source could be Operand or Immediate
#[instrument(level = "trace", skip(prog))]
pub fn iop_cmpx(
    prog: &mut Program,
    dst: &mut metavar::MetaVarCell,
    src_a: &[metavar::MetaVarCell],
    src_b: &[metavar::MetaVarCell],
    cmp_op: Pbs,
) {
    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    // Wrapped given cmp_op and comp_sign lookup table in MetaVar
    let cmp_op = prog.var_from(Some(metavar::VarPos::Pbs(cmp_op)));
    let pbs_none = new_pbs!(prog, "None");
    let cmp_sign = new_pbs!(prog, "CmpSign");
    let cmp_reduce = new_pbs!(prog, "CmpReduce");

    // Pack A and B elements by pairs
    let packed = std::iter::zip(src_a.chunks(2), src_b.chunks(2))
        .enumerate()
        .map(|(pos, (a, b))| {
            let pack_a = if a.len() > 1 {
                // Reset noise for future block merge through sub
                a[1].mac(tfhe_params.msg_range() as u8, &a[0])
                    .pbs(&pbs_none, false)
            } else {
                a[0].clone()
            };

            let pack_b = if b.len() > 1 {
                b[1].mac(tfhe_params.msg_range() as u8, &b[0])
                    .pbs(&pbs_none, pos == (props.blk_w() / 2) - 1)
            } else {
                b[0].clone()
            };
            (pack_a, pack_b)
        })
        .collect::<Vec<_>>();

    let cst_1 = prog.new_imm(1);
    let merged = packed
        .into_iter()
        .enumerate()
        .chunks(props.pbs_batch_w)
        .into_iter()
        .flat_map(|chunk| {
            let chunk = chunk
                .map(|(pos, (mut a, b))| {
                    a -= b;
                    (pos, a)
                })
                .collect::<Vec<_>>();
            let chunk = chunk
                .into_iter()
                .map(|(pos, mut a)| {
                    a.pbs_assign(&cmp_sign, pos == props.blk_w().div_ceil(2) - 1);
                    a
                })
                .collect::<Vec<_>>();
            chunk.into_iter().map(|mut a| {
                a += cst_1.clone();
                a
            })
        })
        .collect::<Vec<_>>();

    let reduce = merged.into_iter().reduce(|acc, x| {
        x.mac(tfhe_params.msg_range() as u8, &acc)
            .pbs(&cmp_reduce, true)
    });

    // interpret reduce with expected cmp
    let cmp = reduce.unwrap().pbs(&cmp_op, true);
    dst.mv_assign(&cmp);
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_if_then_zero(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src = prog.iop_template_var(OperandKind::Src, 0);
    // Cond -> Operand
    // second operand must be a FheBool and have only one blk
    let cond = {
        let mut cond_blk = prog.iop_template_var(OperandKind::Src, 1);
        cond_blk.truncate(1);
        cond_blk.pop().unwrap()
    };

    // Add Comment header
    prog.push_comment("IF_THEN_ZERO Operand::Dst Operand::Src Operand::Src[Condition]".to_string());

    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    // Wrapped required lookup table in MetaVar
    let pbs_if_false_zeroed = new_pbs!(prog, "IfFalseZeroed");

    itertools::izip!(dst, src)
        .enumerate()
        .chunks(props.pbs_batch_w)
        .into_iter()
        .for_each(|chunk| {
            // Pack (cond, src)
            let chunk_pack = chunk
                .into_iter()
                .map(|(pos, (d, src))| (pos, d, cond.mac(tfhe_params.msg_range() as u8, &src)))
                .collect::<Vec<_>>();

            chunk_pack
                .into_iter()
                .for_each(|(pos, mut d, mut cond_src)| {
                    cond_src.pbs_assign(&pbs_if_false_zeroed, pos == props.blk_w() - 1);
                    d <<= cond_src;
                });
        });
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_if_then_else(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Operand
    let src_b = prog.iop_template_var(OperandKind::Src, 1);
    // Cond -> Operand
    // Third operand must be a FheBool and have only one blk
    let cond = {
        let mut cond_blk = prog.iop_template_var(OperandKind::Src, 2);
        cond_blk.truncate(1);
        cond_blk.pop().unwrap()
    };

    // Add Comment header
    prog.push_comment(
        "IF_THEN_ELSE Operand::Dst Operand::Src Operand::Src Operand::Src[Condition]".to_string(),
    );

    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    // Wrapped required lookup table in MetaVar
    let pbs_if_true_zeroed = new_pbs!(prog, "IfTrueZeroed");
    let pbs_if_false_zeroed = new_pbs!(prog, "IfFalseZeroed");

    itertools::izip!(dst, src_a, src_b)
        .enumerate()
        .chunks(props.pbs_batch_w)
        .into_iter()
        .for_each(|chunk| {
            // Pack (cond, a), (cond, b)
            let chunk_pack = chunk
                .into_iter()
                .map(|(pos, (d, a, b))| {
                    (
                        pos,
                        d,
                        cond.mac(tfhe_params.msg_range() as u8, &a),
                        cond.mac(tfhe_params.msg_range() as u8, &b),
                    )
                })
                .collect::<Vec<_>>();
            chunk_pack
                .into_iter()
                .for_each(|(pos, mut d, mut cond_a, mut cond_b)| {
                    cond_a.pbs_assign(&pbs_if_false_zeroed, false);
                    cond_b.pbs_assign(&pbs_if_true_zeroed, pos == props.blk_w() - 1);
                    d <<= &cond_a + &cond_b;
                });
        });
}

/// Implement erc_20 fund xfer
/// Targeted algorithm is as follow:
/// 1. Check that from has enough funds
/// 2. Compute real_amount to xfer (i.e. amount or 0)
/// 3. Compute new amount (from - new_amount, to + new_amount)
#[instrument(level = "info", skip(prog))]
pub fn iop_erc_20(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst_from = prog.iop_template_var(OperandKind::Dst, 0);
    let mut dst_to = prog.iop_template_var(OperandKind::Dst, 1);
    // Src -> Operand
    let src_from = prog.iop_template_var(OperandKind::Src, 0);
    let src_to = prog.iop_template_var(OperandKind::Src, 1);
    // Src Amount -> Operand
    let src_amount = prog.iop_template_var(OperandKind::Src, 2);

    // Add Comment header
    prog.push_comment("ERC_20 (new_from, new_to) <- (from, to, amount)".to_string());

    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    // Wrapped required lookup table in MetaVar
    let pbs_msg = new_pbs!(prog, "MsgOnly");
    let pbs_carry = new_pbs!(prog, "CarryInMsg");
    let pbs_if_false_zeroed = new_pbs!(prog, "IfFalseZeroed");

    // Check if from has enough funds
    let enough_fund = {
        let mut dst = prog.new_var();
        iop_cmpx(
            prog,
            &mut dst,
            &src_from,
            &src_amount,
            asm::dop::PbsCmpGte::default().into(),
        );
        dst
    };

    // Fuse real_amount computation and new_from, new_to
    // First compute a batch of real_amount in advance
    let mut real_amount_work = (0..props.blk_w()).peekable();
    let mut upfront_work = real_amount_work.by_ref().take(props.pbs_batch_w).peekable();
    prog.push_comment(" ==> Compute some real_amount in advance".to_string());
    let mut real_amount = VecDeque::new();
    while let Some(blk) = upfront_work.next() {
        let mut val_cond = enough_fund.mac(tfhe_params.msg_range() as u8, &src_amount[blk]);
        val_cond.pbs_assign(&pbs_if_false_zeroed, upfront_work.peek().is_none());
        real_amount.push_back(val_cond);
    }

    let mut add_carry: Option<metavar::MetaVarCell> = None;

    let mut sub_z_cor: Option<usize> = None;
    let mut sub_carry: Option<metavar::MetaVarCell> = None;

    (0..prog.params().blk_w()).for_each(|blk| {
        prog.push_comment(format!(" ==> Work on output block {blk}"));

        // Compte next real_amount if any
        if let Some(work) = real_amount_work.next() {
            let mut val_cond = enough_fund.mac(tfhe_params.msg_range() as u8, &src_amount[work]);
            val_cond.pbs_assign(&pbs_if_false_zeroed, false);
            real_amount.push_back(val_cond);
        }
        let amount_blk = real_amount.pop_front().unwrap();

        // Add
        let mut add_msg = &src_to[blk] + &amount_blk;
        if let Some(cin) = &add_carry {
            add_msg += cin.clone();
        }
        if blk < (props.blk_w() - 1) {
            add_carry = Some(add_msg.pbs(&pbs_carry, false));
        }
        // Force allocation of new reg to allow carry/msg pbs to run in //
        let add_msg = add_msg.pbs(&pbs_msg, false);

        // Sub
        // Compute -b
        let neg_from = if let Some(z) = &sub_z_cor {
            prog.new_imm(tfhe_params.msg_range() - *z)
        } else {
            prog.new_imm(tfhe_params.msg_range())
        };
        let amount_neg = &neg_from - &amount_blk;

        sub_z_cor = Some(
            amount_blk
                .get_degree()
                .div_ceil(tfhe_params.msg_range())
                .max(1),
        );

        // Compute a + (-b)
        let mut sub_msg = &src_from[blk] + &amount_neg;

        // Handle input/output carry and extract msg
        if let Some(cin) = &sub_carry {
            sub_msg += cin.clone();
        }
        if blk < (props.blk_w() - 1) {
            sub_carry = Some(sub_msg.pbs(&pbs_carry, false));
        }
        // Force allocation of new reg to allow carry/msg pbs to run in //
        let sub_msg = sub_msg.pbs(&pbs_msg, true);

        // Store result
        dst_to[blk] <<= add_msg;
        dst_from[blk] <<= sub_msg;
    });
}

/// Implement memcpy operation
/// Utilities IOp used to duplicate a ciphertext when already uploaded on HPU
/// Use to enforce clone semantic at the HL-Api level
#[instrument(level = "info", skip(prog))]
pub fn iop_memcpy(prog: &mut Program) {
    // Allocate metavariables:
    let dst = prog.iop_template_var(OperandKind::Dst, 0);
    let src = prog.iop_template_var(OperandKind::Src, 0);

    // NB: Move from memory -> memory isn't supported by HPU
    // Thus we have to go through register file and LD->RegFile->ST
    // Memcpy is a small IOp and could triggered issue with `min_iop_size`
    // If required padded the iop with linear operaation
    let iop_len = src.len().min(dst.len()) * 2;
    for _ in 0..(prog.params().min_iop_size as isize - iop_len as isize) {
        let _ = prog.new_cst(0);
    }

    for (mut d, s) in itertools::izip!(dst, src) {
        s.reg_alloc_mv();
        d <<= s;
    }
}
