use super::*;
use crate::asm::OperandKind;
use crate::fw::program::Program;

use crate::asm::dop::pbs_macro;
use crate::asm::iop::opcode::*;
use crate::new_pbs;

crate::impl_fw!("Demo" [
    ADD => fw_impl::ilp::iop_add;
    SUB => fw_impl::ilp::iop_sub;
    MUL => fw_impl::ilp::iop_mul;
    DIV => fw_impl::ilp_div::iop_div;
    MOD => fw_impl::ilp_div::iop_mod;

    ADDS => fw_impl::ilp::iop_adds;
    SUBS => fw_impl::ilp::iop_subs;
    SSUB => fw_impl::ilp::iop_ssub;
    MULS => fw_impl::ilp::iop_muls;
    DIVS => fw_impl::ilp_div::iop_divs;
    MODS => fw_impl::ilp_div::iop_mods;

    BW_AND => (|prog| {fw_impl::ilp::iop_bw(prog, asm::dop::PbsBwAnd::default().into())});
    BW_OR  => (|prog| {fw_impl::ilp::iop_bw(prog, asm::dop::PbsBwOr::default().into())});
    BW_XOR => (|prog| {fw_impl::ilp::iop_bw(prog, asm::dop::PbsBwXor::default().into())});

    CMP_LTE => (|prog| {fw_impl::ilp::iop_cmp(prog, asm::dop::PbsCmpLte::default().into())});
    CMP_EQ  => (|prog| {fw_impl::ilp::iop_cmp(prog, asm::dop::PbsCmpEq::default().into())});
    CMP_NEQ => (|prog| {fw_impl::ilp::iop_cmp(prog, asm::dop::PbsCmpNeq::default().into())});

    IF_THEN_ZERO => fw_impl::ilp::iop_if_then_zero;
    IF_THEN_ELSE => fw_impl::ilp::iop_if_then_else;

    ERC_20 => fw_impl::ilp::iop_erc_20;

    CMP_GT  => cmp_gt;
    CMP_GTE => cmp_gte;
    CMP_LT  => cmp_lt;

    COUNT0 => fw_impl::ilp_log::iop_count0;
    COUNT1 => fw_impl::ilp_log::iop_count1;
    ILOG2 => fw_impl::ilp_log::iop_ilog2;
    LEAD0 => fw_impl::ilp_log::iop_lead0;
    LEAD1 => fw_impl::ilp_log::iop_lead1;
    TRAIL0 => fw_impl::ilp_log::iop_trail0;
    TRAIL1 => fw_impl::ilp_log::iop_trail1;

]);

// Recursive {{{1
pub fn cmp_gt(prog: &mut Program) {
    // Create Input/Output template entry points to be linked at execution time.
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    let src_b = prog.iop_template_var(OperandKind::Src, 1);

    // Get the index of the required PBSs
    let sgn_pbs = new_pbs!(prog, "CmpSign");
    let red_pbs = new_pbs!(prog, "CmpReduce");
    let gt_pbs = new_pbs!(prog, "CmpGt");

    dst[0] <<= std::iter::zip(src_a, src_b)
        .rev()
        .fold(prog.new_imm(pbs_macro::CMP_EQUAL), |acc, (a, b)| {
            (&(&a - &b).pbs(&sgn_pbs, false) + &prog.new_imm(1))
                .pack_carry(&acc)
                .pbs(&red_pbs, false)
        })
        .pbs(&gt_pbs, false);
}
// }}}

// Parallel {{{
pub fn cmp_gte(prog: &mut Program) {
    // Allocate metavariables:
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    let src_b = prog.iop_template_var(OperandKind::Src, 1);

    // Allocate the needed PBSs
    let sgn_pbs = new_pbs!(prog, "CmpSign");
    let red_pbs = new_pbs!(prog, "CmpReduce");
    let gte_pbs = new_pbs!(prog, "CmpGte");

    let mut ord_vec: Vec<_> = std::iter::zip(src_a, src_b)
        .map(|(a, b)| &(&a - &b).pbs(&sgn_pbs, false) + &prog.new_imm(1))
        .collect();

    while ord_vec.len() > 1 {
        ord_vec = ord_vec
            .chunks(2)
            .map(|c| {
                let v: Vec<_> = c.into();
                match v.len() {
                    2 => v[0].pack_carry(&v[1]).pbs(&red_pbs, false),
                    1 => v[0].clone(),
                    _ => panic!("chunks misbehaved"),
                }
            })
            .collect();
    }

    dst[0] <<= ord_vec[0].pbs(&gte_pbs, true);
}
// }}}

// Parallel with flushes and without the extra last PBS {{{1
pub fn cmp_lt(prog: &mut Program) {
    // Allocate metavariables:
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    let src_b = prog.iop_template_var(OperandKind::Src, 1);

    // Allocate the needed PBSs
    let sgn_pbs = new_pbs!(prog, "CmpSign");
    let red_pbs = new_pbs!(prog, "CmpReduce");
    let lt_pbs = new_pbs!(prog, "CmpLtMrg");

    let end = src_a.len() - 1;

    let mut ord_vec: Vec<_> = std::iter::zip(src_a, src_b)
        .enumerate()
        .map(|(i, x)| (i == end, x))
        .map(|(flush, (a, b))| &(&a - &b).pbs(&sgn_pbs, flush) + &prog.new_imm(1))
        .collect();

    while ord_vec.len() > 2 {
        let end = ord_vec.len().div_ceil(2) - 1;
        ord_vec = ord_vec
            .chunks(2)
            .enumerate()
            .map(|(i, x)| (i == end, x))
            .map(|(flush, c)| {
                let v: Vec<_> = c.into();
                match v.len() {
                    2 => v[0].pack_carry(&v[1]).pbs(&red_pbs, flush),
                    1 => v[0].clone(),
                    _ => panic!("chunks misbehaved"),
                }
            })
            .collect();
    }

    dst[0] <<= ord_vec[0].pack_carry(&ord_vec[1]).pbs(&lt_pbs, true);
}
//}}}

// vim: foldmethod=marker
