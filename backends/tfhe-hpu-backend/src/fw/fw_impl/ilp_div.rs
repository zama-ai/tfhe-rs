//!
//! Implementation of Ilp firmware for division, and modulo
//!
//! In this version of the Fw focus is done on Instruction Level Parallelism
use std::cmp::Ordering;
use std::collections::VecDeque;

use super::*;
use crate::asm::{self, OperandKind};
use crate::fw::fw_impl::ilp_log;
use crate::fw::program::Program;
use tracing::{instrument, warn};

use crate::new_pbs;

#[instrument(level = "trace", skip(prog))]
pub fn iop_div(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst_quotient = prog.iop_template_var(OperandKind::Dst, 0);
    let mut dst_remain = prog.iop_template_var(OperandKind::Dst, 1);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment("DIV Operand::Dst Operand::Src Operand::Src".to_string());
    // Deferred implementation to generic divx function
    iop_divx(prog, &mut dst_quotient, &mut dst_remain, &src_a, &src_b);
}

pub fn iop_divs(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst_quotient = prog.iop_template_var(OperandKind::Dst, 0);
    let mut dst_remain = prog.iop_template_var(OperandKind::Dst, 1);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Imm, 0);

    // Add Comment header
    prog.push_comment("DIVS Operand::Dst Operand::Src Operand::Immediate".to_string());
    // Deferred implementation to generic divx function
    // TODO: do computation on immediate directly for more efficiency.
    // Workaround: transform immediate into ct.
    let cst_0 = prog.new_cst(0);
    let src_imm: Vec<metavar::MetaVarCell> = src_b.iter().map(|imm| imm + &cst_0).collect();
    iop_divx(prog, &mut dst_quotient, &mut dst_remain, &src_a, &src_imm);
}

/// Generic div operation
/// One destination and two sources operation
/// Source could be Operand or Immediate
pub fn iop_divx(
    prog: &mut Program,
    dst_quotient: &mut [metavar::MetaVarCell],
    dst_remain: &mut [metavar::MetaVarCell],
    src_a: &[metavar::MetaVarCell],
    src_b: &[metavar::MetaVarCell],
) {
    let result = iop_div_corev(prog, src_a, src_b, Some(DivCoreOutput::All));
    let quotient_a = result[0].clone();
    let remain_a = result[1].clone();
    (0..prog.params().blk_w()).rev().for_each(|blk| {
        quotient_a[blk].reg_alloc_mv();
        dst_quotient[blk].mv_assign(&quotient_a[blk]);
    });
    (0..prog.params().blk_w()).for_each(|blk| {
        remain_a[blk].reg_alloc_mv();
        dst_remain[blk].mv_assign(&remain_a[blk]);
    });
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_mod(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst_remain = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment("MOD Operand::Dst Operand::Src Operand::Src".to_string());
    // Deferred implementation to generic modx function
    iop_modx(prog, &mut dst_remain, &src_a, &src_b);
}

pub fn iop_mods(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst_remain = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediate
    let src_b = prog.iop_template_var(OperandKind::Imm, 0);

    // Add Comment header
    prog.push_comment("MODS Operand::Dst Operand::Src Operand::Immediate".to_string());
    // Deferred implementation to generic modx function
    // TODO: do computation on immediate directly for more efficiency.
    // Workaround: transform immediate into ct.
    let cst_0 = prog.new_cst(0);
    let src_imm: Vec<metavar::MetaVarCell> = src_b.iter().map(|imm| imm + &cst_0).collect();
    iop_modx(prog, &mut dst_remain, &src_a, &src_imm);
}

/// Generic mod operation
/// One destination and two sources operation
/// Source could be Operand or Immediate
pub fn iop_modx(
    prog: &mut Program,
    dst_remain: &mut [metavar::MetaVarCell],
    src_a: &[metavar::MetaVarCell],
    src_b: &[metavar::MetaVarCell],
) {
    let result = iop_div_corev(prog, src_a, src_b, Some(DivCoreOutput::Remain));
    let remain_a = result[0].clone();
    (0..prog.params().blk_w()).for_each(|blk| {
        remain_a[blk].reg_alloc_mv();
        dst_remain[blk].mv_assign(&remain_a[blk]);
    });
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AddHSPostProcess {
    NoPostProcess,
    CleanCt,
    CleanCtButLast,
}

#[instrument(level = "trace", skip(prog))]
/// Add 2 integers, using the Hillis Steel method.
/// Outputs a list containing the resulting blocks.
/// clean_ct : option to clean the ct at the output.
/// Note that if the ct is not cleaned, its noise
/// has increased by 2 additions, compared to the input.
pub fn iop_add_hillissteel_v(
    prog: &mut Program,
    src_a: &[metavar::MetaVarCell],
    src_b: &[metavar::MetaVarCell],
    post_process: Option<AddHSPostProcess>, // default is CleanCt
) -> Vec<metavar::MetaVarCell> {
    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    let pbs_many_carry_msg = new_pbs!(prog, "ManyCarryMsg");
    let pbs_msg_only = new_pbs!(prog, "MsgOnly");
    let pbs_reduce_carry_pad = new_pbs!(prog, "ReduceCarryPad");
    let pbs_solve_prop = new_pbs!(prog, "SolveProp");
    let pbs_solve_prop_carry = new_pbs!(prog, "SolvePropCarry");
    let pbs_solve_prop_group_final0 = new_pbs!(prog, "SolvePropGroupFinal0");
    let pbs_solve_prop_group_final1 = new_pbs!(prog, "SolvePropGroupFinal1");
    let pbs_solve_prop_group_final2 = new_pbs!(prog, "SolvePropGroupFinal2");
    let pbs_extract_prop_group_0 = new_pbs!(prog, "ExtractPropGroup0");
    let pbs_extract_prop_group_1 = new_pbs!(prog, "ExtractPropGroup1");
    let pbs_extract_prop_group_2 = new_pbs!(prog, "ExtractPropGroup2");
    let pbs_extract_prop_group_3 = new_pbs!(prog, "ExtractPropGroup3");

    let pbs_solve_prop_group_final_v = [
        pbs_solve_prop_group_final0,
        pbs_solve_prop_group_final1,
        pbs_solve_prop_group_final2,
    ];
    let pbs_extract_prop_group_v = [
        pbs_extract_prop_group_0,
        pbs_extract_prop_group_1,
        pbs_extract_prop_group_2,
        pbs_extract_prop_group_3,
    ];

    // Step 1
    // Add blocks.
    // Also handle src of different sizes.
    let long_src;
    let short_src;
    let add_size = match src_a.len().cmp(&src_b.len()) {
        Ordering::Less => {
            long_src = src_b;
            short_src = src_a;
            src_a.len()
        }
        _ => {
            long_src = src_a;
            short_src = src_b;
            src_b.len()
        }
    };

    let mut sum_a: Vec<metavar::MetaVarCell> = Vec::new();
    long_src.iter().zip(short_src.iter()).for_each(|(a, b)| {
        let s = a + b;
        sum_a.push(s);
    });
    long_src[add_size..].iter().for_each(|x| {
        sum_a.push(x.clone());
    });

    // Use Hillis Steel propagation on groups of 4 blocks,
    // with TFHE.rs propagate flag encoding.
    let mut prop_group_a: Vec<metavar::MetaVarCell> = Vec::new();
    let mut msg0 = None; // Store msg part of very first block
                         // of each group
                         // Extract propagation status of each ct.
                         // Place it at the correct position, for next step.
    sum_a.chunks(4).enumerate().for_each(|(c_idx, chk)| {
        chk.iter().enumerate().for_each(|(idx, v)| {
            if c_idx == 0 {
                // Proceed differently for the 1rst group
                // [0] carry is already known.
                if idx == 0 {
                    let mut it = v.pbs_many(&pbs_many_carry_msg, false).into_iter();
                    msg0 = it.next();
                    let prop_carry = it.next().unwrap();
                    prop_group_a.push(prop_carry.clone());
                } else {
                    let prop = v.pbs(&pbs_extract_prop_group_v[idx - 1], false);
                    prop_group_a.push(prop.clone());
                }
            } else {
                let prop = v.pbs(&pbs_extract_prop_group_v[idx % 4], false);
                prop_group_a.push(prop.clone());
            }
        });
    });
    let msg0 = msg0.unwrap();

    // Solve propagation status within each group
    // prop_group_a [0,1,2] contains the sum of the propagation status
    // at each step.
    // [3] contains the propagation status of the group of 4.
    // Note that group #0 is particular, since the status is actually
    // the carry value.
    let mut group_prop_a: Vec<metavar::MetaVarCell> = Vec::new();
    prop_group_a
        .chunks_mut(4)
        .enumerate()
        .for_each(|(c_idx, chk)| {
            chk.iter_mut().enumerate().fold(None, |acc, (idx, p)| {
                if let Some(x) = acc {
                    let sum = &x + &*p;
                    if idx < 3 {
                        // Store the sum. Will be processed later.
                        group_prop_a.push(sum.clone());
                    } else if c_idx == 0 {
                        // Solve carry directly
                        let group_carry = sum.pbs(&pbs_solve_prop_group_final_v[3 - 1], false);
                        group_prop_a.push(group_carry.clone());
                    } else {
                        let cst_1 = prog.new_imm(1);
                        let mut group_prop = sum.pbs(&pbs_reduce_carry_pad, false);
                        group_prop = &group_prop + &cst_1;
                        group_prop_a.push(group_prop.clone());
                    }
                    Some(sum)
                } else {
                    group_prop_a.push(p.clone());
                    Some(p.clone())
                }
            });
        });

    // Solve propagate status on each group.
    // Will end with a carry info for each group
    let group_nb = group_prop_a.len().div_ceil(4);
    let step_nb = (group_nb as f32).log2().ceil() as usize;
    (0..step_nb).for_each(|step| {
        let stride = 2_u32.pow(step as u32) as usize;
        let mut p_a: VecDeque<metavar::MetaVarCell> = VecDeque::new();
        (stride..group_nb).step_by(stride).for_each(|g_idx| {
            for k in 0..stride {
                let neigh_prop = group_prop_a.get((g_idx + k - stride) * 4 + 3);
                let prop = group_prop_a.get((g_idx + k) * 4 + 3);
                let mut ct;
                if let Some(x) = prop {
                    ct = x.mac(tfhe_params.msg_range() as u8, neigh_prop.unwrap());
                } else {
                    continue;
                }
                if g_idx == stride {
                    // Solve carry
                    ct = ct.pbs(&pbs_solve_prop_carry, false);
                } else {
                    ct = ct.pbs(&pbs_solve_prop, false);
                }
                p_a.push_back(ct);
            }
        });
        for idx in 0..p_a.len() {
            group_prop_a[(stride + idx) * 4 + 3] = p_a.pop_front().unwrap(); // Fill with new values
                                                                             // for next step
        }
    });

    // Final resolution
    let mut carry_a: Vec<metavar::MetaVarCell> = Vec::new();
    (0..group_prop_a.len()).for_each(|idx| {
        match idx {
            0 => carry_a.push(group_prop_a[0].clone()),
            1 | 2 => {
                let ct = group_prop_a[idx].pbs(&pbs_solve_prop_group_final_v[idx - 1], false);
                carry_a.push(ct);
            }
            _ => {
                if (idx % 4) == 3 {
                    // already solved
                    carry_a.push(group_prop_a[idx].clone());
                } else {
                    let mut ct = &group_prop_a[idx] + &group_prop_a[idx - idx % 4 - 1];
                    ct = ct.pbs(&pbs_solve_prop_group_final_v[idx % 4], false);
                    carry_a.push(ct);
                }
            }
        };
    });

    // Addition with carry
    let mut res: Vec<metavar::MetaVarCell> = Vec::new();
    res.push(msg0);

    for (idx, ct) in sum_a.iter().skip(1).enumerate() {
        let mut s = ct + &carry_a[idx];
        let pp = post_process.unwrap_or(AddHSPostProcess::CleanCt);
        if (pp == AddHSPostProcess::CleanCt)
            || (pp == AddHSPostProcess::CleanCtButLast && idx < sum_a.len() - 2)
        {
            s = s.pbs(&pbs_msg_only, false);
        }
        res.push(s);
    }

    res
}

#[instrument(level = "trace", skip(prog))]
/// Outputs a tuple corresponding to (src x2, src x3)
pub fn iop_x2_x3v(
    prog: &mut Program,
    src: &[metavar::MetaVarCell],
) -> (Vec<metavar::MetaVarCell>, Vec<metavar::MetaVarCell>) {
    //let props = prog.params();
    //let tfhe_params: asm::DigitParameters = props.clone().into();

    let pbs_many_msg_split_shift1 = new_pbs!(prog, "ManyMsgSplitShift1");

    // First step
    // Compute x2
    let mut x2_a: Vec<metavar::MetaVarCell> = Vec::new(); // Will contain lsb part of the msg
    let last_msb = src.iter().fold(None, |prev_msb, x| {
        let mut it = x.pbs_many(&pbs_many_msg_split_shift1, false).into_iter();
        let mut lsb = it.next().unwrap();
        let msb = it.next().unwrap();
        if let Some(v) = prev_msb {
            lsb += v; // add with previous msb
        }
        x2_a.push(lsb);
        Some(msb)
    });
    x2_a.push(last_msb.unwrap());

    // Second step compute x3
    let x3_a = iop_add_hillissteel_v(prog, &x2_a, src, Some(AddHSPostProcess::CleanCt));

    (x2_a, x3_a)
}

#[instrument(level = "trace", skip(prog))]
/// Compute the negative value, in 2s complement of the input.
/// The input is assumed to be positive.
/// An additional ct is added in the MSB for the sign.
/// Note that the carry propagation is not done here.
/// The noise introduced corresponds to 1 addition.
pub fn iop_opposite_nopropv(
    prog: &mut Program,
    src: &[metavar::MetaVarCell],
) -> Vec<metavar::MetaVarCell> {
    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    let cst_msg = prog.new_imm(tfhe_params.msg_range());
    let cst_msg_m1 = prog.new_imm(tfhe_params.msg_range() - 1);
    let mut m_src_a: Vec<metavar::MetaVarCell> = Vec::new();

    let ct = &cst_msg - &src[0];
    m_src_a.push(ct);

    for ct in src.iter().skip(1) {
        let tmp = &cst_msg_m1 - ct;
        m_src_a.push(tmp);
    }

    // Add the sign
    // Create sign cst backed in register
    let sign = prog.new_cst(tfhe_params.msg_range() - 1);
    m_src_a.push(sign);
    m_src_a
}

/// Initialize the division.
/// It computes:
/// * keep_div : boolean to keep the division result, or set the default value.
/// * div_x1_is_not_null_a : list of booleans indicating if the divider is null from a certain block
///   position.
/// * div_x2_is_not_null_a : list of booleans indicating if the divider x2 is null from a certain
///   block position.
/// * div_x3_is_not_null_a : list of booleans indicating if the divider x3 is null from a ce;rtain
///   block position.
/// * mdiv_x1_a : opposite value of divider
/// * mdiv_x2_a : opposite value of divider x2
/// * mdiv_x3_a : opposite value of divider x3
pub struct IopDivInitStruct {
    keep_div: metavar::MetaVarCell,
    div_x2_a: Vec<metavar::MetaVarCell>,
    div_x3_a: Vec<metavar::MetaVarCell>,
    div_x1_is_not_null_a: Vec<metavar::MetaVarCell>,
    div_x2_is_not_null_a: Vec<metavar::MetaVarCell>,
    div_x3_is_not_null_a: Vec<metavar::MetaVarCell>,
    mdiv_x1_a: Vec<metavar::MetaVarCell>,
    mdiv_x2_a: Vec<metavar::MetaVarCell>,
    mdiv_x3_a: Vec<metavar::MetaVarCell>,
}
pub fn iop_div_initv(prog: &mut Program, div_x1_a: &[metavar::MetaVarCell]) -> IopDivInitStruct {
    //let props = prog.params();
    //let tfhe_params: asm::DigitParameters = props.clone().into();

    // Note that div_x2 and div_x3 has an additional ct in msb
    let (div_x2_a, div_x3_a) = iop_x2_x3v(prog, div_x1_a);

    let div_x1_is_not_null_a = ilp_log::iop_propagate_msb_to_lsb_blockv(
        prog,
        div_x1_a,
        &Some(ilp_log::BitType::One),
        &Some(false),
        &Some(false),
    );
    let div_x2_is_not_null_a = ilp_log::iop_propagate_msb_to_lsb_blockv(
        prog,
        &div_x2_a,
        &Some(ilp_log::BitType::One),
        &Some(false),
        &Some(false),
    );
    let div_x3_is_not_null_a = ilp_log::iop_propagate_msb_to_lsb_blockv(
        prog,
        &div_x3_a,
        &Some(ilp_log::BitType::One),
        &Some(false),
        &Some(false),
    );

    // If the divider is null set quotient to 0
    let keep_div = div_x1_is_not_null_a[0].clone();

    // During the operation, we need to subtract div_x1, div_x2, and div_x3.
    // Compute here (-div_x1), (-div_x2), (-div_x3) in 2s complement.
    // Note that the opposite values have an additional ct for the sign.
    let mdiv_x1_a = iop_opposite_nopropv(prog, div_x1_a);
    let mdiv_x2_a = iop_opposite_nopropv(prog, &div_x2_a);
    let mdiv_x3_a = iop_opposite_nopropv(prog, &div_x3_a);

    IopDivInitStruct {
        keep_div,
        div_x2_a,
        div_x3_a,
        div_x1_is_not_null_a,
        div_x2_is_not_null_a,
        div_x3_is_not_null_a,
        mdiv_x1_a,
        mdiv_x2_a,
        mdiv_x3_a,
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IfThenElse0Select {
    SelPos0Msg,       // Select bool in position 0 of carry part, output msg
    SelPos1Msg,       // Select bool in position 1 of carry part, output msg
    SelPos1MsgCarry1, // Select bool in position 1 of carry part, output msg + 1bit of carry
}

#[instrument(level = "trace", skip(prog))]
/// select is a boolean.
/// There several select type. See IfThenElse0Select description.
pub fn iop_if_then_else_0v(
    prog: &mut Program,
    src: &[metavar::MetaVarCell],
    select: &metavar::MetaVarCell,
    select_type: Option<IfThenElse0Select>, // Default SelPos0Msg
) -> Vec<metavar::MetaVarCell> {
    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    let pbs_if_false_zeroed = new_pbs!(prog, "IfFalseZeroed");
    let pbs_if_pos1_false_zeroed = new_pbs!(prog, "IfPos1FalseZeroed");
    let pbs_if_pos1_false_zeroed_msg_carry1 = new_pbs!(prog, "IfPos1FalseZeroedMsgCarry1");

    src.iter()
        .map(|ct| {
            let x = select.mac(tfhe_params.msg_range() as u8, ct);
            match select_type.unwrap_or(IfThenElse0Select::SelPos0Msg) {
                IfThenElse0Select::SelPos0Msg => x.pbs(&pbs_if_false_zeroed, false),
                IfThenElse0Select::SelPos1Msg => x.pbs(&pbs_if_pos1_false_zeroed, false),
                IfThenElse0Select::SelPos1MsgCarry1 => {
                    x.pbs(&pbs_if_pos1_false_zeroed_msg_carry1, false)
                }
            }
        })
        .collect::<Vec<_>>()
}

// Division core function.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DivCoreOutput {
    All,      // Output quotient and remain
    Quotient, // Output quotient
    Remain,   // Output remain
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_div_corev(
    prog: &mut Program,
    src_a: &[metavar::MetaVarCell],
    src_b: &[metavar::MetaVarCell],
    div_output: Option<DivCoreOutput>, // Default All
) -> Vec<Vec<metavar::MetaVarCell>> {
    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    // Wrapped required lookup table in MetaVar
    let pbs_msg_not_null_pos1 = new_pbs!(prog, "MsgNotNullPos1");
    let pbs_is_null_pos1 = new_pbs!(prog, "IsNullPos1");
    let pbs_xor = new_pbs!(prog, "BwXor");
    let pbs_none = new_pbs!(prog, "None");
    let pbs_solve_quotient_pos1 = new_pbs!(prog, "SolveQuotientPos1");

    // Renaming for clarity
    let num_a = src_a;
    let div_x1_a = src_b.to_vec();

    // Compute type.
    let res_type = div_output.unwrap_or(DivCoreOutput::All);

    // Initialization
    let init = iop_div_initv(prog, &div_x1_a);
    let keep_div = init.keep_div;
    let div_x2_a = init.div_x2_a;
    let div_x3_a = init.div_x3_a;
    let div_x1_is_not_null_a = init.div_x1_is_not_null_a;
    let div_x2_is_not_null_a = init.div_x2_is_not_null_a;
    let div_x3_is_not_null_a = init.div_x3_is_not_null_a;
    let mdiv_x1_a = init.mdiv_x1_a;
    let mdiv_x2_a = init.mdiv_x2_a;
    let mdiv_x3_a = init.mdiv_x3_a;

    let div_x_v = [div_x1_a, div_x2_a, div_x3_a];
    let div_x_is_not_null_v = [
        div_x1_is_not_null_a,
        div_x2_is_not_null_a,
        div_x3_is_not_null_a,
    ];
    let mdiv_x_v = [mdiv_x1_a, mdiv_x2_a, mdiv_x3_a];

    // Loop
    let mut quotient_a: Vec<metavar::MetaVarCell> = Vec::new();
    let mut remain_a: Vec<metavar::MetaVarCell> = Vec::new();
    let cst_sign = prog.new_cst(tfhe_params.msg_range() - 1);

    for loop_idx in 0..num_a.len() {
        let block_nb = loop_idx + 1;
        let mut entry_num: Vec<metavar::MetaVarCell> = Vec::new();
        entry_num.push(num_a[num_a.len() - 1 - loop_idx].clone());
        entry_num.append(&mut remain_a);
        remain_a = entry_num; // rename

        let mut diff_x_v: Vec<Vec<metavar::MetaVarCell>> = Vec::new();
        let mut r_lt_div_x_v: Vec<metavar::MetaVarCell> = Vec::new();

        diff_x_v.push(remain_a.clone()); // Corresponds to remain - (div * 0)
        for xi in 0..3 {
            // for x1, x2, x3
            // Step 1
            // Sign extension
            let mut ext_mdiv_x_a: Vec<metavar::MetaVarCell> = Vec::new();
            for (_k, ct) in (0..block_nb).zip(mdiv_x_v[xi].iter()) {
                ext_mdiv_x_a.push(ct.clone());
            }
            for _k in mdiv_x_v[xi].len()..block_nb {
                ext_mdiv_x_a.push(cst_sign.clone());
            }
            ext_mdiv_x_a.push(cst_sign.clone());

            // Step2
            // Compute remain - div
            // Here, do not clean the last block, which is the carry
            let diff_x_a = iop_add_hillissteel_v(
                prog,
                &remain_a,
                &ext_mdiv_x_a,
                Some(AddHSPostProcess::NoPostProcess),
            );

            // Step3
            // Comparison : look at the sign block
            let mut is_lt: metavar::MetaVarCell;
            if block_nb < div_x_v[xi].len() {
                // Take the msb of div_x into account.
                // The sign block contains either 'b100 (positive) or 'b11 (negative).
                // The remain is less than div_x if:
                // div_x msb is not null => div_x_is_not_null_v[xi][block_nb] != 0
                // or the difference is negative.
                // Note that if we subtract div_x_is_not_null to the sign block,
                // if the result is 'b100, this means that the result is positive.
                // In all other case ('b11 or 'b10) the result is negative.
                is_lt = &diff_x_a[block_nb] - &div_x_is_not_null_v[xi][block_nb];
                is_lt = is_lt.pbs(&pbs_msg_not_null_pos1, false);
            } else {
                is_lt = diff_x_a[block_nb].pbs(&pbs_msg_not_null_pos1, false);
            }
            // Note that here the lt boolean is stored in position 1 and not 0
            // to ease the if_then_else later.
            r_lt_div_x_v.push(is_lt);

            diff_x_v.push(diff_x_a);
        } // for xi

        if res_type == DivCoreOutput::All
            || res_type == DivCoreOutput::Remain
            || (res_type == DivCoreOutput::Quotient && (loop_idx < num_a.len() - 1))
        {
            // Do not compute the remain for the very last iteration, since not needed anymore.
            // Find the 1hot corresponding to the 1rst factor of div which is not greater than r.
            // {r_lt_div_x3, r_lt_div_x2, r_lt_div_x1, 0} xor {1, r_lt_div_x3,
            // r_lt_div_x2,r_lt_div_x1}
            let mut q_1h: Vec<metavar::MetaVarCell> = Vec::new();
            let mut ct1 = r_lt_div_x_v[0].mac(tfhe_params.msg_range() as u8, &r_lt_div_x_v[1]);
            ct1 = ct1.pbs(&pbs_xor, false);
            let mut ct2 = r_lt_div_x_v[1].mac(tfhe_params.msg_range() as u8, &r_lt_div_x_v[2]);
            ct2 = ct2.pbs(&pbs_xor, false);
            let ct3 = r_lt_div_x_v[2].pbs(&pbs_is_null_pos1, false);
            q_1h.push(r_lt_div_x_v[0].clone());
            q_1h.push(ct1);
            q_1h.push(ct2);
            q_1h.push(ct3);

            // Select the remain with the 1-hot
            // Mask then Or
            // Note that the sign block is not used here.
            let mut remain_tmp_v: Vec<Vec<metavar::MetaVarCell>> = Vec::new();
            for (sel, diff) in q_1h.iter().zip(diff_x_v.iter()) {
                remain_tmp_v.push(iop_if_then_else_0v(
                    prog,
                    &diff[0..block_nb],
                    sel,
                    Some(IfThenElse0Select::SelPos1Msg),
                ));
            }

            remain_a = Vec::new();
            for i in 0..block_nb {
                remain_tmp_v[0][i] = &remain_tmp_v[0][i] + &remain_tmp_v[1][i];
                remain_tmp_v[2][i] = &remain_tmp_v[2][i] + &remain_tmp_v[3][i];
                remain_tmp_v[0][i] = &remain_tmp_v[0][i] + &remain_tmp_v[2][i];
                remain_a.push(remain_tmp_v[0][i].pbs(&pbs_none, false));
            }
        }

        // Quotient
        // Note that {r_lt_div_x3, r_lt_div_x2, r_lt_div_x1, 0} is a multi-hot.
        // with the 1s in the MBSs. Therefore, we can deduce the quotient 2 bits
        // from the nb of 1.
        // Note : In r_lt_div_x the boolean is stored in position 1 instead of 0.
        // 'b0000 => 3 * 2
        // 'b1000 => 2 * 2
        // 'b1100 => 1 * 2
        // 'b1110 => 0 * 2
        if res_type == DivCoreOutput::All || res_type == DivCoreOutput::Quotient {
            let ct01 = r_lt_div_x_v[0].clone(); // + 0
            let ct23 = &r_lt_div_x_v[1] + &r_lt_div_x_v[2];
            let ct0123 = &ct01 + &ct23;
            quotient_a.push(ct0123.pbs(&pbs_solve_quotient_pos1, false));
        }
    } // for loop_idx

    if res_type == DivCoreOutput::All || res_type == DivCoreOutput::Quotient {
        quotient_a.reverse();
        quotient_a = iop_if_then_else_0v(
            prog,
            &quotient_a,
            &keep_div,
            Some(IfThenElse0Select::SelPos0Msg),
        );
    }

    match res_type {
        DivCoreOutput::All => vec![quotient_a, remain_a],
        DivCoreOutput::Quotient => vec![quotient_a],
        DivCoreOutput::Remain => vec![remain_a],
    }
}
