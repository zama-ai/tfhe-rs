//!
//! Implementation of Ilp firmware for bit count (log2, trailing, leading bit)
//!
//! In this version of the Fw focus is done on Instruction Level Parallelism
use super::*;
use crate::asm::{self, OperandKind};
use crate::fw::program::Program;
use tracing::{instrument, warn};

use crate::new_pbs;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BitType {
    One,
    Zero,
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_count0(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);

    // Add Comment header
    prog.push_comment("COUNT0 Operand::Dst Operand::Src Operand::Src".to_string());
    // Deferred implementation to generic countx function
    iop_countx(prog, &mut dst, &src_a, &Some(BitType::Zero));
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_count1(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);

    // Add Comment header
    prog.push_comment("COUNT1 Operand::Dst Operand::Src Operand::Src".to_string());
    // Deferred implementation to generic countx function
    iop_countx(prog, &mut dst, &src_a, &Some(BitType::One));
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_ilog2(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);

    // Add Comment header
    prog.push_comment("ILOG2 Operand::Dst Operand::Src Operand::Src".to_string());

    let props = &prog.params();

    let prop_a = iop_propagate_msb_to_lsbv(prog, &src_a, &Some(BitType::One), &Some(false));
    let count_a = iop_countv(prog, &prop_a[1..], &Some(BitType::One));

    count_a.iter().enumerate().for_each(|(idx, c)| {
        c.reg_alloc_mv();
        dst[idx].mv_assign(c);
    });
    let cst_0 = prog.new_cst(0);
    (count_a.len()..props.blk_w()).for_each(|blk| {
        dst[blk].mv_assign(&cst_0);
    });
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_lead0(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);

    // Add Comment header
    prog.push_comment("LEAD0 Operand::Dst Operand::Src Operand::Src".to_string());

    let props = &prog.params();

    let prop_a = iop_propagate_msb_to_lsbv(prog, &src_a, &Some(BitType::One), &Some(false));
    let count_a = iop_countv(prog, &prop_a, &Some(BitType::Zero));

    count_a.iter().enumerate().for_each(|(idx, c)| {
        c.reg_alloc_mv();
        dst[idx].mv_assign(c);
    });
    let cst_0 = prog.new_cst(0);
    (count_a.len()..props.blk_w()).for_each(|blk| {
        dst[blk].mv_assign(&cst_0);
    });
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_lead1(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);

    // Add Comment header
    prog.push_comment("LEAD1 Operand::Dst Operand::Src Operand::Src".to_string());

    let props = &prog.params();

    let prop_a = iop_propagate_msb_to_lsbv(prog, &src_a, &Some(BitType::Zero), &Some(false));
    let count_a = iop_countv(prog, &prop_a, &Some(BitType::One));

    count_a.iter().enumerate().for_each(|(idx, c)| {
        c.reg_alloc_mv();
        dst[idx].mv_assign(c);
    });
    let cst_0 = prog.new_cst(0);
    (count_a.len()..props.blk_w()).for_each(|blk| {
        dst[blk].mv_assign(&cst_0);
    });
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_trail0(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);

    // Add Comment header
    prog.push_comment("TRAIL0 Operand::Dst Operand::Src Operand::Src".to_string());

    let props = &prog.params();

    let prop_a = iop_propagate_msb_to_lsbv(prog, &src_a, &Some(BitType::One), &Some(true));
    let count_a = iop_countv(prog, &prop_a, &Some(BitType::Zero));

    count_a.iter().enumerate().for_each(|(idx, c)| {
        c.reg_alloc_mv();
        dst[idx].mv_assign(c);
    });
    let cst_0 = prog.new_cst(0);
    (count_a.len()..props.blk_w()).for_each(|blk| {
        dst[blk].mv_assign(&cst_0);
    });
}

#[instrument(level = "trace", skip(prog))]
pub fn iop_trail1(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);

    // Add Comment header
    prog.push_comment("TRAIL1 Operand::Dst Operand::Src Operand::Src".to_string());

    let props = &prog.params();

    let prop_a = iop_propagate_msb_to_lsbv(prog, &src_a, &Some(BitType::Zero), &Some(true));
    let count_a = iop_countv(prog, &prop_a, &Some(BitType::One));

    count_a.iter().enumerate().for_each(|(idx, c)| {
        c.reg_alloc_mv();
        dst[idx].mv_assign(c);
    });
    let cst_0 = prog.new_cst(0);
    (count_a.len()..props.blk_w()).for_each(|blk| {
        dst[blk].mv_assign(&cst_0);
    });
}

/// Generic count bit operation
/// One destination and one source operation
/// Source is Operand
pub fn iop_countx(
    prog: &mut Program,
    dst: &mut [metavar::MetaVarCell],
    src_a: &[metavar::MetaVarCell],
    bit_type: &Option<BitType>,
) {
    let props = prog.params();
    //let tfhe_params: asm::DigitParameters = props.clone().into();

    let pbs_many_msg_split = new_pbs!(prog, "ManyMsgSplit");

    let mut bit_a: Vec<metavar::MetaVarCell> = Vec::new();
    for (idx, ct) in src_a.iter().enumerate() {
        let do_flush = idx == src_a.len() - 1;
        let v = &ct.pbs_many(&pbs_many_msg_split, do_flush)[..];
        bit_a.push(v[0].clone());
        bit_a.push(v[1].clone());
    }

    let count_a = iop_countv(prog, &bit_a, bit_type);

    count_a.iter().enumerate().for_each(|(idx, c)| {
        c.reg_alloc_mv();
        dst[idx].mv_assign(c);
    });
    let cst_0 = prog.new_cst(0);
    (count_a.len()..props.blk_w()).for_each(|blk| {
        dst[blk].mv_assign(&cst_0);
    });
}

// Do an iteration only if there are columns that need
// to be reduced, i.e. with more than 1 element.
fn need_iter(v: &[Vec<metavar::MetaVarCell>]) -> bool {
    v.iter()
        .filter(|l| l.len() > 1)
        .fold(false, |_acc, _l| true)
}

/// From a source composed blocks containing each
/// a single significant bit at position 0, count the number of
/// bits equal to 0 or 1, according to bit_type.
/// The source is assumed to be "clean".
pub fn iop_countv(
    prog: &mut Program,
    src_a: &[metavar::MetaVarCell],
    bit_type: &Option<BitType>,
) -> Vec<metavar::MetaVarCell> {
    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    let pbs_msg = new_pbs!(prog, "MsgOnly");
    let pbs_carry = new_pbs!(prog, "CarryInMsg");
    let pbs_many_carrymsg = new_pbs!(prog, "ManyCarryMsg");
    let pbs_many_inv1_carrymsg = new_pbs!(prog, "ManyInv1CarryMsg");
    let pbs_many_inv2_carrymsg = new_pbs!(prog, "ManyInv2CarryMsg");
    let pbs_many_inv3_carrymsg = new_pbs!(prog, "ManyInv3CarryMsg");
    let pbs_many_inv4_carrymsg = new_pbs!(prog, "ManyInv4CarryMsg");
    let pbs_many_inv5_carrymsg = new_pbs!(prog, "ManyInv5CarryMsg");
    let pbs_many_inv6_carrymsg = new_pbs!(prog, "ManyInv6CarryMsg");
    let pbs_many_inv7_carrymsg = new_pbs!(prog, "ManyInv7CarryMsg");

    let pbs_many_inv_carrymsg = [
        pbs_many_carrymsg.clone(), // place holder
        pbs_many_inv1_carrymsg,
        pbs_many_inv2_carrymsg,
        pbs_many_inv3_carrymsg,
        pbs_many_inv4_carrymsg,
        pbs_many_inv5_carrymsg,
        pbs_many_inv6_carrymsg,
        pbs_many_inv7_carrymsg,
    ];

    // TODO: TOREVIEW
    let op_nb = props.nu;
    // clog2(op_nb)
    let op_nb_bool = 1 << ((op_nb as f32).log2().ceil() as usize);
    let op_nb_single = op_nb_bool - 1;

    // Number of block to store the results.
    let block_nb =
        (((src_a.len() * tfhe_params.msg_w + 1) as f32).log2().ceil() as usize).div_ceil(2);

    // During the process, the current MSB column will be composed of
    // blocks of single bit.
    // The others are composed of blocks of msg_w bits.
    // Single bit column is summed op_nb_single blocks at a time. Therefore
    // leaving a free bit for the manyLut extraction.
    // Full msg column is summed op_nb blocks at a time. Therefore
    // 2 PBS are used for the extraction.

    let mut sum_v: Vec<Vec<metavar::MetaVarCell>> = vec![src_a.to_vec()];

    let mut iter_idx = 0;
    while need_iter(&sum_v) {
        let empty_col_nb = sum_v
            .iter()
            .filter(|col| col.is_empty())
            .fold(0, |acc, _col| acc + 1);

        let mut next_v: Vec<Vec<metavar::MetaVarCell>> = Vec::new();
        next_v.push(Vec::new()); // For the msg
        for (c_idx, col) in sum_v.iter().enumerate() {
            next_v.push(Vec::new()); // For the carry
            let next_len = &next_v.len();
            let is_last_nonempty_col = c_idx == (&sum_v.len() - 1 - empty_col_nb);

            if col.len() == 1 {
                // Single element, do not need to process
                next_v[next_len - 2].push(col[0].clone());
            } else if c_idx == sum_v.len() - 1 {
                // Last column contains only bits
                let chunk_nb = col.len().div_ceil(op_nb_single);
                for (chk_idx, chk) in col.chunks(op_nb_single).enumerate() {
                    let do_flush = (chk_idx == (chunk_nb - 1)) && is_last_nonempty_col;

                    let cst_0 = prog.new_imm(0);
                    let (s, nb) = chk
                        .iter()
                        .fold((cst_0, 0), |(acc, elt_nb), ct| (ct + &acc, elt_nb + 1));
                    let m: metavar::MetaVarCell;
                    let c: metavar::MetaVarCell;
                    if bit_type.unwrap_or(BitType::One) == BitType::Zero && iter_idx == 0 {
                        let v = s.pbs_many(&pbs_many_inv_carrymsg[nb], do_flush);
                        m = v[0].clone();
                        c = v[1].clone();
                    } else {
                        let v = s.pbs_many(&pbs_many_carrymsg, do_flush);
                        m = v[0].clone();
                        c = v[1].clone();
                    }
                    if nb >= tfhe_params.msg_range() && c_idx < block_nb {
                        // Do not compute after
                        // the number of needed blocks.
                        next_v[next_len - 1].push(c);
                    }
                    next_v[next_len - 2].push(m);
                }
            } else {
                // Regular column. Sum by op_nb elements
                let chunk_nb = col.len().div_ceil(op_nb);
                for (chk_idx, chk) in col.chunks(op_nb).enumerate() {
                    let do_flush = (chk_idx == (chunk_nb - 1)) && is_last_nonempty_col;

                    let cst_0 = prog.new_imm(0);
                    let (s, nb) = chk
                        .iter()
                        .fold((cst_0, 0), |(acc, elt_nb), ct| (ct + &acc, elt_nb + 1));
                    let m: metavar::MetaVarCell;
                    let c: metavar::MetaVarCell;
                    if nb > 2 {
                        m = s.pbs(&pbs_msg, false);
                        c = s.pbs(&pbs_carry, do_flush);
                    } else {
                        // Free bit to used manyLut
                        let v = s.pbs_many(&pbs_many_carrymsg, do_flush);
                        m = v[0].clone();
                        c = v[1].clone();
                    }
                    if c_idx < block_nb {
                        // Do not compute after
                        // the number of needed blocks.
                        next_v[next_len - 1].push(c);
                    }
                    next_v[next_len - 2].push(m);
                }
            }
        } // For c_idx, col
        iter_idx += 1;
        sum_v = next_v;
    } // while

    //    let mut res : Vec<metavar::MetaVarCell> = Vec::new();
    sum_v
        .iter()
        .filter(|v| !v.is_empty())
        .map(|v| v[0].clone())
        .collect()
}

/// Propagate bit from msb to lsb.
pub fn iop_propagate_msb_to_lsbv(
    prog: &mut Program,
    src_a: &[metavar::MetaVarCell],
    bit_type: &Option<BitType>,
    inverse_propagation: &Option<bool>, // default false
) -> Vec<metavar::MetaVarCell> {
    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    let pbs_many_m2l_prop_bit1_msg_split = new_pbs!(prog, "Manym2lPropBit1MsgSplit");
    let pbs_many_m2l_prop_bit0_msg_split = new_pbs!(prog, "Manym2lPropBit0MsgSplit");
    let pbs_many_l2m_prop_bit1_msg_split = new_pbs!(prog, "Manyl2mPropBit1MsgSplit");
    let pbs_many_l2m_prop_bit0_msg_split = new_pbs!(prog, "Manyl2mPropBit0MsgSplit");

    let propagate_block =
        iop_propagate_msb_to_lsb_blockv(prog, src_a, bit_type, &Some(false), inverse_propagation);

    let mut res_v = Vec::new();
    for (idx, ct) in src_a.iter().enumerate() {
        // propagation start point
        let start_idx = if inverse_propagation.unwrap_or(false) {
            0
        } else {
            src_a.len() - 1
        };
        let do_flush = idx == (src_a.len() - 1);
        let m = if idx == start_idx {
            ct.clone()
        } else {
            let neigh_idx = if inverse_propagation.unwrap_or(false) {
                idx - 1
            } else {
                idx + 1
            };
            propagate_block[neigh_idx].mac(tfhe_params.msg_range() as u8, ct)
        };
        let v = if bit_type.unwrap_or(BitType::One) == BitType::One {
            if inverse_propagation.unwrap_or(false) {
                m.pbs_many(&pbs_many_l2m_prop_bit1_msg_split, do_flush)
            } else {
                m.pbs_many(&pbs_many_m2l_prop_bit1_msg_split, do_flush)
            }
        } else if inverse_propagation.unwrap_or(false) {
            m.pbs_many(&pbs_many_l2m_prop_bit0_msg_split, do_flush)
        } else {
            m.pbs_many(&pbs_many_m2l_prop_bit0_msg_split, do_flush)
        };
        res_v.push(v[0].clone());
        res_v.push(v[1].clone());
    }

    res_v
}

#[instrument(level = "trace", skip(prog))]
/// Propagate bit value given by bit_type from msb to lsb,
/// on block basis.
/// If inverse_output = false
/// From MSB to LSB:
/// * bit_type = 1 if block <i> contains the first bit equal to 1, from MSB then the Noutput block
///   <i> and below are set to 1, the output block <i+1> and up are set to 0.
/// * bit_type = 0 if block <i> contains the first bit equal to 0, from MSB then the output block
///   <i> and below are set to 1, the output block <i+1> and up are set to 0.
/// If inverse_output = true, the output bits described above are
/// negated.
pub fn iop_propagate_msb_to_lsb_blockv(
    prog: &mut Program,
    src_a: &[metavar::MetaVarCell],
    bit_type: &Option<BitType>,       // Default One
    inverse_output: &Option<bool>,    // Default false
    inverse_direction: &Option<bool>, // Default false
) -> Vec<metavar::MetaVarCell> {
    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    let pbs_not_null = new_pbs!(prog, "NotNull");
    let pbs_is_null = new_pbs!(prog, "IsNull");

    // TODO: TOREVIEW
    let op_nb = props.nu;
    // clog2(op_nb)
    let op_nb_bool = 1 << ((op_nb as f32).log2().ceil() as usize);

    let mut proc_nb = op_nb;
    let mut src = if bit_type.unwrap_or(BitType::One) == BitType::One {
        src_a.to_vec()
    } else {
        // Bitwise not
        // Do not clean the ct, but reduce the nb of sequential operations
        // in next step (reducing proc_nb).
        proc_nb -= 1;
        let cst_msg_max = prog.new_imm(tfhe_params.msg_mask());
        src_a.iter().map(|ct| &cst_msg_max - ct).collect()
    };

    if inverse_direction.unwrap_or(false) {
        src.reverse();
    }

    // First step
    // Work within each group of proc_nb blocks.
    // For <i> get a boolean not null status of current block and the MSB ones.
    // within this group.
    let mut g_a: Vec<metavar::MetaVarCell> = Vec::new();
    for (c_id, c) in src.chunks(proc_nb).enumerate() {
        c.iter().rev().fold(None, |acc, elt| {
            let is_not_null;
            let tmp;
            if let Some(x) = acc {
                tmp = &x + elt;
                is_not_null = tmp.pbs(&pbs_not_null, false);
            } else {
                tmp = elt.clone();
                is_not_null = elt.pbs(&pbs_not_null, false);
            };
            g_a.insert(c_id * proc_nb, is_not_null); // Reverse insertion per chunk
            Some(tmp)
        });
    }

    // Second step
    // Proparate the not null status from MSB to LSB, with stride of
    // (op_nb_bool**k)*proc_nb
    //assert_eq!(g_a.len(),props.blk_w());
    let grp_nb = g_a.len().div_ceil(proc_nb);
    let mut level_nb = 0;
    let mut stride_size: usize = 1; // in group unit
    while stride_size < grp_nb {
        for chk in g_a.chunks_mut(op_nb_bool * stride_size * proc_nb) {
            chk.chunks_mut(stride_size * proc_nb)
                .rev()
                .fold(None, |acc, sub_chk| {
                    if let Some(x) = acc {
                        let tmp = &x + &sub_chk[0];
                        sub_chk[0] = tmp.pbs(&pbs_not_null, false);
                        Some(tmp)
                    } else {
                        Some(sub_chk[0].clone())
                    }
                });
        }

        stride_size *= op_nb_bool;
        level_nb += 1;
    }

    // This code was written for a limited size, due the following
    // leveled additions.
    assert!(level_nb < op_nb_bool);

    // Third step
    // Apply
    let mut neigh_a: Vec<metavar::MetaVarCell> = Vec::new();
    for _i in 1..level_nb {
        neigh_a.push(prog.new_cst(0));
    }

    let mut neigh = prog.new_cst(0);
    let mut prev = None;
    g_a.chunks_mut(proc_nb)
        .enumerate()
        .rev()
        .for_each(|(chk_idx, chk)| {
            let keep_v0 = chk[0].clone();

            let all_neigh = if let Some(x) = &prev {
                &neigh + x
            } else {
                neigh.clone()
            };

            for (idx, v) in chk.iter_mut().enumerate() {
                if idx == 0 {
                    // [0] is already complete with prev.
                    // do not need to add prev
                    *v = &*v + &neigh;
                } else {
                    *v = &*v + &all_neigh;
                }
                // Need to inverse it for 0 if needed
                if inverse_output.unwrap_or(false) {
                    *v = v.pbs(&pbs_is_null, false);
                } else {
                    *v = v.pbs(&pbs_not_null, false);
                }
            }

            // For next chunk
            prev = Some(keep_v0.clone());

            // Update neighbors for next iteration
            let mut do_update_neigh = false;
            for i in 1..(level_nb as u32) {
                if (chk_idx % op_nb_bool.pow(i)) == 0 {
                    // Update the corresponding neigh value
                    neigh_a[(i - 1) as usize] = keep_v0.clone();
                    do_update_neigh = true;
                }
            }
            if do_update_neigh {
                neigh = neigh_a[0].clone();
                for n in neigh_a.iter().skip(1) {
                    neigh = &neigh + n;
                }
            }
        });

    if inverse_direction.unwrap_or(false) {
        g_a.reverse();
    }

    g_a
}
