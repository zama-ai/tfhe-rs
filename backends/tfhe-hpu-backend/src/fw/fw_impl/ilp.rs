//!
//! Implementation of Ilp firmware
//!
//! In this version of the Fw focus is done on Instruction Level Parallelism
use std::collections::VecDeque;

use super::*;
use crate::asm::{self, Arg, Pbs};
use itertools::Itertools;
use tracing::{debug, instrument, trace};

use crate::new_pbs;

crate::impl_fw!("Ilp" [
    "ADD" => fw_impl::ilp::iop_addx;
    "SUB" => fw_impl::ilp::iop_subx;
    "MUL" => fw_impl::ilp::iop_mulx;

    "ADDS" => fw_impl::ilp::iop_addx;
    "SUBS" => fw_impl::ilp::iop_subx;
    "SSUB" => fw_impl::ilp::iop_ssub;
    "MULS" => fw_impl::ilp::iop_mulx;


    "BW_AND" => (|prog, arg| {fw_impl::ilp::iop_bw(prog, arg, asm::PbsBwAnd::default().into())});
    "BW_OR"  => (|prog, arg| {fw_impl::ilp::iop_bw(prog, arg, asm::PbsBwOr::default().into())});
    "BW_XOR" => (|prog, arg| {fw_impl::ilp::iop_bw(prog, arg, asm::PbsBwXor::default().into())});

    "CMP_GT"  => (|prog, arg| {fw_impl::ilp::iop_cmp(prog, arg, asm::PbsCmpGt::default().into())});
    "CMP_GTE" => (|prog, arg| {fw_impl::ilp::iop_cmp(prog, arg, asm::PbsCmpGte::default().into())});
    "CMP_LT"  => (|prog, arg| {fw_impl::ilp::iop_cmp(prog, arg, asm::PbsCmpLt::default().into())});
    "CMP_LTE" => (|prog, arg| {fw_impl::ilp::iop_cmp(prog, arg, asm::PbsCmpLte::default().into())});
    "CMP_EQ"  => (|prog, arg| {fw_impl::ilp::iop_cmp(prog, arg, asm::PbsCmpEq::default().into())});
    "CMP_NEQ" => (|prog, arg| {fw_impl::ilp::iop_cmp(prog, arg, asm::PbsCmpNeq::default().into())});

]);

#[instrument(level = "info", skip(prog))]
pub fn iop_addx(prog: &mut Program, op: &IOp) {
    assert!(
        (op.name() == "ADD") | (op.name() == "ADDS"),
        "Check used of impl_macro"
    );
    let props = prog.props();

    let mut dst = prog.user_var(op.dst()[0]);
    let src_a = prog.user_var(op.src()[0]);
    let src_b = prog.user_var(op.src()[1]);

    // Wrapped required lookup table in MetaVar
    let pbs_msg = new_pbs!(prog, "MsgOnly");
    let pbs_carry = new_pbs!(prog, "CarryInMsg");

    let mut carry: Option<metavar::MetaVarCell> = None;

    (0..prog.props().blk_w()).for_each(|blk| {
        let mut msg = &src_a[blk] + &src_b[blk];
        if let Some(cin) = &carry {
            msg += cin.clone();
        }
        if blk < (props.blk_w() - 1) {
            carry = Some(msg.pbs(&pbs_carry, false));
        }
        // Force allocation of new reg to allow carry/msg pbs to run in //
        let msg = msg.pbs(&pbs_msg, false);

        // Store result
        dst[blk].mv_assign(msg);
    });
}

#[instrument(level = "info", skip(prog))]
pub fn iop_subx(prog: &mut Program, op: &IOp) {
    assert!(
        (op.name() == "SUB") | (op.name() == "SUBS"),
        "Check used of impl_macro"
    );
    let props = prog.props();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    let mut dst = prog.user_var(op.dst()[0]);
    let src_a = prog.user_var(op.src()[0]);
    let src_b = prog.user_var(op.src()[1]);

    // Wrapped required lookup table in MetaVar
    let pbs_msg = new_pbs!(prog, "MsgOnly");
    let pbs_carry = new_pbs!(prog, "CarryInMsg");

    let mut z_cor: Option<usize> = None;
    let mut carry: Option<metavar::MetaVarCell> = None;

    (0..prog.props().blk_w()).for_each(|blk| {
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
        }
        // Force allocation of new reg to allow carry/msg pbs to run in //
        let msg = msg.pbs(&pbs_msg, false);

        // Store result
        dst[blk] <<= msg;
    });
}

#[instrument(level = "info", skip(prog))]
pub fn iop_ssub(prog: &mut Program, op: &IOp) {
    // NB: Dedicated implementation to achieved same perf as SUBS
    assert!((op.name() == "SSUB"), "Check used of impl_macro");
    let props = prog.props();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    let mut dst = prog.user_var(op.dst()[0]);
    let src_a = prog.user_var(op.src()[0]);
    let src_b = prog.user_var(op.src()[1]);

    // Wrapped required lookup table in MetaVar
    let pbs_msg = new_pbs!(prog, "MsgOnly");
    let pbs_carry = new_pbs!(prog, "CarryInMsg");

    let mut z_cor: Option<usize> = None;
    let mut carry: Option<metavar::MetaVarCell> = None;

    (0..prog.props().blk_w()).for_each(|blk| {
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
        }
        // Force allocation of new reg to allow carry/msg pbs to run in //
        let msg = msg.pbs(&pbs_msg, false);

        // Store result
        dst[blk] <<= msg;
    });
}

#[instrument(level = "info", skip(prog))]
pub fn iop_mulx(prog: &mut Program, op: &IOp) {
    assert!(
        (op.name() == "MUL") | (op.name() == "MULS"),
        "Check used of impl_macro"
    );
    let props = prog.props();
    let tfhe_params: asm::DigitParameters = props.clone().into();
    let blk_w = props.blk_w();

    let mut dst = prog.user_var(op.dst()[0]);
    let src_a = prog.user_var(op.src()[0]);
    let src_b = prog.user_var(op.src()[1]);

    // Wrapped required lookup table in MetaVar
    let pbs_msg = new_pbs!(prog, "MsgOnly");
    let pbs_carry = new_pbs!(prog, "CarryInMsg");
    let pbs_mul_lsb = new_pbs!(prog, "MultCarryMsgLsb");
    let pbs_mul_msb = new_pbs!(prog, "MultCarryMsgMsb");

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

    for pp in pp_deg_idx.chunks(props.pbs_w) {
        // Pack
        let pack = pp
            .iter()
            .map(|(w, i, j)| {
                let mac = src_a[*i].mac(tfhe_params.msg_range(), &src_b[*j]);
                debug!(target: "Fw", "@{w}[{i}, {j}] -> {mac:?}",);
                (w, mac)
            })
            .collect::<Vec<_>>();

        // Pbs Mul
        // Reserve twice as pbs_w since 2 pbs could be generated for a given block
        prog.reg_bulk_reserve(2 * props.pbs_w);
        pack.into_iter().for_each(|(w, pp)| {
            let lsb = pp.pbs(&pbs_mul_lsb, false);
            debug!(target: "Fw", "Pbs generate @{w} -> {lsb:?}");
            pp_vars.push_back((*w, lsb));

            // Extract msb if needed
            if *w < (blk_w - 1) {
                // Force allocation of new reg to allow lsb/msb pbs to run in //
                let msb = pp.pbs(&pbs_mul_msb, false);
                debug!(target: "Fw", "Pbs generate @{} -> {msb:?}", w + 1);
                pp_vars.push_back((*w + 1, msb));
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
                // Skip position w if already commited
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
                            debug!(target:"Fw", "Commit {w} <- {:?}", acc_chunks[0]);
                            dst[w] <<= acc_chunks.swap_remove(0);
                            wb_idx += 1;
                        } else {
                            // not my turn, enqueue back
                            debug!(target:"Fw", "{w}::{wb_idx}: insert backed in pp_vars {:?}", acc_chunks[0]);
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
            debug!(target: "Fw", "Reduce @{w}[{}] <- {acc_chunks:?}",acc_chunks.len());
            // Hand-writter tree reduction for up to 5
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

        if pdg_pbs.len() == props.pbs_w || (pp_vars.is_empty()) {
            trace!(target: "Fw", "pdg_pbs[{}] <- {pdg_pbs:?}", pdg_pbs.len());
            prog.reg_bulk_reserve(pdg_pbs.len());
            while let Some((w, var)) = pdg_pbs.pop() {
                let lsb = var.pbs(&pbs_msg, false);
                debug!(target: "Fw", "Pbs generate @{w} -> {lsb:?}");
                // TODO These explicit flush enhance perf for large MUL but degrade them for small
                // one Find a proper way to arbitrait their used
                // Furthermore, it induce error with current ISC without LD/ST ordering
                // lsb.heap_alloc_mv(true);
                pp_vars.push_back((w, lsb));

                // Extract msb if needed
                if w < (blk_w - 1) {
                    // Force allocation of new reg to allow carry/msg pbs to run in //
                    let msb = var.pbs(&pbs_carry, false);
                    debug!(target: "Fw", "Pbs generate @{} -> {msb:?}", w + 1);
                    // TODO These explicit flush enhance perf for large MUL but degrade them for
                    // small one Find a proper way to arbitrait their used
                    // Furthermore, it induce error with current ISC without LD/ST ordering
                    // msb.heap_alloc_mv(true);
                    pp_vars.push_back((w + 1, msb));
                }
            }
            // Compute LSB ASAP
            pp_vars
                .make_contiguous()
                .sort_by(|x, y| x.0.partial_cmp(&y.0).unwrap());
        }
    }
}

#[instrument(level = "info", skip(prog))]
pub fn iop_bw(prog: &mut Program, op: &IOp, bw_op: Pbs) {
    assert!(
        (op.name() == "BW_AND") | (op.name() == "BW_OR") | (op.name() == "BW_XOR"),
        "Check used of impl_macro"
    );
    let props = prog.props();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    let dst = prog.user_var(op.dst()[0]);
    let src_a = prog.user_var(op.src()[0]);
    let src_b = prog.user_var(op.src()[1]);

    // Wrapped given bw_op lookup table in MetaVar
    let bw_op = prog.var_from(Some(Arg::Pbs(bw_op)));

    itertools::izip!(dst, src_a, src_b)
        .chunks(props.pbs_w)
        .into_iter()
        .for_each(|chunk| {
            let chunk_pack = chunk
                .into_iter()
                .map(|(d, a, b)| (d, a.mac(tfhe_params.msg_range(), &b)))
                .collect::<Vec<_>>();
            chunk_pack.into_iter().for_each(|(mut d, mut pack)| {
                pack.pbs_assign(&bw_op, false);
                d <<= pack;
            });
        });
}

#[instrument(level = "info", skip(prog))]
pub fn iop_cmp(prog: &mut Program, op: &IOp, cmp_op: Pbs) {
    assert!(op.name().contains("CMP_"), "Check used of impl_macro");

    let props = prog.props();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    let mut dst = prog.user_var(op.dst()[0]);
    let src_a = prog.user_var(op.src()[0]);
    let src_b = prog.user_var(op.src()[1]);

    // Wrapped given cmp_op and comp_sign lookup table in MetaVar
    let cmp_op = prog.var_from(Some(Arg::Pbs(cmp_op)));
    let pbs_none = new_pbs!(prog, "None");
    let cmp_sign = new_pbs!(prog, "CmpSign");
    let cmp_reduce = new_pbs!(prog, "CmpReduce");

    // Pack A and B elements by pairs
    let packed = std::iter::zip(src_a.as_slice().chunks(2), src_b.as_slice().chunks(2))
        .map(|(a, b)| {
            let pack_a = if a.len() > 1 {
                // Reset noise for future block merge through sub
                a[1].mac(tfhe_params.msg_range(), &a[0])
                    .pbs(&pbs_none, false)
            } else {
                a[0].clone()
            };

            let pack_b = if b.len() > 1 {
                b[1].mac(tfhe_params.msg_range(), &b[0])
                    .pbs(&pbs_none, false)
            } else {
                b[0].clone()
            };
            (pack_a, pack_b)
        })
        .collect::<Vec<_>>();

    let cst_1 = prog.new_imm(1);
    let merged = packed
        .into_iter()
        .chunks(props.pbs_w)
        .into_iter()
        .flat_map(|chunk| {
            let chunk = chunk
                .map(|(mut a, b)| {
                    a -= b;
                    a
                })
                .collect::<Vec<_>>();
            let chunk = chunk
                .into_iter()
                .map(|mut a| {
                    a.pbs_assign(&cmp_sign, false);
                    a
                })
                .collect::<Vec<_>>();
            chunk.into_iter().map(|mut a| {
                a += cst_1.clone();
                a
            })
        })
        .collect::<Vec<_>>();

    let reduce = merged
        .into_iter()
        .reduce(|acc, x| x.mac(tfhe_params.msg_range(), &acc).pbs(&cmp_reduce, false));

    // Compute cst for destination MSB and interpret reduce for LSB
    let cst_0 = prog.new_cst(0);
    let cmp = reduce.unwrap().pbs(&cmp_op, false);

    dst[0] <<= cmp;
    dst[1..].iter_mut().for_each(|d| {
        let mut d = d.clone();
        d <<= cst_0.clone();
    });
}
