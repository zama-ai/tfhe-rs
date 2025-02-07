//!
//! Implementation of Ilp firmware
//!
//! In this version of the Fw focus is done on Instruction Level Parallelism
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::io::Write;

use super::*;
use crate::asm::{self, OperandKind, Pbs};
use crate::fw::program::Program;
use crate::fw::FwParameters;
use itertools::Itertools;
use tracing::{debug, instrument, trace};

use crate::asm::iop::opcode::*;
use crate::new_pbs;

crate::impl_fw!("Ilp" [
    ADD => fw_impl::ilp::iop_add;
    ADDK => fw_impl::ilp::iop_add_kogge;
    SUB => fw_impl::ilp::iop_sub;
    SUBK => fw_impl::ilp::iop_sub_kogge;
    MUL => fw_impl::ilp::iop_mul;

    ADDS => fw_impl::ilp::iop_adds;
    SUBS => fw_impl::ilp::iop_subs;
    SSUB => fw_impl::ilp::iop_ssub;
    MULS => fw_impl::ilp::iop_muls;


    BW_AND => (|prog| {fw_impl::ilp::iop_bw(prog, asm::dop::PbsBwAnd::default().into())});
    BW_OR  => (|prog| {fw_impl::ilp::iop_bw(prog, asm::dop::PbsBwOr::default().into())});
    BW_XOR => (|prog| {fw_impl::ilp::iop_bw(prog, asm::dop::PbsBwXor::default().into())});

    CMP_GT  => (|prog| {fw_impl::ilp::iop_cmp(prog, asm::dop::PbsCmpGt::default().into())});
    CMP_GTE => (|prog| {fw_impl::ilp::iop_cmp(prog, asm::dop::PbsCmpGte::default().into())});
    CMP_LT  => (|prog| {fw_impl::ilp::iop_cmp(prog, asm::dop::PbsCmpLt::default().into())});
    CMP_LTE => (|prog| {fw_impl::ilp::iop_cmp(prog, asm::dop::PbsCmpLte::default().into())});
    CMP_EQ  => (|prog| {fw_impl::ilp::iop_cmp(prog, asm::dop::PbsCmpEq::default().into())});
    CMP_NEQ => (|prog| {fw_impl::ilp::iop_cmp(prog, asm::dop::PbsCmpNeq::default().into())});

]);

#[instrument(level = "info", skip(prog))]
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
    iop_addx(prog, &mut dst, &src_a, &src_b);
}

#[instrument(level = "info", skip(prog))]
pub fn iop_add_kogge(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediat
    let src_b = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment("ADDK Operand::Dst Operand::Src Operand::Src".to_string());

    let rtl = {
        // Convert MetaVarCell in VarCell for Rtl analysis
        let a = src_a
            .into_iter()
            .map(|x| VarCell::from(x))
            .collect::<Vec<_>>();
        let b = src_b
            .into_iter()
            .map(|x| VarCell::from(x))
            .collect::<Vec<_>>();

        // Do a + b with the kogge stone adder
        cached_kogge_add(prog, a, b, None, dst)
    }; // Any reference to any metavar not linked to the RTL is dropped here
    rtl.add(prog);
}

pub fn iop_adds(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediat
    let src_b = prog.iop_template_var(OperandKind::Imm, 0);

    // Add Comment header
    prog.push_comment("ADDS Operand::Dst Operand::Src Operand::Immediat".to_string());
    // Deferred implementation to generic addx function
    iop_addx(prog, &mut dst, &src_a, &src_b);
}

/// Generic Add operation
/// One destination and two sources operation
/// Source could be Operand or Immediat
#[instrument(level = "info", skip(prog))]
pub fn iop_addx(
    prog: &mut Program,
    dst: &mut [metavar::MetaVarCell],
    src_a: &[metavar::MetaVarCell],
    src_b: &[metavar::MetaVarCell],
) {
    let props = prog.params();

    // Wrapped required lookup table in MetaVar
    let pbs_msg = new_pbs!(prog, "MsgOnly");
    let pbs_carry = new_pbs!(prog, "CarryInMsg");

    let mut carry: Option<metavar::MetaVarCell> = None;

    (0..prog.params().blk_w()).for_each(|blk| {
        prog.push_comment(format!(" ==> Work on output block {blk}"));

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
        dst[blk].mv_assign(&msg);
    });
}

#[instrument(level = "info", skip(prog))]
pub fn iop_sub(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediat
    let src_b = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment("SUB Operand::Dst Operand::Src Operand::Src".to_string());
    // Deferred implementation to generic subx function
    iop_subx(prog, &mut dst, &src_a, &src_b);
}

#[instrument(level = "info", skip(prog))]
pub fn iop_sub_kogge(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediat
    let src_b = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment("SUBK Operand::Dst Operand::Src Operand::Src".to_string());

    let rtl = {
        // Convert MetaVarCell in VarCell for Rtl analysis
        let a = src_a
            .into_iter()
            .map(|x| VarCell::from(x))
            .collect::<Vec<_>>();
        let b = src_b
            .into_iter()
            .map(|x| VarCell::from(x))
            .collect::<Vec<_>>();

        let imm = (0..a.len())
            .map(|_| VarCell::from(prog.new_imm((1 << prog.params().msg_w) - 1)))
            .collect::<Vec<_>>();

        // subtracting b to a constant with all ones. This will bitwise invert b.
        let b_bw_inv = b
            .into_iter()
            .zip(imm)
            .map(|(x, i)| &i - &x)
            .collect::<Vec<_>>();
        let one = VarCell::from(prog.new_imm(1));

        // Do a + ~b + 1 with the kogge stone adder
        cached_kogge_add(prog, a, b_bw_inv, Some(one), dst)
    }; // Any reference to any metavar not linked to the RTL is dropped here
    rtl.add(prog);
}

pub fn iop_subs(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediat
    let src_b = prog.iop_template_var(OperandKind::Imm, 0);

    // Add Comment header
    prog.push_comment("SUBS Operand::Dst Operand::Src Operand::Immediat".to_string());
    // Deferred implementation to generic subx function
    iop_subx(prog, &mut dst, &src_a, &src_b);
}

/// Generic sub operation
/// One destination and two sources operation
/// Source could be Operand or Immediat
#[instrument(level = "info", skip(prog))]
pub fn iop_subx(
    prog: &mut Program,
    dst: &mut [metavar::MetaVarCell],
    src_a: &[metavar::MetaVarCell],
    src_b: &[metavar::MetaVarCell],
) {
    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    // Wrapped required lookup table in MetaVar
    let pbs_msg = new_pbs!(prog, "MsgOnly");
    let pbs_carry = new_pbs!(prog, "CarryInMsg");

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
        }
        // Force allocation of new reg to allow carry/msg pbs to run in //
        let msg = msg.pbs(&pbs_msg, false);

        // Store result
        dst[blk] <<= msg;
    });
}

/// Implemenation of SSUB
/// Provide its own implementation to match SUBS perfs
#[instrument(level = "info", skip(prog))]
pub fn iop_ssub(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediat
    let src_b = prog.iop_template_var(OperandKind::Imm, 0);

    // Add Comment header
    prog.push_comment("SSUB Operand::Dst Operand::Src Operand::Immediat".to_string());

    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    // Wrapped required lookup table in MetaVar
    let pbs_msg = new_pbs!(prog, "MsgOnly");
    let pbs_carry = new_pbs!(prog, "CarryInMsg");

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
        }
        // Force allocation of new reg to allow carry/msg pbs to run in //
        let msg = msg.pbs(&pbs_msg, false);

        // Store result
        dst[blk] <<= msg;
    });
}

#[instrument(level = "info", skip(prog))]
pub fn iop_mul(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediat
    let src_b = prog.iop_template_var(OperandKind::Src, 1);

    // Add Comment header
    prog.push_comment("MUL Operand::Dst Operand::Src Operand::Src".to_string());
    // Deferred implementation to generic mulx function
    iop_mulx(prog, &mut dst, &src_a, &src_b);
}

pub fn iop_muls(prog: &mut Program) {
    // Allocate metavariables:
    // Dest -> Operand
    let mut dst = prog.iop_template_var(OperandKind::Dst, 0);
    // SrcA -> Operand
    let src_a = prog.iop_template_var(OperandKind::Src, 0);
    // SrcB -> Immediat
    let src_b = prog.iop_template_var(OperandKind::Imm, 0);

    // Add Comment header
    prog.push_comment("MULS Operand::Dst Operand::Src Operand::Immediat".to_string());
    // Deferred implementation to generic mulx function
    iop_mulx(prog, &mut dst, &src_a, &src_b);
}

/// Generic mul operation
/// One destination and two sources operation
/// Source could be Operand or Immediat
#[instrument(level = "info", skip(prog))]
pub fn iop_mulx(
    prog: &mut Program,
    dst: &mut [metavar::MetaVarCell],
    src_a: &[metavar::MetaVarCell],
    src_b: &[metavar::MetaVarCell],
) {
    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();
    let blk_w = props.blk_w();

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

    for pp in pp_deg_idx.chunks(props.pbs_batch_w) {
        // Pack
        let pack = pp
            .iter()
            .map(|(w, i, j)| {
                let mac = src_a[*i].mac(tfhe_params.msg_range() as u8, &src_b[*j]);
                debug!(target: "Fw", "@{w}[{i}, {j}] -> {mac:?}",);
                (w, mac)
            })
            .collect::<Vec<_>>();

        // Pbs Mul
        // Reserve twice as pbs_w since 2 pbs could be generated for a given block
        prog.reg_bulk_reserve(2 * props.pbs_batch_w);
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

        if pdg_pbs.len() == props.pbs_batch_w || (pp_vars.is_empty()) {
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
        .chunks(props.pbs_batch_w)
        .into_iter()
        .for_each(|chunk| {
            let chunk_pack = chunk
                .into_iter()
                .map(|(d, a, b)| (d, a.mac(tfhe_params.msg_range() as u8, &b)))
                .collect::<Vec<_>>();
            chunk_pack.into_iter().for_each(|(mut d, mut pack)| {
                pack.pbs_assign(&bw_op, false);
                d <<= pack;
            });
        });
}

#[instrument(level = "info", skip(prog))]
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

    let props = prog.params();
    let tfhe_params: asm::DigitParameters = props.clone().into();

    // Wrapped given cmp_op and comp_sign lookup table in MetaVar
    let cmp_op = prog.var_from(Some(metavar::VarPos::Pbs(cmp_op)));
    let pbs_none = new_pbs!(prog, "None");
    let cmp_sign = new_pbs!(prog, "CmpSign");
    let cmp_reduce = new_pbs!(prog, "CmpReduce");

    // Pack A and B elements by pairs
    let packed = std::iter::zip(src_a.as_slice().chunks(2), src_b.as_slice().chunks(2))
        .map(|(a, b)| {
            let pack_a = if a.len() > 1 {
                // Reset noise for future block merge through sub
                a[1].mac(tfhe_params.msg_range() as u8, &a[0])
                    .pbs(&pbs_none, false)
            } else {
                a[0].clone()
            };

            let pack_b = if b.len() > 1 {
                b[1].mac(tfhe_params.msg_range() as u8, &b[0])
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
        .chunks(props.pbs_batch_w)
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

    let reduce = merged.into_iter().reduce(|acc, x| {
        x.mac(tfhe_params.msg_range() as u8, &acc)
            .pbs(&cmp_reduce, false)
    });

    // Compute cst for destination MSB and interpret reduce for LSB
    let cst_0 = prog.new_cst(0);
    let cmp = reduce.unwrap().pbs(&cmp_op, false);

    dst[0] <<= cmp;
    dst[1..].iter_mut().for_each(|d| {
        let mut d = d.clone();
        d <<= cst_0.clone();
    });
}

// For the kogge stone add/sub
use crate::fw::rtl::{Rtl, VarCell};
use lazy_static::lazy_static;
use std::cmp::{Eq, PartialEq};
use std::env;
use std::error::Error;
use std::sync::{Arc, Mutex};

// For the kogge block table
use serde::{Deserialize, Serialize};
use toml;

#[derive(Clone, Serialize, Deserialize, Hash, PartialEq, Eq, Debug)]
struct KoggeBlockTableIndex(String);

impl From<FwParameters> for KoggeBlockTableIndex {
    fn from(value: FwParameters) -> Self {
        KoggeBlockTableIndex(format!("blk_{}_pbs_{}", value.blk_w(), value.pbs_batch_w))
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct KoggeBlockCfg {
    #[serde(skip)]
    filename: String,
    table: HashMap<KoggeBlockTableIndex, usize>,
}

fn append_bin(name: &str) -> String {
    let exe = env::current_exe().unwrap();
    let exe_dir = exe.parent().and_then(|p| p.to_str()).unwrap_or(".");
    format!("{}/{}", exe_dir, name)
}

impl KoggeBlockCfg {
    fn try_with_filename<F, E, R>(name: &str, f: F) -> Result<E, R>
    where
        F: Fn(&str) -> Result<E, R>,
    {
        f(name).or_else(|_| f(&append_bin(name)))
    }

    pub fn new(filename: &str) -> KoggeBlockCfg {
        if let Ok(contents) =
            KoggeBlockCfg::try_with_filename(filename, |f| std::fs::read_to_string(f))
        {
            let mut res: KoggeBlockCfg = toml::from_str(&contents)
                .expect(&format!("{} is not a valid KoggeBlockCfg", filename));
            res.filename = String::from(filename);
            res
        } else {
            KoggeBlockCfg {
                filename: String::from(filename),
                table: HashMap::new(),
            }
        }
    }

    pub fn entry(&mut self, index: KoggeBlockTableIndex) -> Entry<'_, KoggeBlockTableIndex, usize> {
        self.table.entry(index)
    }

    pub fn get(&mut self, index: &KoggeBlockTableIndex) -> Option<&usize> {
        self.table.get(index)
    }

    fn try_write(&self) -> Result<(), Box<dyn Error>> {
        // Convert in toml string
        let toml = toml::to_string(&self)?;

        // Open file and write to it
        let mut file = KoggeBlockCfg::try_with_filename(&self.filename, |name| {
            std::fs::File::options()
                .write(true)
                .truncate(true)
                .create(true)
                .open(name)
        })?;
        write!(&mut file, "{}", toml)?;
        Ok(())
    }
}

impl Drop for KoggeBlockCfg {
    fn drop(&mut self) {
        if let Err(err) = self.try_write() {
            print!("Could not write {}: {}\n", self.filename, err);
        }
    }
}

impl From<&str> for KoggeBlockCfg {
    fn from(cfg_f: &str) -> Self {
        let mut hash = KOGGE_BLOCK_CFG.lock().unwrap();
        (hash
            .entry(cfg_f.to_string())
            .or_insert_with_key(|key| KoggeBlockCfg::new(key)))
        .clone()
    }
}

lazy_static! {
    static ref KOGGE_BLOCK_CFG: Arc<Mutex<HashMap<String, KoggeBlockCfg>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

#[derive(Hash, PartialEq, Eq, Clone)]
struct Range(usize, usize);

struct KoggeTree {
    cache: HashMap<Range, VarCell>,
    tfhe_params: asm::DigitParameters,
    pbs: Pbs,
}

impl KoggeTree {
    fn new(prg: &mut Program, inputs: Vec<VarCell>) -> KoggeTree {
        let mut cache = HashMap::new();
        inputs.into_iter().enumerate().for_each(|(i, v)| {
            cache.insert(Range(i, i), v);
        });
        let props = prg.params();
        let tfhe_params: asm::DigitParameters = props.clone().into();
        let pbs = asm::Pbs::GenPropMerge(asm::dop::PbsGenPropMerge::default());
        KoggeTree {
            cache,
            tfhe_params,
            pbs,
        }
    }

    fn get_subindex(&self, index: &Range) -> (Range, Range) {
        let range = index.1 - index.0 + 1;
        // Find the biggest power of two smaller than range
        let pow = 1 << range.ilog2();
        let mid = if pow == range {
            index.0 + (pow >> 1)
        } else {
            index.0 + pow
        };
        (Range(index.0, mid - 1), Range(mid, index.1))
    }

    fn insert_subtree(&mut self, index: &Range) {
        if !self.cache.contains_key(&index) {
            let (lhs, rhs) = self.get_subindex(&index);
            self.insert_subtree(&lhs);
            self.insert_subtree(&rhs);

            let (lhs, rhs) = (self.cache.get(&lhs).unwrap(), self.cache.get(&rhs).unwrap());

            let mac = rhs.mac(self.tfhe_params.msg_range(), lhs);
            let pbs = mac.pbs(&self.pbs).into_iter().next().unwrap();
            self.cache.insert((*index).clone(), pbs);
        }
    }

    fn get_subtree(&mut self, index: &Range) -> &VarCell {
        self.insert_subtree(&index);
        self.cache.get(&index).unwrap()
    }
}

// Receives cypher texts with carry (in carry save form) and outputs cypher
// texts with carry propagated. The first item in the input vector is the carry
// in.
// Calling this only makes sense if the generated PBSs fit nicely into the batch
// size.
#[instrument(level = "info", skip(prog))]
fn propagate_carry(
    prog: &mut Program,
    dst: &mut [VarCell],
    carrysave: &[VarCell],
    cin: &Option<VarCell>,
) -> VarCell {
    let tfhe_params: asm::DigitParameters = prog.params().clone().into();

    let pbs_genprop = asm::Pbs::ManyGenProp(asm::dop::PbsManyGenProp::default());
    let pbs_genprop_add = asm::Pbs::GenPropAdd(asm::dop::PbsGenPropAdd::default());

    // Split the result into message and propagate/generate information using a
    // manyLUT
    let (msg, mut carry): (Vec<_>, Vec<_>) = carrysave
        .into_iter()
        .map(|v| {
            let mut res = v.pbs(&pbs_genprop).into_iter();
            (res.next().unwrap(), res.next().unwrap())
        })
        .unzip();

    // Add the carry in as the first carry if any
    carry.insert(
        0,
        cin.clone().unwrap_or(VarCell::from({
            let new = prog.var_from(None);
            &VarCell::from(new.clone()) - &VarCell::from(new)
        })),
    );

    // Build a list of terminal outputs
    let mut carry_tree = KoggeTree::new(prog, carry);

    for i in 0..msg.len() {
        let subtree = carry_tree.get_subtree(&Range(0, i));
        let mac = subtree.mac(tfhe_params.msg_range(), &msg[i]);
        let pbs = mac.pbs(&pbs_genprop_add).into_iter().next().unwrap();
        dst[i] <<= &pbs;
    }

    carry_tree.get_subtree(&Range(0, msg.len())).clone()
}

// Adds two vectors of VarCells and produces a register transfer level
// description of a kogge stone adder that can then be added to the program
fn kogge_adder(
    prog: &mut Program,
    a: Vec<VarCell>,
    b: Vec<VarCell>,
    mut cin: Option<VarCell>,
    mut dst: Vec<VarCell>,
    par_w: usize,
) -> Rtl {
    let csave: Vec<_> = a
        .into_iter()
        .zip(b.into_iter())
        .map(|(a, b)| &a + &b)
        .collect();

    (0..csave.len().div_ceil(par_w)).for_each(|chunk_idx| {
        let start = chunk_idx * par_w;
        let end = (start + par_w).min(csave.len());
        cin = Some(propagate_carry(
            prog,
            &mut dst[start..],
            &csave[start..end],
            &cin,
        ));
    });

    Rtl::from(dst)
}

// cached kogge_adder wrapper
// This finds the best par_w for the given architecture and caches the result
fn cached_kogge_add(
    prog: &mut Program,
    a: Vec<VarCell>,
    b: Vec<VarCell>,
    cin: Option<VarCell>,
    dst: Vec<metavar::MetaVarCell>,
) -> Rtl {
    let mut kogge_cfg = KoggeBlockCfg::from(prog.params().kogge_cfg.as_str());
    let index: KoggeBlockTableIndex = prog.params().into();
    let dst: Vec<_> = dst.iter().map(|v| VarCell::from(v.clone())).collect();

    kogge_cfg
        .get(&index)
        .and_then(|w| Some(*w..=*w))
        .or_else(|| Some(1..=prog.params().blk_w()))
        .unwrap()
        .map(|w| {
            // Build a new tree for every par_w trial, which means that we
            // need to get fresh variables for each trial.
            let unlink = |v: &Vec<VarCell>| v.iter().map(|v| v.unlinked()).collect();
            let a: Vec<_> = unlink(&a);
            let b: Vec<_> = unlink(&b);
            let dst: Vec<_> = unlink(&dst);
            let cin = cin.clone().and_then(|c| Some(c.unlinked()));
            let tree = kogge_adder(prog, a, b, cin, dst, w);
            (w, tree.estimate(prog))
        })
        .min_by_key(|(_, cycle_estimate)| *cycle_estimate)
        .map(|(w, _)| {
            kogge_cfg.entry(index).or_insert(w);
            kogge_adder(prog, a, b, cin, dst, w)
        })
        .unwrap()
}
