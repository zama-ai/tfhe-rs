//! Help with IOp management over HPU
//! Track IOp status and handle backward update of associated HpuVariable
use super::*;
use crate::asm::iop::{IOpMapping, Immediate, Operand, OperandKind};
use crate::asm::{IOp, IOpId, IOpcode};
use variable::HpuVarWrapped;

use std::sync::atomic;

/// Underlying type used for Immediate value;
pub type HpuImm = u128;

/// Structure that hold an IOp with there associated operands
/// Wrap operands memory with the IOp for proper lifetime management
#[derive(Debug)]
pub struct HpuCmd {
    pub(crate) op: IOp,
    // Keep track of pending sync tokens -> i.e. Number of Hpu still working on associated IOp
    pub(crate) pdg_sync: atomic::AtomicUsize,
    pub(crate) dst: Vec<HpuVarWrapped>,
    pub(crate) _src: Vec<HpuVarWrapped>,
    // NB: No need to track Immediate lifetime. It's simply constant completely held by the IOp
    // definition
}

impl HpuCmd {
    fn new(
        map: IOpMapping,
        opcode: IOpcode,
        iid: IOpId,
        dst: &[HpuVarWrapped],
        src: &[HpuVarWrapped],
        imm: &[HpuImm],
    ) -> Self {
        // Check arguments compliance with IOp prototype if any
        #[cfg(debug_assertions)]
        if let Some(format) = crate::asm::iop::IOP_LUT.hex.get(&opcode) {
            assert_eq!(
                dst.len(),
                format.proto.dst.len(),
                "Error {}: Invalid number of dst arguments",
                format.name
            );
            assert_eq!(
                src.len(),
                format.proto.src.len(),
                "Error {}: Invalid number of dst arguments",
                format.name
            );
            assert_eq!(
                imm.len(),
                format.proto.imm,
                "Error {}: Invalid number of dst arguments",
                format.name
            );
        }
        let pdg_sync = atomic::AtomicUsize::new(map.len());

        // Extract Operands definition from HpuVar
        let dst_op = dst
            .iter()
            .map(|var| {
                Operand::new(
                    var.width as u8,
                    var.id.0 as u16,
                    1, /* TODO handle vec source !? */
                    var.hpu_id,
                    iid,
                    Some(OperandKind::Dst),
                )
            })
            .collect::<Vec<_>>();
        let src_op = src
            .iter()
            .map(|var| {
                // TODO should be able to get inner_iid without lock
                let iid = var.inner.lock().unwrap().iid();
                Operand::new(
                    var.width as u8,
                    var.id.0 as u16,
                    1, /* TODO handle vec source !? */
                    var.hpu_id,
                    iid,
                    Some(OperandKind::Src),
                )
            })
            .collect::<Vec<_>>();
        let imm_op = imm
            .iter()
            .map(|var| Immediate::from_cst(*var))
            .collect::<Vec<_>>();

        let op = IOp::new(opcode, map, dst_op, src_op, imm_op);

        // Update HpuVar state and keep track for lifetime enforcement
        // i.e. Prevent release of associated variable while IOp is pending
        let dst = dst
            .iter()
            .map(|var| {
                // Update dst state to OpPending
                var.inner.lock().unwrap().operation_pending(iid);
                (*var).clone()
            })
            .collect::<Vec<_>>();
        let src = src.iter().map(|var| (*var).clone()).collect::<Vec<_>>();
        Self {
            op,
            pdg_sync,
            dst,
            _src: src,
        }
    }

    pub fn new_wrapped(
        map: IOpMapping,
        opcode: IOpcode,
        iop_id: IOpId,
        dst: &[HpuVarWrapped],
        src: &[HpuVarWrapped],
        imm: &[HpuImm],
    ) -> Arc<Self> {
        Arc::new(Self::new(map, opcode, iop_id, dst, src, imm))
    }

    pub fn op(&self) -> &IOp {
        &self.op
    }
}

/// Generic interface
impl HpuCmd {
    pub fn exec_raw(
        proto: &crate::asm::iop::IOpProto,
        opcode: crate::asm::IOpcode,
        dst: &[HpuVarWrapped],
        rhs_ct: &[HpuVarWrapped],
        rhs_imm: &[HpuImm],
    ) {
        // Extract cluster info from first dst operand
        // i.e. all operand must have share the same Arc<...>
        let first_dst = dst
            .first()
            .expect("Try to generate an IOp without any destination");
        let cluster = &first_dst.parent;

        // Compute mapping based on workload and operand position
        let hpu_id = cluster.keys().copied().collect::<Vec<_>>();
        let map = cluster.compute_cmd_map(&hpu_id, proto, dst, rhs_ct);
        let iop_id = cluster.gen_iop_id();

        // Create associated command
        let cmd = Self::new_wrapped(map.clone(), opcode, iop_id, dst, rhs_ct, rhs_imm);

        // Update cluster workload
        // _NB_: Done here to prevent bg_polling delay in workload update
        for hid in cmd.op.mapping().iter() {
            cluster.workload()[hid.0 as usize].fetch_add(1, atomic::Ordering::SeqCst);
        }

        // Issue it on cluster
        // _NB_: Cluster is in charge of dispatch on involved HpuNode
        cluster
            .cmd_tx
            .send(cmd)
            .expect("Error with cluster cmd channel");
    }

    pub fn exec(
        proto: &crate::asm::iop::IOpProto,
        opcode: crate::asm::IOpcode,
        rhs_ct: &[HpuVarWrapped],
        rhs_imm: &[HpuImm],
        dst_pos: Option<crate::asm::PhysId>,
    ) -> Vec<HpuVarWrapped> {
        // Use given position or default to node likely to be used
        let pos = dst_pos.unwrap_or(rhs_ct[0].hpu_id);
        let dst = proto
            .dst
            .iter()
            .map(|m| rhs_ct[0].fork(*m, pos))
            .collect::<Vec<_>>();
        Self::exec_raw(proto, opcode, &dst, rhs_ct, rhs_imm);
        dst
    }

    pub fn exec_assign(
        proto: &crate::asm::iop::IOpProto,
        opcode: crate::asm::IOpcode,
        rhs_ct: &[HpuVarWrapped],
        rhs_imm: &[HpuImm],
    ) {
        // Clone dst sub-array from srcs
        let dst = std::iter::zip(proto.dst.iter(), rhs_ct.iter())
            .map(|(p, v)| {
                debug_assert_eq!(
                    *p, v.mode,
                    "Assign with invalid prototype, rhs mode don't match"
                );
                v.clone()
            })
            .collect::<Vec<_>>();
        Self::exec_raw(proto, opcode, &dst, rhs_ct, rhs_imm);
    }
}
