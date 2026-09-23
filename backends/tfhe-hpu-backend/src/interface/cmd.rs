//! Help with IOp management over HPU
//! Track IOp status and handle backward update of associated HpuVariable
use super::*;
use crate::asm::{FwMode, IOp, IOpId, IOpMapping, IOpcode, Immediate, Operand, OperandKind};
use variable::HpuVarWrapped;
use zhc::builder::Type;

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
        fw_mode: FwMode,
        opcode: IOpcode,
        iid: IOpId,
        dst: &[HpuVarWrapped],
        src: &[HpuVarWrapped],
        imm: &[HpuImm],
    ) -> Self {
        // Check arguments compliance with IOp signature
        #[cfg(debug_assertions)]
        {
            let first_src = src
                .first()
                .expect("IOp must contains at least 1 source operand");
            let (signature, _used_nodes) =
                first_src
                    .parent
                    .get_signature(fw_mode, opcode, first_src.bit_width());
            let (src_arity, imm_arity) =
                signature
                    .get_args()
                    .iter()
                    .fold((0_usize, 0_usize), |(src, imm), ty| match ty {
                        Type::Ciphertext(_) => (src + 1, imm),
                        Type::Plaintext(_) => (src, imm + 1),
                    });
            assert_eq!(
                dst.len(),
                signature.get_returns().len(),
                "Error {opcode:?}: Invalid number of dst arguments"
            );
            assert_eq!(
                src.len(),
                src_arity,
                "Error {opcode:?}: Invalid number of src arguments"
            );
            assert_eq!(
                imm.len(),
                imm_arity,
                "Error {opcode:?}: Invalid number of imm arguments"
            );
        }
        let pdg_sync = atomic::AtomicUsize::new(map.len());

        // Extract Operands definition from HpuVar
        // NB: every operand is expected to be dispatched by `exec_raw` beforehand
        let dst_op = dst
            .iter()
            .map(|var| {
                let (pos, slot) = var
                    .position()
                    .expect("Dst variable must be dispatched before IOp creation");
                Operand::new(
                    var.blocks(),
                    slot.0 as u16,
                    1, /* TODO handle vec source !? */
                    pos,
                    iid,
                    Some(OperandKind::Dst),
                )
            })
            .collect::<Vec<_>>();
        let src_op = src
            .iter()
            .map(|var| {
                let (pos, slot) = var
                    .position()
                    .expect("Src variable must be dispatched before IOp creation");
                // TODO should be able to get inner_iid without lock
                let iid = var.inner.lock().unwrap().iid();
                Operand::new(
                    var.blocks(),
                    slot.0 as u16,
                    1, /* TODO handle vec source !? */
                    pos,
                    iid,
                    Some(OperandKind::Src),
                )
            })
            .collect::<Vec<_>>();
        let imm_op = imm
            .iter()
            .map(|var| Immediate::from_cst(*var))
            .collect::<Vec<_>>();

        let op = IOp::new(fw_mode, opcode, map, dst_op, src_op, imm_op);

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
        fw_mode: FwMode,
        opcode: IOpcode,
        iop_id: IOpId,
        dst: &[HpuVarWrapped],
        src: &[HpuVarWrapped],
        imm: &[HpuImm],
    ) -> Arc<Self> {
        Arc::new(Self::new(map, fw_mode, opcode, iop_id, dst, src, imm))
    }

    pub fn op(&self) -> &IOp {
        &self.op
    }
}

/// Generic interface
impl HpuCmd {
    pub fn exec_raw(
        fw_mode: crate::asm::FwMode,
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

        // Look up the IOp's required number of Hpu nodes
        let first_src = rhs_ct
            .first()
            .expect("IOp must contains at least 1 source operand");
        let (_signature, used_nodes) =
            cluster.get_signature(fw_mode, opcode, first_src.bit_width());

        // Compute mapping based on workload and already dispatched operand position
        let hpu_id = cluster.keys().copied().collect::<Vec<_>>();
        let map = cluster.compute_cmd_map(&hpu_id, used_nodes, dst, rhs_ct);

        // Late allocation
        // Variables that aren't bound to a node yet land on the first node of the mapping.
        // Doing it here -- and not at variable creation -- let the workload/position heuristic
        // select the node once the operation is known, and prevent needless board to board
        // transfer.
        // TODO: Enhance this fallback position once multi-hpu Signature gave more insight on
        //       per node variables read/write
        // 
        // For src only:
        // Enforce that sources are readable by the Hw.
        // NB: must be done before `HpuCmd::new` since the latter flags destinations as
        // Hpu-only, and dst aliases src for assign-style IOp.
        let home = *map
            .first()
            .expect("IOp mapping must contains at least one node");

        for var in dst.iter() {
            var.dispatch_on(home);
        }
        for var in rhs_ct.iter(){
            var.dispatch_and_sync(home, true)
            .unwrap_or_else(|err| panic!("Couldn't sync {var:?} on Hpu: {err}"));
        }

        let iop_id = cluster.gen_iop_id();

        // Create associated command
        let cmd = Self::new_wrapped(map.clone(), fw_mode, opcode, iop_id, dst, rhs_ct, rhs_imm);

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
        fw_mode: crate::asm::FwMode,
        opcode: crate::asm::IOpcode,
        rhs_ct: &[HpuVarWrapped],
        rhs_imm: &[HpuImm],
        dst_pos: Option<crate::asm::PhysId>,
    ) -> Vec<HpuVarWrapped> {
        let cluster = &rhs_ct[0].parent;
        let (signature, _used_nodes) =
            cluster.get_signature(fw_mode, opcode, rhs_ct[0].bit_width());
        // Destinations are built from the IOp's declared returns: each of them already carries
        // its absolute `CiphertextSpec`, no need to derive it from an existing variable.
        //
        // _NB_: `dst_pos` honors an explicit placement request, which makes the targeted node
        // part of the computed IOp mapping. Left to `None`, destinations stay un-dispatched
        // and `exec_raw` places them on the first node of the mapping.
        let dst = signature
            .get_returns()
            .iter()
            .map(|ty| match ty {
                Type::Ciphertext(spec) => HpuVarWrapped::new(cluster.clone(), *spec, dst_pos, None),
                Type::Plaintext(_) => panic!("Error {opcode:?}: IOp couldn't return a plaintext"),
            })
            .collect::<Vec<_>>();
        Self::exec_raw(fw_mode, opcode, &dst, rhs_ct, rhs_imm);
        dst
    }

    pub fn exec_assign(
        fw_mode: crate::asm::FwMode,
        opcode: crate::asm::IOpcode,
        rhs_ct: &[HpuVarWrapped],
        rhs_imm: &[HpuImm],
    ) {
        let (signature, _used_nodes) =
            rhs_ct[0]
                .parent
                .get_signature(fw_mode, opcode, rhs_ct[0].bit_width());
        // Clone dst sub-array from srcs
        let dst = std::iter::zip(signature.get_returns().iter(), rhs_ct.iter())
            .map(|(ty, v)| {
                debug_assert!(
                    v.matches_type(ty),
                    "Assign with invalid prototype, rhs mode don't match"
                );
                v.clone()
            })
            .collect::<Vec<_>>();
        Self::exec_raw(fw_mode, opcode, &dst, rhs_ct, rhs_imm);
    }
}
