///
/// Help with IOp management over HPU
/// Track IOp status and handle backward update of associated HpuVariable
use super::*;
use crate::asm::iop::{Immediate, Operand, OperandKind};
use crate::asm::{IOp, IOpcode};
use variable::HpuVarWrapped;

/// Underlying type used for Immediate value;
pub type HpuImm = u128;

/// Structure that hold an IOp with there associated operands
/// Wrap operands memory with the IOp for proper lifetime management
pub struct HpuCmd {
    pub(crate) op: IOp,
    pub(crate) dst: Vec<HpuVarWrapped>,
    pub(crate) src: Vec<HpuVarWrapped>,
    // NB: No need to track Immediate lifetime. It's simply constant completely held by the IOp
    // definition
}

impl HpuCmd {
    pub fn new(
        opcode: IOpcode,
        dst: &[HpuVarWrapped],
        src: &[HpuVarWrapped],
        imm: &[HpuImm],
    ) -> Self {
        // TODO Check that dst/rhs_x backend match
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

        // Extract Operands definition from HpuVar
        let dst_op = dst
            .iter()
            .map(|var| {
                Operand::new(
                    var.width as u8,
                    var.id.0 as u16,
                    1, /* TODO handle vec source !? */
                    Some(OperandKind::Dst),
                )
            })
            .collect::<Vec<_>>();
        let src_op = src
            .iter()
            .map(|var| {
                Operand::new(
                    var.width as u8,
                    var.id.0 as u16,
                    1, /* TODO handle vec source !? */
                    Some(OperandKind::Src),
                )
            })
            .collect::<Vec<_>>();
        let imm_op = imm
            .iter()
            .map(|var| Immediate::from_cst(*var))
            .collect::<Vec<_>>();

        let op = IOp::new(opcode, dst_op, src_op, imm_op);
        // TODO set op_width

        let dst = dst
            .iter()
            .map(|var| {
                // Update dst state to OpPending
                var.inner.lock().unwrap().operation_pending();
                (*var).clone()
            })
            .collect::<Vec<_>>();
        let src = src.iter().map(|var| (*var).clone()).collect::<Vec<_>>();
        Self { op, dst, src }
    }

    pub fn op(&self) -> &IOp {
        &self.op
    }
}

/// Generic interface
impl HpuCmd {
    pub fn exec_raw(
        opcode: crate::asm::IOpcode,
        dst: &[HpuVarWrapped],
        rhs_ct: &[HpuVarWrapped],
        rhs_imm: &[HpuImm],
    ) {
        // Create associated command
        let cmd = Self::new(opcode, dst, rhs_ct, rhs_imm);
        // Issue it on Hpubackend
        dst.first()
            .expect("Try to generate an IOp without any destination")
            .cmd_api
            .send(cmd)
            .expect("Issue with cmd_api");
    }

    // TODO add more runtime check on prototype ?
    pub fn exec(
        proto: &crate::asm::iop::IOpProto,
        opcode: crate::asm::IOpcode,
        rhs_ct: &[HpuVarWrapped],
        rhs_imm: &[HpuImm],
    ) -> Vec<HpuVarWrapped> {
        let dst = proto
            .dst
            .iter()
            .map(|m| rhs_ct[0].fork(*m))
            .collect::<Vec<_>>();
        Self::exec_raw(opcode, &dst, rhs_ct, rhs_imm);
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
        Self::exec_raw(opcode, &dst, rhs_ct, rhs_imm);
    }
}
