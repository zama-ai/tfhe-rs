///
/// Help with IOp management over HPU
/// Track IOp status and handle backward update of associated HpuVariable
use super::*;
use crate::asm::{Arg, Asm, IOp, IOpName};
use variable::HpuVarWrapped;

/// Structure that hold an IOp with there associated operands
pub struct HpuCmd {
    pub(crate) op: IOp,
    pub(crate) dst: HpuVarWrapped,
    pub(crate) src_a: HpuVarWrapped,
    pub(crate) src_b: Option<HpuVarWrapped>,
}

impl HpuCmd {
    pub fn new_ct_ct(
        op_name: IOpName,
        dst: HpuVarWrapped,
        src_a: HpuVarWrapped,
        src_b: HpuVarWrapped,
    ) -> Self {
        // TODO Check that dst/rhs_x backend match
        let mut op = IOp::from(op_name);
        let args = vec![dst.as_arg(), src_a.as_arg(), src_b.as_arg()];
        op.from_args(args).expect("Invalid IOp arguments");
        // TODO set op_width

        Self {
            op,
            dst,
            src_a,
            src_b: Some(src_b),
        }
    }

    pub fn new_ct_imm(
        op_name: IOpName,
        dst: HpuVarWrapped,
        src_a: HpuVarWrapped,
        imm: usize,
    ) -> Self {
        // TODO Check that dst/rhs_x backend match
        let mut op = IOp::from(op_name);
        let args = vec![dst.as_arg(), src_a.as_arg(), Arg::Imm(imm)];
        op.from_args(args).expect("Invalid IOp arguments");
        // TODO set op_width

        Self {
            op,
            dst,
            src_a,
            src_b: None,
        }
    }

    pub fn op(&self) -> &IOp {
        &self.op
    }
}
