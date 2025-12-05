use super::{DdrMem, HbmBank};
use tfhe::tfhe_hpu_backend::prelude::*;

pub struct UCore {
    config: BoardConfig,
}

impl UCore {
    pub fn new(config: BoardConfig) -> Self {
        Self { config }
    }
}

impl UCore {
    /// Top level function
    /// Read DOp stream from Fw memory and patch Templated LD/ST with concrete one
    pub fn translate(
        &self,
        ddr: &DdrMem,
        hbm_bank: &[HbmBank],
        iop: &hpu_asm::IOp,
    ) -> (Vec<hpu_asm::DOp>, Vec<hpu_asm::DOp>) {
        let dops = self.load_fw(ddr, hbm_bank, iop);
        let dops_patched = self.patch_fw(iop, &dops);
        (dops, dops_patched)
    }

    /// Read DOp stream from Firmware memory
    fn load_fw(&self, ddr: &DdrMem, hbm_bank: &[HbmBank], iop: &hpu_asm::IOp) -> Vec<hpu_asm::DOp> {
        let fw_view = match self.config.fw_pc {
            MemKind::Ddr { offset } => ddr.get_chunk(offset as u64).data(),
            MemKind::Hbm { pc } => {
                // Bypass fw_ofst register value
                // Expect to have only one memzone in fw bank allocated in 0
                // NB: Fw memory bank is linked to ucore and there is no associated offset register
                // -> Stick with Offset 0
                hbm_bank[pc].get_chunk(0).data()
            }
        };
        let fw_view_u32 = bytemuck::cast_slice::<u8, u32>(fw_view);

        // WARN: fw ofst are in byte addr and we addr the fw array as 32b word
        let dop_ofst = fw_view_u32[iop.fw_entry()] as usize / std::mem::size_of::<u32>();
        let dop_len = fw_view_u32[dop_ofst] as usize;
        let (start, end) = (dop_ofst + 1, dop_ofst + 1 + dop_len);
        let dop_stream = &fw_view_u32[start..end];

        // Allocate DOp parser
        dop_stream
            .iter()
            .map(|bin| hpu_asm::DOp::from_hex(*bin).expect("Invalid DOp"))
            .collect::<Vec<hpu_asm::DOp>>()
    }

    /// Rtl ucore emulation
    /// Map a Raw DOp stream to the given IOp operands
    /// I.e. it replace Templated MemId with concrete one
    fn patch_fw(&self, iop: &hpu_asm::IOp, dops: &[hpu_asm::DOp]) -> Vec<hpu_asm::DOp> {
        let mut dops_patch = dops
            .iter()
            .map(|dop| {
                let mut dop_patch = dop.clone();
                match &mut dop_patch {
                    hpu_asm::DOp::LD(op_impl) => {
                        let slot = op_impl.slot_mut();
                        *slot = match slot {
                            hpu_asm::MemId::Heap { bid } => hpu_asm::MemId::Addr(hpu_asm::CtId(
                                (self.config.ct_mem - 1) as u16 - *bid,
                            )),
                            hpu_asm::MemId::Src { tid, bid } => hpu_asm::MemId::Addr(
                                hpu_asm::CtId(iop.src()[*tid as usize].base_cid.0 + *bid as u16),
                            ),
                            hpu_asm::MemId::Dst { tid, bid } => hpu_asm::MemId::Addr(
                                hpu_asm::CtId(iop.dst()[*tid as usize].base_cid.0 + *bid as u16),
                            ),
                            hpu_asm::MemId::Addr(ct_id) => hpu_asm::MemId::Addr(*ct_id),
                        };
                        dop_patch
                    }
                    hpu_asm::DOp::ST(op_impl) => {
                        let slot = op_impl.slot_mut();
                        *slot = match slot {
                            hpu_asm::MemId::Heap { bid } => hpu_asm::MemId::Addr(hpu_asm::CtId(
                                (self.config.ct_mem - 1) as u16 - *bid,
                            )),
                            hpu_asm::MemId::Src { tid, bid } => hpu_asm::MemId::Addr(
                                hpu_asm::CtId(iop.src()[*tid as usize].base_cid.0 + *bid as u16),
                            ),
                            hpu_asm::MemId::Dst { tid, bid } => hpu_asm::MemId::Addr(
                                hpu_asm::CtId(iop.dst()[*tid as usize].base_cid.0 + *bid as u16),
                            ),
                            hpu_asm::MemId::Addr(ct_id) => hpu_asm::MemId::Addr(*ct_id),
                        };
                        dop_patch
                    }
                    hpu_asm::DOp::ADDS(op_impl) => {
                        let imm = op_impl.msg_mut();
                        patch_imm(iop, imm);
                        dop_patch
                    }
                    hpu_asm::DOp::SUBS(op_impl) => {
                        let imm = op_impl.msg_mut();
                        patch_imm(iop, imm);
                        dop_patch
                    }
                    hpu_asm::DOp::SSUB(op_impl) => {
                        let imm = op_impl.msg_mut();
                        patch_imm(iop, imm);
                        dop_patch
                    }
                    hpu_asm::DOp::MULS(op_impl) => {
                        let imm = op_impl.msg_mut();
                        patch_imm(iop, imm);
                        dop_patch
                    }
                    // TODO Patch immediate
                    _ => dop_patch,
                }
            })
            .collect::<Vec<_>>();

        // Ucore is in charge of Sync insertion
        dops_patch.push(hpu_asm::dop::DOpSync::new(None).into());
        tracing::trace!("Patch DOp stream => {dops_patch:?}");
        dops_patch
    }
}

/// Utility function to patch immediate argument
fn patch_imm(iop: &hpu_asm::IOp, imm: &mut hpu_asm::ImmId) {
    *imm = match imm {
        hpu_asm::ImmId::Cst(val) => hpu_asm::ImmId::Cst(*val),
        hpu_asm::ImmId::Var { tid, bid } => {
            hpu_asm::ImmId::Cst(iop.imm()[*tid as usize].msg_block(*bid))
        }
    }
}
