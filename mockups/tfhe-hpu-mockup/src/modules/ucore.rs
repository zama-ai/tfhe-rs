use super::HbmBank;
use hpu_asm::{Asm, AsmBin};
use strum::IntoEnumIterator;
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
        hbm_bank: &[HbmBank],
        iop: &hpu_asm::IOp,
    ) -> (Vec<hpu_asm::DOp>, Vec<hpu_asm::DOp>) {
        let dops = self.load_fw(hbm_bank, iop);
        let dops_patched = self.patch_fw(iop, &dops);
        (dops, dops_patched)
    }

    /// Read DOp stream from Firmware memory
    fn load_fw(&self, hbm_bank: &[HbmBank], iop: &hpu_asm::IOp) -> Vec<hpu_asm::DOp> {
        let iop_code = {
            let mut bytes = iop.bin_encode_le().unwrap();
            bytes.reverse();
            bytes[0] as u32
        };

        // Bypass fw_ofst register value
        // Expect to have only one memzone in fw bank allocated in 0
        // NB: Fw memory bank is linked to ucore and there is no associated offset register
        // -> Stick with Offset 0
        let fw_bank = &hbm_bank[self.config.fw_pc];
        let fw_chunk = fw_bank.get_chunk(0);
        let fw_view = &fw_chunk.data;
        let fw_view_u32 = bytemuck::cast_slice::<u8, u32>(fw_view.as_slice());

        // WARN: fw ofst are in byte addr and we addr the fw array as 32b word
        let dop_ofst = fw_view_u32[iop_code as usize] as usize / std::mem::size_of::<u32>();
        let dop_len = fw_view_u32[dop_ofst] as usize;
        let (start, end) = (dop_ofst + 1, dop_ofst + 1 + dop_len);
        let dop_stream = &fw_view_u32[start..end];

        // Allocate DOp parser
        let dops_ref = hpu_asm::DOp::iter().collect::<Vec<_>>();
        let mut dop_parser = hpu_asm::Parser::new(dops_ref);
        dop_stream
            .iter()
            .map(|bin| {
                let be_bytes = bin.to_be_bytes();
                dop_parser
                    .from_be_bytes::<hpu_asm::FmtDOp>(&be_bytes)
                    .unwrap()
            })
            .collect::<Vec<hpu_asm::DOp>>()
    }

    /// Rtl ucore emulation
    /// Map a Raw DOp stream to the given IOp operands
    /// I.e. it replace Templated LD/ST with concrete one
    fn patch_fw(&self, iop: &hpu_asm::IOp, dops: &Vec<hpu_asm::DOp>) -> Vec<hpu_asm::DOp> {
        // NB: Currently heap is always the last defined bid
        let heap = hpu_asm::MemRegion {
            bid: self.config.ct_bank.len() - 1,
            size: *self.config.ct_bank.last().unwrap(),
        };

        let iop_args = iop.args();
        let mut dops_patch = dops
            .iter()
            .map(|dop| {
                match dop {
                    // NB: Templated Load are patch with LD
                    hpu_asm::DOp::TLDA(op) => {
                        let mut patch_op = hpu_asm::DOpLd::default();
                        patch_op.src = Self::fuse_tmem_user(&op.src, &iop_args[1]);
                        patch_op.dst = op.dst;
                        hpu_asm::DOp::LD(patch_op)
                    }
                    hpu_asm::DOp::TLDB(op) => {
                        let mut patch_op = hpu_asm::DOpLd::default();
                        patch_op.src = Self::fuse_tmem_user(&op.src, &iop_args[2]);
                        patch_op.dst = op.dst;
                        hpu_asm::DOp::LD(patch_op)
                    }
                    hpu_asm::DOp::TLDH(op) => {
                        let mut patch_op = hpu_asm::DOpLd::default();
                        patch_op.src = Self::fuse_tmem_heap(&op.src, &heap);
                        patch_op.dst = op.dst;
                        hpu_asm::DOp::LD(patch_op)
                    }
                    // NB: Templated Store are patch with ST
                    hpu_asm::DOp::TSTD(op) => {
                        let mut patch_op = hpu_asm::DOpSt::default();
                        patch_op.dst = Self::fuse_tmem_user(&op.dst, &iop_args[0]);
                        patch_op.src = op.src;
                        hpu_asm::DOp::ST(patch_op)
                    }
                    hpu_asm::DOp::TSTH(op) => {
                        let mut patch_op = hpu_asm::DOpSt::default();
                        patch_op.dst = Self::fuse_tmem_heap(&op.dst, &heap);
                        patch_op.src = op.src;
                        hpu_asm::DOp::ST(patch_op)
                    }
                    _ => dop.clone(),
                }
            })
            .collect::<Vec<_>>();

        // Ucore is in charge of Sync insertion
        dops_patch.push(hpu_asm::DOp::SYNC(Default::default()));
        tracing::trace!("Patch DOp stream => {dops_patch:?}");
        dops_patch
    }

    /// Merge a templated memory slot with concrete operands
    fn fuse_tmem_user(dop_ms: &hpu_asm::MemSlot, iop_arg: &hpu_asm::Arg) -> hpu_asm::MemSlot {
        if let hpu_asm::Arg::MemId(iop_ms) = iop_arg {
            hpu_asm::MemSlot::new_uncheck(
                iop_ms.bid(),
                iop_ms.cid() + dop_ms.cid(),
                hpu_asm::MemMode::Raw,
                None,
            )
        } else {
            panic!("Dop template arg patching only work on MemId")
        }
    }

    /// Merge a templated heap slot with heap properties
    fn fuse_tmem_heap(dop_ms: &hpu_asm::MemSlot, heap: &hpu_asm::MemRegion) -> hpu_asm::MemSlot {
        assert!(heap.size >= dop_ms.cid(),
                    "Asm heap overflow, request more heap than the one allocated for simulation. Check fw/simulation parameters");
        hpu_asm::MemSlot::new_uncheck(heap.bid, dop_ms.cid(), hpu_asm::MemMode::Raw, None)
    }
}
