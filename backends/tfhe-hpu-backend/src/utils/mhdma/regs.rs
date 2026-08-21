//! Register access by name, MHDMA host request injection and multi-board setup.

use hw_regmap::FlatRegmap;
use tfhe_hpu_backend::ffi;
use tfhe_hpu_backend::prelude::*;
use tracing::info;

use super::{on_each_node, PCS};

// Position of local HPU (who am I : hpu_id_N[31])
pub(crate) const HPU_ID_LOCAL_BIT: u32 = 1 << 31;
pub(crate) const HPU_ID_MAC_MASK: u32 = 0x00FF_FFFF; // hpu_id_N[23:0]

// opcodes -----------------------------------------------------------------------------------------
pub(crate) const REQ_ID_NOTIFY: u32 = 2;
pub(crate) const REQ_ID_NOTIFY_ACK: u32 = 3;
pub(crate) const REQ_ID_READ: u32 = 6;
pub(crate) const REQ_ID_EMISSION: u32 = 7;

// =================================================================================================
// Low-level register access
// =================================================================================================

/// Scalar register access by name: resolve name -> offset via the regmap, then MMIO.
pub(crate) trait RegByName {
    fn reg_read(&self, regmap: &FlatRegmap, name: &str) -> u32;
    fn reg_write(&mut self, regmap: &FlatRegmap, name: &str, val: u32);
}

impl RegByName for ffi::HpuHw {
    fn reg_read(&self, regmap: &FlatRegmap, name: &str) -> u32 {
        let reg = regmap
            .register()
            .get(name)
            .unwrap_or_else(|| panic!("Register {name} not found in regmap"));
        self.read_reg(*reg.offset() as u64)
    }
    fn reg_write(&mut self, regmap: &FlatRegmap, name: &str, val: u32) {
        let reg = regmap
            .register()
            .get(name)
            .unwrap_or_else(|| panic!("Register {name} not found in regmap"));
        self.write_reg(*reg.offset() as u64, val);
    }
}

// =================================================================================================
// MHDMA request injection (host -> HPU)
// Every requests are issued by same consecutive register writes: req_addr then req_id.
// The opcode in req_id selects the type; see mhdma_notify / issue_reads.
// =================================================================================================

fn build_req_id(opcode: u32, node: u8, mode: u32) -> u32 {
    // assert, not debug_assert: release drops those, and node >= 16 bleeds into the opcode nibble.
    assert!(
        node < 16 && mode < 4,
        "req_id field overflow: node={node} mode={mode}"
    );
    (opcode << 20) | ((node as u32) << 16) | (mode << 14)
}

/// Inject one host request: req_addr (dst[31:16] | src[15:0]) then req_id (opcode | node | mode).
pub(crate) fn req_inject(
    hw: &mut ffi::HpuHw,
    regmap: &FlatRegmap,
    opcode: u32,
    node: u8,
    src: u16,
    dst: u16,
    mode: u32,
) {
    hw.reg_write(
        regmap,
        "mhdma_request::req_addr",
        ((dst as u32) << 16) | (src as u32),
    );
    hw.reg_write(
        regmap,
        "mhdma_request::req_id",
        build_req_id(opcode, node, mode),
    );
}

/// Issue one MHDMA notify from this card to `node`.
pub fn mhdma_notify(
    hw: &mut ffi::HpuHw,
    regmap: &FlatRegmap,
    node: u8,
    src_addr: u16,
    dst_addr: u16,
    mode: u32,
) {
    req_inject(hw, regmap, REQ_ID_NOTIFY, node, src_addr, dst_addr, mode);
}

/// sends "count" notifies to a "target"
pub(crate) fn notify_burst(
    peers: &mut [ffi::HpuHw],
    regmap: &FlatRegmap,
    target: u8,
    count: u32,
    base: u16,
) {
    for peer in peers.iter_mut() {
        for k in 0..count {
            let a = base.wrapping_add(k as u16);
            mhdma_notify(peer, regmap, target, a, a, 0);
        }
    }
    // let the frames land before the caller changes the error/mask state
    std::thread::sleep(std::time::Duration::from_millis(200));
}

// ------------------------------------------------------------------------------------------------
// Setup (applied to every node)
// ------------------------------------------------------------------------------------------------
/// Configure every board:
///  - "node_id"-slot HPU-ID table (MAC per slot, local bit on the board's own slot)
///  - timeouts
///  - HBM CT base addresses
pub fn mhdma_setup(hw: &mut ffi::HpuHw, config: &HpuConfig, regmap: &FlatRegmap, fpga_id: u8) {
    let props = ffi::HpuHw::get_board_properties();

    info!("setup over nodes {:?}", config.fpga.node_id);

    on_each_node(hw, config, fpga_id, |h, node| {
        // HPU-ID table: MAC per slot, local bit on the board's own slot
        for &slot in &config.fpga.node_id {
            // Mask mac_addr: hpu_id_N[31] is the local flag, and a stray bit there sticks error_id.
            let mac = props
                .get(slot as usize)
                .map(|p| p.mac_addr & HPU_ID_MAC_MASK)
                .unwrap_or(0);
            let val = if slot == node {
                mac | HPU_ID_LOCAL_BIT
            } else {
                mac
            };
            h.reg_write(regmap, &format!("mhdma_system::hpu_id_{slot}"), val);
        }

        // timeouts at max, so retries never fire and a stall stays visible as a stall
        h.reg_write(regmap, "mhdma_system::timeout_notify", 0xFFFF_FFFF);
        h.reg_write(regmap, "mhdma_system::timeout_read_req", 0xFFFF_FFFF);

        for (pc, (base, _)) in PCS.iter().enumerate() {
            h.reg_write(
                regmap,
                &format!("mhdma_hbm_axi4_addr_2in3::ct_pc{pc}_msb"),
                (base >> 32) as u32,
            );
            h.reg_write(
                regmap,
                &format!("mhdma_hbm_axi4_addr_2in3::ct_pc{pc}_lsb"),
                *base as u32,
            );
        }
    });

    info!("setup complete.");
}
