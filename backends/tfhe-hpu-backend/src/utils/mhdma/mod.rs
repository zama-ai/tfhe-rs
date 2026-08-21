//! MHDMA host-side tooling (used by the `hputil` CLI).
//!
//! Layout:
//!  - [`regs`]     register access by name, request injection, multi-board setup
//!  - [`trace`]    packet-trace debug ring: decode, status/arm/dump/wait, mask, inject
//!  - [`tests`]    multi-board traffic tests (notify / read-request / stress)
//!  - [`selftest`] fault-injecting self-tests + the umbrella suite
//!
//! This file holds the shared constants and the cross-file helpers
//! (multi-board fan-out, error/stat sweeps, CLI bounds).

use hw_regmap::FlatRegmap;
use tfhe_hpu_backend::ffi;
use tfhe_hpu_backend::prelude::*;

mod regs;
mod selftest;
mod tests;
mod trace;

pub use regs::{mhdma_notify, mhdma_setup};
pub use selftest::{
    pkt_trace_error_midstream_selftest, pkt_trace_inject_selftest, pkt_trace_selftest, selftest_all,
};
pub use tests::{notify_test, readreq_stress, readreq_test, NotifyPattern, ReadPattern};
pub use trace::{
    pkt_trace_arm, pkt_trace_dump, pkt_trace_inject, pkt_trace_set_mask, pkt_trace_status,
    pkt_trace_wait,
};

use regs::RegByName;
use trace::pkt_trace_print_errors;

// =================================================================================================
// MAGIC NUMBERS (ground truth: mhdma_pkg.sv)
// =================================================================================================

// CT slot ceiling = the PC0/PC1 non-overlap limit; slots are 16-bit, hence the assert.
pub(crate) const HW_MAX_ADDR: u64 = (PC1_ADDR - PC0_ADDR) / CT_MEM_BYTES;
const _: () = assert!(HW_MAX_ADDR <= 0x1_0000);

// Fifo depths
pub(crate) const REQ_FIFO_DEPTH: u32 = 128;
pub(crate) const RX_FIFO_DEPTH: u32 = 256;

// HBM CT geometry --------------------------------------------------------------------------------
// PC base addresses double as mhdma_hbm_axi4_addr_2in3::ct_pc{0,1}_{lsb,msb} setup values.
pub(crate) const CT_MEM_BYTES: u64 = 0x3000; // per-ciphertext stride (page aligned)
pub(crate) const PC0_ADDR: u64 = 0x44_0000_0000;
pub(crate) const PC1_ADDR: u64 = 0x44_2000_0000;
pub(crate) const PC0_SIZE: usize = 8224; // 0x2020 = 257 words x 32B at AXI_DATA_W=256 (AXI-width dependent)
pub(crate) const PC1_SIZE: usize = 8192; // 0x2000 bytes

// The pseudo-channels
pub(crate) const PCS: [(u64, usize); 2] = [(PC0_ADDR, PC0_SIZE), (PC1_ADDR, PC1_SIZE)];

// =================================================================================================
// Helper functions
// =================================================================================================

// -c bounds at the CLI boundary: the in-test guards then never do unchecked u32 math on user input.
fn parse_count(s: &str, max: u32, what: &str) -> Result<u32, String> {
    match s.parse::<u32>() {
        Ok(v) if (1..=max).contains(&v) => Ok(v),
        Ok(v) => Err(format!("{v} is out of range 1..={max} ({what})")),
        Err(_) => Err(format!("`{s}` is not a number")),
    }
}

pub fn count_fifo(s: &str) -> Result<u32, String> {
    parse_count(s, REQ_FIFO_DEPTH, "command FIFO depth")
}

/// Reject a burst needing `count * per` slots of a `depth`-deep resource;
/// prints the arithmetic and the largest usable -c. True = it fits.
pub(crate) fn fifo_guard(what: &str, per: u32, count: u32, depth: u32) -> bool {
    let need = count * per;
    if need <= depth {
        return true;
    }
    println!(
        "[FAIL] {what}: {count}x{per}={need} > {depth} available; use -c <= {}",
        depth / per
    );
    false
}

/// Run `f` on every node in `config.fpga.node_id`, in parallel.
pub(crate) fn on_each_node<R, F>(
    hw: &mut ffi::HpuHw,
    config: &HpuConfig,
    fpga_id: u8,
    f: F,
) -> Vec<(u8, R)>
where
    F: Fn(&mut ffi::HpuHw, u8) -> R + Sync,
    R: Send,
{
    let nodes = &config.fpga.node_id;
    let ffi = &config.fpga.ffi;
    let polling = std::time::Duration::from_micros(config.fpga.polling_us);
    let f = &f;
    std::thread::scope(|s| {
        // spawn peers first so they run concurrently with the main-thread board
        let peers: Vec<_> = nodes
            .iter()
            .copied()
            .filter(|&node| node != fpga_id)
            .map(|node| {
                s.spawn(move || {
                    let mut peer = ffi::HpuHw::open_hpu_hw(node, ffi, polling);
                    (node, f(&mut peer, node))
                })
            })
            .collect();

        let mut out = Vec::with_capacity(nodes.len());
        if nodes.contains(&fpga_id) {
            out.push((fpga_id, f(hw, fpga_id)));
        }
        out.extend(peers.into_iter().map(|h| h.join().unwrap()));
        out
    })
}

// Stat / error helpers ---------------------------------------------------------------------------
/// The network stat counters (all read-to-clear).
const STAT_COUNTERS: [&str; 4] = [
    "mhdma_request::stat_nb_notify_received",
    "mhdma_request::stat_nb_nack_received",
    "mhdma_request::stat_nb_ce_received",
    "mhdma_request::stat_nb_read_req_received",
];

/// Read (and thereby clear) the stat counters, discarding the values.
fn stat_clear(hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
    for name in STAT_COUNTERS {
        let _ = hw.reg_read(regmap, name);
    }
}

/// Clear the sticky error
pub(crate) fn error_reset(hw: &ffi::HpuHw, regmap: &FlatRegmap) {
    let _ = hw.reg_read(regmap, "mhdma_system::errors");
}

/// Put every board in a clean pre-test state:
/// clear sticky errors & counters, drain any read-request completions left over from a prior
/// aborted run, flush the read-to-clear counters so the post-traffic read reflects only this test.
pub(crate) fn reset_boards(
    hw: &mut ffi::HpuHw,
    config: &HpuConfig,
    regmap: &FlatRegmap,
    fpga_id: u8,
) {
    on_each_node(hw, config, fpga_id, |h, _| {
        error_reset(h, regmap);
        stat_clear(h, regmap);
        for _ in 0..64 {
            let _ = h.reg_read(regmap, "mhdma_request::read_request"); // dequeue
        }
    });
}

/// Decode & report any non-zero per-board error values.
pub(crate) fn report_errors(errs: &[(u8, u32)]) -> bool {
    let mut clean = true;
    for &(node, e) in errs {
        if e != 0 {
            println!("[FAIL] board {node}: mhdma errors = 0x{e:04x}");
            pkt_trace_print_errors(e, "        ");
            clean = false;
        }
    }
    clean
}

/// Read every board's errors register once and report.
pub(crate) fn errors_report(
    hw: &mut ffi::HpuHw,
    config: &HpuConfig,
    regmap: &FlatRegmap,
    fpga_id: u8,
) -> bool {
    let errs = on_each_node(hw, config, fpga_id, |h, _| {
        h.reg_read(regmap, "mhdma_system::errors")
    });
    report_errors(&errs)
}
