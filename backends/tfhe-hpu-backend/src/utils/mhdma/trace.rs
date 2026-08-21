//! MHDMA packet-trace debug ring: entry decode, status/arm/dump/wait, trigger mask and
//! software error inject.
//!
//! The mhdma decoder circularly captures decoded packet headers + other relevant data.
//! On the first mhdma-domain error it keeps capturing up to TRACE_DEPTH/2 more headers then
//! freezes, so the ring holds ~half from before the fault and ~half after.
//!
//! The tail is a CEILING: TRACE_TAIL_TIMEOUT (1024 cyc) usually fires first; short tails are
//! normal.

use hw_regmap::FlatRegmap;
use tfhe_hpu_backend::ffi;
use tracing::{info, warn};

use super::error_reset;
use super::regs::{RegByName, REQ_ID_EMISSION, REQ_ID_NOTIFY, REQ_ID_NOTIFY_ACK, REQ_ID_READ};

// network trace ----------------------------------------------------------------------------------
pub(crate) const PKT_TRACE_DEPTH: usize = 64;
const PKT_TRACE_WORDS_PER_ENTRY: usize = 4;

const PKT_TRACE_ERR_W: u32 = 12;
const PKT_TRACE_FSM_W: u32 = 13;
const PKT_TRACE_TS_W: u32 = 7;
const PKT_TRACE_TS_PERIOD: u32 = 1 << PKT_TRACE_TS_W;

pub(crate) const PKT_TRACE_MASK_NONE: u32 = 0x0000_0000; // no real error arms the trace
pub(crate) const PKT_TRACE_MASK_ALL: u32 = 0x7FFF_FFFF;
pub(crate) const PKT_TRACE_INJECT_BIT: u32 = 1 << 31;

const PKT_TRACE_ERR_LABEL: [&str; 14] = [
    "hpu_onehot_id_violation",  // 0
    "hbm_write_error_pc0",      // 1
    "hbm_write_error_pc1",      // 2
    "ct_seq_num_mismatch",      // 3
    "master_max_retry_notify",  // 4
    "master_max_retry_rreq",    // 5
    "hbm_read_resp_error",      // 6
    "slave_rreq_cmdq_ovf",      // 7
    "decoder_rx_fifo_ovf",      // 8
    "formatter_payload_gap",    // 9
    "formatter_slave_discard",  // 10
    "formatter_master_discard", // 11
    "master_notify_cmdq_ovf",   // 12 (not in the trace)
    "master_rreq_cmdq_ovf",     // 13 (not in the trace)
];

// Wire decode ------------------------------------------------------------------------------------

/// Extract a `width`-bit field starting at bit `lsb`.
fn bitfield(value: u32, lsb: u32, width: u32) -> u32 {
    (value >> lsb) & ((1u32 << width) - 1)
}

/// word0..2 = command_t (96b); word3 = {ts[6:0]@25, fsm[12:0]@12, errors[11:0]@0}.
pub(crate) struct PktTraceEntry {
    src_mac: u32,
    hpu: u32,
    iop: u32,
    req: u32,
    mode: u32,
    flag: u32,
    seq: u32,
    src_addr: u32,
    dst_addr: u32,
    ts: u32,
    fsm: u32,
    pub(crate) errbits: u32,
}

impl PktTraceEntry {
    /// Decode one entry from its 4 raw words.
    fn decode(w: &[u32]) -> Self {
        let (w0, w1, w2, w3) = (w[0], w[1], w[2], w[3]);
        Self {
            dst_addr: bitfield(w0, 0, 16),
            src_addr: bitfield(w0, 16, 16),
            iop: bitfield(w1, 0, 8),
            req: bitfield(w1, 8, 4),
            mode: bitfield(w1, 12, 2),
            flag: bitfield(w1, 14, 6),
            hpu: bitfield(w1, 28, 4),
            seq: bitfield(w2, 0, 8),
            src_mac: bitfield(w2, 8, 24),
            errbits: bitfield(w3, 0, PKT_TRACE_ERR_W),
            fsm: bitfield(w3, PKT_TRACE_ERR_W, PKT_TRACE_FSM_W),
            ts: bitfield(w3, PKT_TRACE_ERR_W + PKT_TRACE_FSM_W, PKT_TRACE_TS_W),
        }
    }

    /// fsm[12:0] = {fmt[2:0], cem[1:0], nrx[1:0], burst[1:0], rreq[1:0], ntfy[1:0]}
    fn fsm_str(&self) -> String {
        let f = self.fsm;
        format!(
            "{},{},{},{},{},{}",
            bitfield(f, 10, 3),
            bitfield(f, 8, 2),
            bitfield(f, 6, 2),
            bitfield(f, 4, 2),
            bitfield(f, 2, 2),
            bitfield(f, 0, 2)
        )
    }

    /// req_id opcode -> mnemonic (mhdma_pkg req_id opcodes).
    fn req_name(&self) -> &'static str {
        match self.req {
            REQ_ID_NOTIFY => "NOTIFY",
            REQ_ID_NOTIFY_ACK => "NACK",
            REQ_ID_READ => "READ",
            REQ_ID_EMISSION => "EMISSION",
            _ => "?",
        }
    }
}

/// (bit, label) of every error set in the bitmap (errors register or a trace entry).
fn err_labels(errbits: u32) -> Vec<(usize, &'static str)> {
    let mut v: Vec<(usize, &str)> = PKT_TRACE_ERR_LABEL
        .iter()
        .enumerate()
        .filter(|(i, _)| (errbits >> i) & 1 != 0)
        .map(|(i, &label)| (i, label))
        .collect();
    // errors register only: trace_aux captures real errors, never the injected one
    if errbits & PKT_TRACE_INJECT_BIT != 0 {
        v.push((31, "software_injected_error"));
    }
    v
}

/// Set error labels as a compact comma-joined string (empty if none) - for inline per-entry decode.
fn err_names(errbits: u32) -> String {
    err_labels(errbits)
        .iter()
        .map(|&(_, label)| label)
        .collect::<Vec<_>>()
        .join(",")
}

// =================================================================================================
// Ring operations
// =================================================================================================

/// Decode + print the errors bitmap, one per line.
pub(crate) fn pkt_trace_print_errors(errbits: u32, prefix: &str) {
    let labels = err_labels(errbits);
    if labels.is_empty() {
        println!("{prefix}(none)");
    }
    for (i, label) in labels {
        println!("{prefix}[{i}] {label}");
    }
}

/// Set the trace-trigger mask and also clears inject_err, so a later inject sees a fresh 0->1 edge.
pub fn pkt_trace_set_mask(hw: &mut ffi::HpuHw, regmap: &FlatRegmap, mask: u32) {
    let val = mask & PKT_TRACE_MASK_ALL;
    hw.reg_write(regmap, "mhdma_system::error_mask", val);
    info!("trace trigger mask = 0x{val:08x} (inject_err cleared)");
}

/// Inject a synthetic error
pub fn pkt_trace_inject(hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
    let mask = hw.reg_read(regmap, "mhdma_system::error_mask") & PKT_TRACE_MASK_ALL;
    hw.reg_write(regmap, "mhdma_system::error_mask", mask);
    hw.reg_write(
        regmap,
        "mhdma_system::error_mask",
        mask | PKT_TRACE_INJECT_BIT,
    );
    info!("injected a software error (error_mask.inject_err 0->1)");
}

/// Pop + decode the whole ring (the HW read pointer auto-increments per trace_data read), indexed
/// by absolute entry. Only meaningful while frozen: earlier reads return 0 without advancing.
fn pkt_trace_read_ring(hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> Vec<PktTraceEntry> {
    let data_off = {
        let reg = regmap
            .register()
            .get("mhdma_system::trace_data")
            .unwrap_or_else(|| {
                panic!("mhdma_system::trace_data not found - regmap must be synced")
            });
        *reg.offset() as u64
    };
    let words: Vec<u32> = (0..PKT_TRACE_DEPTH * PKT_TRACE_WORDS_PER_ENTRY)
        .map(|_| hw.read_reg(data_off))
        .collect();

    words
        .chunks(PKT_TRACE_WORDS_PER_ENTRY)
        .map(PktTraceEntry::decode)
        .collect()
}

/// Valid-entry window for a freeze snapshot, as (count, index of the oldest).
///   wrapped=1 -> ring full: all TRACE_DEPTH entries valid, oldest at wptr (rotate)
///   wrapped=0 -> partial fill: only [0..wptr-1] valid, in order (the rest are stale)
fn pkt_trace_window(wptr: usize, wrapped: bool) -> (usize, usize) {
    if wrapped {
        (PKT_TRACE_DEPTH, wptr)
    } else {
        (wptr, 0)
    }
}

/// READ and decode trace_ctrl, the trigger mask and the errors register.
///
/// Note the errors read is ReadNotify: it consumes the sticky bits and so re-enables the trigger.
pub fn pkt_trace_status(hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
    let ctrl = hw.reg_read(regmap, "mhdma_system::trace_ctrl");
    let frozen = bitfield(ctrl, 0, 1);
    let wptr = bitfield(ctrl, 1, 6);
    let wrapped = bitfield(ctrl, 7, 1);
    let mask = hw.reg_read(regmap, "mhdma_system::error_mask");
    let errbits = hw.reg_read(regmap, "mhdma_system::errors");

    println!("=== MHDMA packet-trace status ===");
    println!("  trace_ctrl = 0x{ctrl:08x}");
    let frozen_txt = if frozen == 1 {
        "(buffer FROZEN, ready to read)"
    } else {
        "(armed / capturing)"
    };
    println!("  frozen     = {frozen} {frozen_txt}");
    // The RTL only samples wptr/wrapped into the cfg domain while frozen, so they are leftovers
    // from the previous freeze until the next one.
    let (wptr_txt, wrapped_txt) = if frozen == 0 {
        (
            "(stale: only sampled at freeze)",
            "(stale: only sampled at freeze)",
        )
    } else if wrapped == 1 {
        (
            "(oldest entry index)",
            "(ring FULL: all entries valid, rotate by wptr)",
        )
    } else {
        (
            "(valid entry count / next write slot; oldest is entry 0)",
            "(PARTIAL: only entries [0..wptr-1] valid, rest stale)",
        )
    };
    println!("  wptr       = {wptr} {wptr_txt}");
    println!("  wrapped    = {wrapped} {wrapped_txt}");
    println!(
        "  trig mask  = 0x{:08x} (1 = that errors bit arms the trace; only [11:0] are wired)",
        mask & PKT_TRACE_MASK_ALL
    );
    println!("  inject_err = {}", (mask >> 31) & 1);
    println!("  errors     = 0x{errbits:04x}");
    pkt_trace_print_errors(errbits, "    ");
    println!("  NOTE: that errors read CLEARED the sticky bits and re-enabled the trace trigger.");
}

/// Flush + re-arm circular capture:
/// -> Clears the sticky errors, writes trace_ctrl with frozen=0 (bit0), then confirm frozen is cleared.
///  The clear is mandatory: the mhdma-domain error bits stay registered until mhdma_system::errors is read,
/// and the trigger is built from them, so arming on top of one re-freezes the ring at once.
pub fn pkt_trace_arm(hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> bool {
    info!("Arming packet-trace buffer ...");

    error_reset(hw, regmap);
    hw.reg_write(regmap, "mhdma_system::trace_ctrl", 0x0);

    // The arm strobe crosses a 4-stage CDC into clk_mhdma and must flush the stale frozen bit.
    std::thread::sleep(std::time::Duration::from_millis(100));

    let ctrl = hw.reg_read(regmap, "mhdma_system::trace_ctrl");
    let frozen = bitfield(ctrl, 0, 1);

    // No wptr check: republished only while frozen (mhdma_pkt_trace.sv:369), so here it is stale.
    if frozen != 0 {
        // println! too: RUST_LOG without a matching directive suppresses warn!.
        println!("[FAIL] pkt-trace arm: frozen={frozen} after arm (expected 0)");
        warn!(
            "frozen={frozen} after arm (expected 0). Re-arm/CDC path broken, or an error \
             is asserted continuously (see 'status')."
        );
        return false;
    }
    info!("packet-trace armed (frozen=0).");
    true
}

/// trace_ctrl.frozen
pub(crate) fn trace_frozen(hw: &ffi::HpuHw, regmap: &FlatRegmap) -> bool {
    bitfield(hw.reg_read(regmap, "mhdma_system::trace_ctrl"), 0, 1) == 1
}

/// Bounded poll of the frozen bit. Does not dump, so the caller keeps control of the single
/// clear-on-read of the errors register.
pub(crate) fn pkt_trace_poll_frozen(
    hw: &mut ffi::HpuHw,
    regmap: &FlatRegmap,
    timeout_s: u64,
) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_s);
    loop {
        if trace_frozen(hw, regmap) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// SW-freeze the trace now:
/// -> Write trace_ctrl frozen=1 (bit0), then poll until frozen (bounded).
fn pkt_trace_freeze(hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> bool {
    hw.reg_write(regmap, "mhdma_system::trace_ctrl", 0x1); // frozen=1 => SW freeze
    pkt_trace_poll_frozen(hw, regmap, 2)
}

/// Read the frozen ring
pub(crate) fn pkt_trace_snapshot(
    hw: &mut ffi::HpuHw,
    regmap: &FlatRegmap,
) -> Option<(Vec<PktTraceEntry>, usize, usize)> {
    let ctrl = hw.reg_read(regmap, "mhdma_system::trace_ctrl");
    if bitfield(ctrl, 0, 1) != 1 {
        return None;
    }
    let wptr = bitfield(ctrl, 1, 6) as usize;
    let wrapped = bitfield(ctrl, 7, 1) == 1;

    if wrapped {
        info!("ring FULL, {PKT_TRACE_DEPTH} entries (wptr={wptr} -> oldest)");
    } else {
        info!("ring PARTIAL, {wptr} valid entries (rest stale, not shown)");
    }
    let (n_valid, first) = pkt_trace_window(wptr, wrapped);
    Some((pkt_trace_read_ring(hw, regmap), n_valid, first))
}

/// SW-freeze if needed, then read + print the ring oldest->newest.
pub fn pkt_trace_dump(hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> Option<(u32, usize)> {
    if !trace_frozen(hw, regmap) {
        println!("  not frozen; issuing SW-freeze ...");
        if !pkt_trace_freeze(hw, regmap) {
            warn!("buffer is NOT frozen and SW-freeze did not take; nothing to dump");
            return None;
        }
    }
    let Some((entries, n_valid, first)) = pkt_trace_snapshot(hw, regmap) else {
        warn!("ring went un-frozen between the freeze and the read; nothing to dump");
        return None;
    };

    pkt_trace_print_ring(&entries, n_valid, first);

    let errbits_reg = hw.reg_read(regmap, "mhdma_system::errors");
    println!("  errors register now = 0x{errbits_reg:04x}");
    pkt_trace_print_errors(errbits_reg, "    ");
    println!("  ring left FROZEN (capture stopped) - run `pkt-trace arm` to resume capture");
    Some((errbits_reg, n_valid))
}

/// Print `n_valid` entries starting at `first`, oldest->newest.
pub(crate) fn pkt_trace_print_ring(entries: &[PktTraceEntry], n_valid: usize, first: usize) {
    println!();
    // header, separator and rows all use these exact widths, so columns always line up
    let header = format!(
        "{:<1} {:>4} {:>5} | {:>8} {:>3} {:>3} {:>8} {:>4} {:>4} {:>3} | {:>6} {:>6} | {:>4} {:>11} | {:>6}",
        "", "ord", "entry", "src_mac", "hpu", "iop", "req_op", "mode", "flag", "seq", "src", "dst", "ts", "fsm", "errors",
    );
    let rule = "-".repeat(header.len());

    println!("  fsm = fmt,cem,nrx,brst,rreq,ntfy   (* = entry captured with a live error bit)");
    println!(
        "  ts  = free-running clk_mhdma counter, WRAPS every {PKT_TRACE_TS_PERIOD} cycles: only \
         orders entries captured within one such window"
    );
    println!("{header}");
    println!("{rule}");

    for ord in 0..n_valid {
        let e = (first + ord) % PKT_TRACE_DEPTH;
        let en = &entries[e];

        let req_nm = en.req_name();
        let mark = if en.errbits != 0 { '*' } else { ' ' }; // entry captured with a live error bit
                                                            // interpret this entry's error bits inline (only when set), instead of a global legend
        let err_txt = if en.errbits != 0 {
            format!("  <{}>", err_names(en.errbits))
        } else {
            String::new()
        };
        let mac_s = format!("0x{:06x}", en.src_mac);
        let flag_s = format!("0x{:02x}", en.flag);
        let src_s = format!("0x{:04x}", en.src_addr);
        let dst_s = format!("0x{:04x}", en.dst_addr);
        let err_s = format!("0x{:03x}", en.errbits);
        let fsm_s = en.fsm_str();
        let (hpu, iop, mode, seq, ts) = (en.hpu, en.iop, en.mode, en.seq, en.ts);
        println!(
            "{mark:<1} {ord:>4} {e:>5} | {mac_s:>8} {hpu:>3} {iop:>3} {req_nm:>8} {mode:>4} {flag_s:>4} {seq:>3} | {src_s:>6} {dst_s:>6} | {ts:>4} {fsm_s:>11} | {err_s:>6}{err_txt}"
        );
    }
    println!("{rule}");

    // captured entries per source board: spots a peer that delivered nothing
    let mut per_src: Vec<(u32, usize)> = Vec::new();
    for ord in 0..n_valid {
        let mac = entries[(first + ord) % PKT_TRACE_DEPTH].src_mac;
        match per_src.iter_mut().find(|(m, _)| *m == mac) {
            Some(slot) => slot.1 += 1,
            None => per_src.push((mac, 1)),
        }
    }
    let per_src_txt: Vec<String> = per_src
        .iter()
        .map(|(mac, n)| format!("0x{mac:06x}={n}"))
        .collect();
    println!("  entries per src_mac: {}", per_src_txt.join("  "));
    println!();
}

/// Poll trace_ctrl until frozen (bounded by `timeout_s`), then dump.
/// Returns the dump's (errors word, valid entry count), or None if it never froze.
pub fn pkt_trace_wait(
    hw: &mut ffi::HpuHw,
    regmap: &FlatRegmap,
    timeout_s: u64,
) -> Option<(u32, usize)> {
    info!("waiting up to {timeout_s}s for the packet-trace buffer to freeze ...");
    if !pkt_trace_poll_frozen(hw, regmap, timeout_s) {
        warn!("buffer did not freeze within {timeout_s}s (no mhdma error occurred).");
        return None;
    }
    info!("FROZEN detected.");
    pkt_trace_dump(hw, regmap)
}
