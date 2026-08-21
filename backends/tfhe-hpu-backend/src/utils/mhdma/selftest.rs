//! Self-contained self-tests: packet-trace ring fault injection and the umbrella suite.

use hw_regmap::FlatRegmap;
use tfhe_hpu_backend::ffi;
use tfhe_hpu_backend::prelude::*;
use tracing::{info, warn};

use super::regs::{
    mhdma_notify, mhdma_setup, notify_burst, RegByName, HPU_ID_LOCAL_BIT, HPU_ID_MAC_MASK,
};
use super::tests::{notify_test, readreq_stress, readreq_test, NotifyPattern, ReadPattern};
use super::trace::{
    pkt_trace_arm, pkt_trace_inject, pkt_trace_poll_frozen, pkt_trace_print_errors,
    pkt_trace_print_ring, pkt_trace_set_mask, pkt_trace_snapshot, pkt_trace_wait, trace_frozen,
    PKT_TRACE_DEPTH, PKT_TRACE_INJECT_BIT, PKT_TRACE_MASK_ALL, PKT_TRACE_MASK_NONE,
};
use super::{errors_report, fifo_guard, report_errors, reset_boards};

// ------------------------------------------------------------------------------------------------
// Fault injection helpers
// ------------------------------------------------------------------------------------------------

/// Tell if at least one slot has the local bit set.
fn has_local_hpu_id(hw: &ffi::HpuHw, regmap: &FlatRegmap) -> bool {
    (0..8u8)
        .any(|s| hw.reg_read(regmap, &format!("mhdma_system::hpu_id_{s}")) & HPU_ID_LOCAL_BIT != 0)
}

/// Break the one-hot HPU-ID table to trigger error_id: mark a second slot local.
/// Returns (slot, original) to restore, or None if every slot already has the local bit.
fn break_onehot(hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> Option<(usize, u32)> {
    let local_mac = (0..8usize)
        .map(|s| hw.reg_read(regmap, &format!("mhdma_system::hpu_id_{s}")))
        .find(|v| v & HPU_ID_LOCAL_BIT != 0)
        .map(|v| v & HPU_ID_MAC_MASK)?;

    for slot in 0..8usize {
        let name = format!("mhdma_system::hpu_id_{slot}");
        let orig = hw.reg_read(regmap, &name);
        if orig & HPU_ID_LOCAL_BIT == 0 {
            hw.reg_write(
                regmap,
                &name,
                (orig & !HPU_ID_MAC_MASK) | local_mac | HPU_ID_LOCAL_BIT,
            );
            return Some((slot, orig));
        }
    }
    None
}

/// Wipe errors/counters on every board, optionally set the trigger mask, then arm.
/// False if the ring would not arm.
fn pkt_trace_reset_and_arm(
    hw: &mut ffi::HpuHw,
    config: &HpuConfig,
    regmap: &FlatRegmap,
    fpga_id: u8,
    mask: Option<u32>,
) -> bool {
    reset_boards(hw, config, regmap, fpga_id);
    if let Some(m) = mask {
        pkt_trace_set_mask(hw, regmap, m);
    }
    pkt_trace_arm(hw, regmap)
}

/// Log the outcome of a `break_onehot` fault injection.
fn log_forced_fault(broke: &Option<(usize, u32)>, issued: u32, total: u32) {
    match broke {
        Some((slot, _)) => {
            info!("forced error_id ({issued}/{total}) via hpu_id_{slot} (one-hot violation)")
        }
        None => warn!("no free hpu_id slot to break one-hot"),
    }
}

// ------------------------------------------------------------------------------------------------
// Packet-trace self-tests
// ------------------------------------------------------------------------------------------------

/// Self-contained pkt-trace ring self-test (needs >= 2 boards).
/// Arms the board-under-test, filling trace, forces a one-hot violation to freeze, dumps it, then restores.
pub fn pkt_trace_selftest(
    hw: &mut ffi::HpuHw,
    config: &HpuConfig,
    regmap: &FlatRegmap,
    fpga_id: u8,
    count: u32,
    timeout_s: u64,
    random_err: bool,
) -> bool {
    let nodes = &config.fpga.node_id;
    if nodes.len() < 2 {
        println!(
            "[FAIL] ring self-test needs >= 2 boards in the config (node_id = {nodes:?}); \
             cannot run on a single board."
        );
        return false;
    }
    info!("pkt-trace ring self-test over nodes {nodes:?} (board-under-test = {fpga_id}, random_err={random_err})");

    // setup; None = do not touch the mask, so a hand-set mask stays in force
    if !pkt_trace_reset_and_arm(hw, config, regmap, fpga_id, None) {
        return false;
    }

    if !has_local_hpu_id(hw, regmap) {
        println!("[FAIL] pkt-trace selftest: no local hpu_id bit set - run `mhdma setup` first");
        return false;
    }

    // ring traffic
    let polling = std::time::Duration::from_micros(config.fpga.polling_us);
    let total = count * nodes.len() as u32;
    let mut issued = 0u32;
    let mut broke = None;
    let mut armed_at_fault = None;

    let trigger = if random_err && total > 0 {
        rand::random_range(0..total)
    } else {
        u32::MAX // never fires during the drive
    };

    for (idx, &node) in nodes.iter().enumerate() {
        let dst = nodes[(idx + 1) % nodes.len()];
        info!("  node {node} -> node {dst}: {count} notify(ies)");
        // reuse the open BUT handle; open a transient peer handle only for non-local nodes
        let mut peer =
            (node != fpga_id).then(|| ffi::HpuHw::open_hpu_hw(node, &config.fpga.ffi, polling));
        for k in 0..count {
            if issued == trigger {
                armed_at_fault = Some(!trace_frozen(hw, regmap));
                broke = break_onehot(hw, regmap); // fault always goes on the BUT (hw)
                log_forced_fault(&broke, issued, total);
            }
            let tgt = peer.as_mut().unwrap_or(&mut *hw);
            mhdma_notify(tgt, regmap, dst, k as u16, k as u16, 0);
            issued += 1;
        }
    }

    // default path: let traffic drain, then break
    if !random_err {
        std::thread::sleep(std::time::Duration::from_millis(
            300 + 20 * count as u64 * nodes.len() as u64,
        ));
        armed_at_fault = Some(!trace_frozen(hw, regmap));
        broke = break_onehot(hw, regmap);
        log_forced_fault(&broke, total, total);
    }
    let (slot, orig) = match broke {
        Some(b) => b,
        None => {
            println!("[FAIL] could not force one-hot violation (no free hpu_id slot); aborting.");
            return false;
        }
    };

    // wait for the freeze + dump
    let dumped = pkt_trace_wait(hw, regmap, timeout_s);
    let froze = dumped.is_some();
    let armed_at_fault = armed_at_fault.unwrap_or(false);
    let (errbits, captured) = match dumped {
        Some(v) => v,
        None => {
            let e = hw.reg_read(regmap, "mhdma_system::errors");
            let m = hw.reg_read(regmap, "mhdma_system::error_mask") & PKT_TRACE_MASK_ALL;
            println!("  ring never froze: errors = 0x{e:04x}, trig mask = 0x{m:08x}");
            pkt_trace_print_errors(e, "    ");
            (e, 0)
        }
    };

    // 5. restore one-hot, then clear the sticky error before re-arming
    let onehot = errbits & 1 != 0;
    let clean_errs = report_errors(&[(fpga_id, errbits & !1)]);

    hw.reg_write(regmap, &format!("mhdma_system::hpu_id_{slot}"), orig);

    // 6. wipe every board and re-arm
    pkt_trace_reset_and_arm(hw, config, regmap, fpga_id, None);

    let pass = froze && onehot && armed_at_fault && clean_errs && captured > 0;

    if pass {
        info!("self-test complete ({captured} entries captured, restored, re-armed).");
    } else {
        println!(
            "[FAIL] pkt-trace selftest: froze={froze} one_hot_error={onehot} \
             armed_at_fault={armed_at_fault} no_other_errors={clean_errs} captured={captured}"
        );
        if !armed_at_fault {
            println!(
                "       ring was ALREADY frozen when the fault was forced: an earlier real \
                      error froze it, so this run says nothing about the forced-fault path"
            );
        }
        if froze && captured == 0 {
            println!("       froze on an EMPTY ring: the trigger fired before any header landed");
        }
    }
    pass
}

/// Trigger a real error mid-stream and check the trace captured it on the entries that follow.
pub fn pkt_trace_error_midstream_selftest(
    hw: &mut ffi::HpuHw,
    config: &HpuConfig,
    regmap: &FlatRegmap,
    fpga_id: u8,
    count: Option<u32>,
    timeout_s: u64,
) -> bool {
    let nodes = &config.fpga.node_id;
    let peer_nb = nodes.len() as u32 - 1;
    let pre_per_peer = PKT_TRACE_DEPTH as u32 + 8;
    let pre = pre_per_peer * peer_nb;
    let polling = std::time::Duration::from_micros(config.fpga.polling_us);

    // guardrails
    if nodes.len() < 2 {
        println!("[FAIL] mid-stream error test needs >= 2 boards (node_id = {nodes:?})");
        return false;
    }
    if !has_local_hpu_id(hw, regmap) {
        println!("[FAIL] no local hpu_id bit set - run `mhdma setup` first");
        return false;
    }
    // depth-1: at least one pre-fault entry must survive, else `clean > 0` cannot hold
    // -c caps the post-fault burst; omitted, it spans the ring (depth-1 keeps >= 1 clean entry)
    let ring_cap = PKT_TRACE_DEPTH as u32 - 1;
    let post_max = count.unwrap_or(ring_cap / peer_nb);
    if !fifo_guard("post-fault ring", peer_nb, post_max, ring_cap) {
        return false;
    }

    // drawn, so the marked/clean boundary lands at a different ring index each run
    let post_per_peer = rand::random_range(1..=post_max);
    let post = post_per_peer * peer_nb;
    info!(
        "mid-stream error test -> board {fpga_id}: {pre_per_peer} pre-fault + {post_per_peer} \
         post-fault notify(ies)/peer ({pre}+{post} entries, ring depth {PKT_TRACE_DEPTH} => wraps)"
    );

    if !pkt_trace_reset_and_arm(hw, config, regmap, fpga_id, Some(PKT_TRACE_MASK_NONE)) {
        return false;
    }

    let mut peers: Vec<ffi::HpuHw> = nodes
        .iter()
        .filter(|&&n| n != fpga_id)
        .map(|&n| ffi::HpuHw::open_hpu_hw(n, &config.fpga.ffi, polling))
        .collect();

    // 1. clean traffic, enough to fill (and wrap) the ring; addresses 0..pre_per_peer
    notify_burst(&mut peers, regmap, fpga_id, pre_per_peer, 0);

    // 2. the fault: latched but masked, so capture keeps running
    let Some((slot, orig)) = break_onehot(hw, regmap) else {
        println!("[FAIL] could not force a one-hot violation (no free hpu_id slot)");
        return false;
    };
    info!(
        "forced error_id via hpu_id_{slot} after {pre} of {} notifies",
        pre + post
    );

    std::thread::sleep(std::time::Duration::from_millis(100));

    // masked, so nothing may have frozen yet
    let stayed_armed = !trace_frozen(hw, regmap);

    // 3. traffic with the error live (addresses pre_per_peer..)
    notify_burst(
        &mut peers,
        regmap,
        fpga_id,
        post_per_peer,
        pre_per_peer as u16,
    );

    // 4. unmask: the still-live error now arms the trace and the backstop freezes it
    let (mut marked, mut clean, mut valid) = (0usize, 0usize, 0usize);
    let mut wrapped = false;

    pkt_trace_set_mask(hw, regmap, PKT_TRACE_MASK_ALL);
    let froze = pkt_trace_poll_frozen(hw, regmap, timeout_s);

    if froze {
        if let Some((entries, n_valid, first)) = pkt_trace_snapshot(hw, regmap) {
            pkt_trace_print_ring(&entries, n_valid, first);
            valid = n_valid;
            // pkt_trace_window only yields the full depth when trace_ctrl.wrapped is set
            wrapped = n_valid == PKT_TRACE_DEPTH;
            // bit 0 only: another bit marks every later entry without exercising trace_aux.
            marked = (0..n_valid)
                .filter(|&o| entries[(first + o) % PKT_TRACE_DEPTH].errbits & 1 != 0)
                .count();
            clean = valid - marked;
        }
    }

    // single clear-on-read, after the dump so the table and this agree
    let errbits = hw.reg_read(regmap, "mhdma_system::errors");
    println!("  errors register = 0x{errbits:04x}");
    pkt_trace_print_errors(errbits, "    ");

    // restore and recover: the fault leaves notifies unacked, so wipe every board.
    drop(peers);
    hw.reg_write(regmap, &format!("mhdma_system::hpu_id_{slot}"), orig);
    pkt_trace_reset_and_arm(hw, config, regmap, fpga_id, Some(PKT_TRACE_MASK_ALL));

    let onehot = errbits & 1 != 0;
    let pass = froze && onehot && stayed_armed && wrapped && marked > 0 && clean > 0;
    if pass {
        info!(
            "mid-stream error captured on a WRAPPED ring: {clean} clean + {marked} error-marked \
             entries of {valid}"
        );
    } else {
        println!(
            "[FAIL] mid-stream error test: froze={froze} one_hot_error={onehot} \
             masked_stayed_armed={stayed_armed} wrapped={wrapped} clean={clean} \
             error_marked={marked} of {valid} (drew {post_per_peer} post-fault/peer)"
        );
        if !stayed_armed {
            println!("       froze while the error was masked -> the trigger mask is not gating");
        }
        if froze && !wrapped {
            println!(
                "       ring did not wrap ({valid} of {PKT_TRACE_DEPTH} entries): headers were \
                 dropped, so the rotate-by-wptr readback was not exercised"
            );
        }
        if froze && marked == 0 {
            println!(
                "       no entry captured with the error live -> trace_aux error path suspect"
            );
        }
    }
    pass
}

/// Trigger mask + software inject self-test (single board, no traffic).
pub fn pkt_trace_inject_selftest(hw: &mut ffi::HpuHw, regmap: &FlatRegmap, timeout_s: u64) -> bool {
    info!("pkt-trace software-inject self-test (single board, no traffic needed)");

    pkt_trace_set_mask(hw, regmap, PKT_TRACE_MASK_NONE);
    if !pkt_trace_arm(hw, regmap) {
        println!("[FAIL] inject self-test: could not arm with every real error masked off");
        return false;
    }

    // masked and not yet injected: nothing may freeze the ring
    std::thread::sleep(std::time::Duration::from_millis(100));
    let stayed_armed = !trace_frozen(hw, regmap);

    pkt_trace_inject(hw, regmap);
    let froze = pkt_trace_poll_frozen(hw, regmap, timeout_s);

    // single clear-on-read; errors[31] must report the inject
    let errbits = hw.reg_read(regmap, "mhdma_system::errors");
    let reported = errbits & PKT_TRACE_INJECT_BIT != 0;
    println!("  errors register = 0x{errbits:08x}");
    pkt_trace_print_errors(errbits, "    ");

    // inject_err is still parked at 1 with no fresh edge, so the re-arm must stick
    let rearmed = pkt_trace_arm(hw, regmap);
    std::thread::sleep(std::time::Duration::from_millis(100));
    let no_reinject = !trace_frozen(hw, regmap);

    // leave the board at the reset defaults: trigger on any error, inject cleared, ring armed
    pkt_trace_set_mask(hw, regmap, PKT_TRACE_MASK_ALL);
    pkt_trace_arm(hw, regmap);

    let pass = stayed_armed && froze && reported && rearmed && no_reinject;
    if pass {
        info!(
            "inject self-test complete (masked idle, injected freeze, errors[31], no re-inject)."
        );
    } else {
        println!(
            "[FAIL] pkt-trace inject self-test: masked_stayed_armed={stayed_armed} froze={froze} \
             errors31={reported} rearmed={rearmed} no_reinject={no_reinject}"
        );
        if !stayed_armed {
            println!("       froze before any inject -> the trigger mask is not gating");
        }
        if froze && !reported {
            println!("       froze but errors[31] clear -> inject_err_q / errors MSB path suspect");
        }
        if !no_reinject {
            println!("       re-froze with inject_err held at 1 -> edge detect is not working");
        }
    }
    pass
}

// ================================================================================================
// Umbrella suite
// ================================================================================================

/// Full suite over the config nodes: setup, packet-trace ring, notify (ring/ping/flood),
/// read-request. Clears state between phases, prints a PASS/FAIL summary, returns overall pass.
pub fn selftest_all(
    hw: &mut ffi::HpuHw,
    config: &HpuConfig,
    regmap: &FlatRegmap,
    fpga_id: u8,
    count: u32,
    timeout_s: u64,
) -> bool {
    println!("==================== MHDMA self-test suite ====================");
    info!(
        "nodes {:?}, board-under-test {fpga_id}",
        config.fpga.node_id
    );

    // clean slate first, so the post-setup check reflects THIS setup rather than stale sticky
    // errors
    reset_boards(hw, config, regmap, fpga_id);
    mhdma_setup(hw, config, regmap, fpga_id);

    // setup must leave the ring fault-free; a fault here means the config is broken, so abort the
    // whole suite rather than run every test against a mis-configured ring.
    if !errors_report(hw, config, regmap, fpga_id) {
        println!("[FAILURE] MHDMA self-test suite: errors present right after setup; aborting");
        return false;
    }
    let mut all = true;

    let mut results: Vec<(&str, bool)> = Vec::new();
    // trigger mask + software inject (single board, no traffic)
    results.push((
        "pkt-trace-inject",
        pkt_trace_inject_selftest(hw, regmap, timeout_s),
    ));
    for (name, pattern) in [
        ("notify-ring", NotifyPattern::Ring),
        ("notify-ping", NotifyPattern::Ping),
        ("notify-flood", NotifyPattern::Flood),
    ] {
        results.push((
            name,
            notify_test(hw, config, regmap, fpga_id, pattern, count),
        ));
    }
    results.push((
        "read-request-ring",
        readreq_test(
            hw,
            config,
            regmap,
            fpga_id,
            ReadPattern::Ring,
            count,
            timeout_s,
        ),
    ));
    results.push((
        "read-request-fanin",
        readreq_test(
            hw,
            config,
            regmap,
            fpga_id,
            ReadPattern::FanIn,
            count,
            timeout_s,
        ),
    ));
    // short randomized soak; run `readreq-stress -r <n>` directly for a heavier one
    results.push((
        "read-request-stress",
        readreq_stress(hw, config, regmap, fpga_id, count, 20, timeout_s),
    ));

    results.push((
        "pkt-trace",
        pkt_trace_selftest(hw, config, regmap, fpga_id, count, timeout_s, false),
    ));
    results.push((
        "pkt-trace-error-midstream",
        pkt_trace_error_midstream_selftest(hw, config, regmap, fpga_id, None, timeout_s),
    ));
    results.push((
        "pkt-trace-random-err",
        pkt_trace_selftest(hw, config, regmap, fpga_id, count, timeout_s, true),
    ));

    println!("==================== summary ====================");
    for (name, ok) in &results {
        println!("  [{}] {name}", if *ok { "PASS" } else { "FAIL" });
        all &= *ok;
    }
    println!(
        "[{}] MHDMA self-test suite",
        if all { "SUCCESS" } else { "FAILURE" }
    );
    all
}
