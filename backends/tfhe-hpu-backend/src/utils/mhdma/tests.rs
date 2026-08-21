//! Multi-board traffic tests: notify patterns, read-request data coherency, randomized stress.

use hw_regmap::FlatRegmap;
use tfhe_hpu_backend::ffi;
use tfhe_hpu_backend::prelude::*;
use tracing::info;

use super::regs::{mhdma_notify, req_inject, RegByName, REQ_ID_READ};
use super::{
    fifo_guard, on_each_node, report_errors, reset_boards, CT_MEM_BYTES, HW_MAX_ADDR, PCS,
    REQ_FIFO_DEPTH, RX_FIFO_DEPTH,
};

// =================================================================================================
// Helper functions
// =================================================================================================

/// Ring position of `node` within the config node list.
fn ring_pos(nodes: &[u8], node: u8) -> usize {
    nodes.iter().position(|&x| x == node).unwrap()
}

// Each loop `l` over N boards uses two logical CT ranges that do not overlap.
// The src range is [2Nl, 2Nl+N). The dst range is [2Nl+N, 2Nl+2N).
// For usual counts, all indices stay below HW_MAX_ADDR.

fn rq_src(pos: usize, l: u32, n: usize) -> u64 {
    (2 * n as u32 * l + pos as u32) as u64
}

fn rq_dst(pos: usize, l: u32, n: usize) -> u64 {
    (2 * n as u32 * l + n as u32 + pos as u32) as u64
}

/// Distinct pseudo-random bytes per (run, board, ct, pc). The per-run salt makes stale data from a
/// previous run fail the compare; the per-byte mixing makes any mis-routed read mismatch.
fn make_pattern(run_id: u32, node: u8, l: u32, pc: u8, size: usize) -> Vec<u8> {
    let key = run_id
        ^ (node as u32).wrapping_mul(0x9E37_79B1)
        ^ l.wrapping_mul(0x85EB_CA77)
        ^ ((pc as u32) << 24);
    (0..size)
        .map(|i| {
            let mut x = key.wrapping_add((i as u32).wrapping_mul(0x27D4_EB2F));
            x ^= x >> 15;
            x = x.wrapping_mul(0x2C1B_3C6D);
            (x >> 24) as u8
        })
        .collect()
}

// ------------------------------------------------------------------------------------------------
// Notifies (checks only number of notifies across boards)
// ------------------------------------------------------------------------------------------------
/// Notify-test traffic pattern.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum NotifyPattern {
    /// node i -> node (i+1): each board receives from its predecessor
    Ring,
    /// each board -> every other board
    Ping,
    /// every board -> one target board
    Flood,
}

/// Drive notify traffic across the config ring and check the received/acked counters per pattern:
///   ring  : node i -> (i+1)    -> each node notify_received == nack_received == count
///   ping  : each -> all others -> each node == count*(N-1)
///   flood : all  -> one target -> target notify_received == Σ senders' nack == count*(N-1)
pub fn notify_test(
    hw: &mut ffi::HpuHw,
    config: &HpuConfig,
    regmap: &FlatRegmap,
    fpga_id: u8,
    pattern: NotifyPattern,
    count: u32,
) -> bool {
    let nodes = config.fpga.node_id.clone();
    let n = nodes.len();
    let target = nodes[0]; // flood target
    let peers = n as u32 - 1;

    if n < 2 {
        println!("[FAIL] notify {pattern:?} needs >= 2 boards (node_id = {nodes:?})");
        return false;
    }

    // FIFO capacity: reject a burst that would overflow a command / decoder FIFO (see depths).
    let (per_sent, per_recv) = match pattern {
        NotifyPattern::Ring => (1, 1),
        NotifyPattern::Ping => (peers, peers),
        NotifyPattern::Flood => (1, peers), // one target receives from all peers
    };
    let what = format!("notify {pattern:?}");
    if !fifo_guard(&format!("{what} cmdq"), per_sent, count, REQ_FIFO_DEPTH)
        || !fifo_guard(&format!("{what} rx-fifo"), per_recv, count, RX_FIFO_DEPTH)
    {
        return false;
    }
    info!("notify {pattern:?} over nodes {nodes:?} ({count} notify/hop)");

    reset_boards(hw, config, regmap, fpga_id);

    // drive
    on_each_node(hw, config, fpga_id, |h, node| {
        let p = ring_pos(&nodes, node);
        // mode mirrors the bring-up scripts: ring/flood use mode 1, ping uses mode 2.
        match pattern {
            NotifyPattern::Ring => {
                let dst = nodes[(p + 1) % n];
                for k in 0..count {
                    mhdma_notify(h, regmap, dst, k as u16, k as u16, 1);
                }
            }
            NotifyPattern::Ping => {
                for &dst in &nodes {
                    if dst == node {
                        continue;
                    }
                    for k in 0..count {
                        mhdma_notify(h, regmap, dst, k as u16, k as u16, 2);
                    }
                }
            }
            NotifyPattern::Flood => {
                if node != target {
                    for k in 0..count {
                        mhdma_notify(h, regmap, target, k as u16, k as u16, 1);
                    }
                }
            }
        }
    });

    // Notifies traverse the network + ACK round-trip;
    // wait proportionally to the traffic volume before the single read-to-clear sample (arbitrary).
    let settle_ms = 300 + 20 * count as u64 * n as u64;
    std::thread::sleep(std::time::Duration::from_millis(settle_ms));

    // one post-traffic sweep: notify/nack counters + errors together
    let mut stats = on_each_node(hw, config, fpga_id, |h, _| {
        (
            h.reg_read(regmap, "mhdma_request::stat_nb_notify_received"),
            h.reg_read(regmap, "mhdma_request::stat_nb_nack_received"),
            h.reg_read(regmap, "mhdma_system::errors"),
        )
    });
    stats.sort_by_key(|(node, _)| *node);

    let expected = match pattern {
        NotifyPattern::Ring => count,
        NotifyPattern::Ping | NotifyPattern::Flood => count * (n as u32 - 1),
    };

    println!("  node | notify_recv  nack_recv");
    for (node, (notify, nack, _)) in &stats {
        println!("  {node:4} | {notify:11}  {nack:9}");
    }

    let mut pass = true;

    match pattern {
        NotifyPattern::Ring | NotifyPattern::Ping => {
            for (node, (notify, nack, _)) in &stats {
                if notify != nack || *notify != expected {
                    println!(
                        "[FAIL] board {node}: notify_recv={notify} nack_recv={nack} (expected {expected} each)"
                    );
                    pass = false;
                }
            }
        }
        NotifyPattern::Flood => {
            let tgt_notify = stats
                .iter()
                .find(|(nd, _)| *nd == target)
                .map(|(_, (nfy, _, _))| *nfy)
                .unwrap();
            let sum_nack: u32 = stats
                .iter()
                .filter(|(nd, _)| *nd != target)
                .map(|(_, (_, nk, _))| *nk)
                .sum();
            println!(
                "  target {target}: notify_recv={tgt_notify}, Σ senders nack_recv={sum_nack} (expected {expected})"
            );
            if tgt_notify != sum_nack || tgt_notify != expected {
                println!(
                    "[FAIL] board {target}: notify_recv={tgt_notify} Σ senders nack_recv={sum_nack} \
                     (expected {expected} each)"
                );
                pass = false;
            }
            // each sender must have acked `count` on its own, so a bad sender can't hide in the sum
            for (node, (_, nack, _)) in &stats {
                if *node != target && *nack != count {
                    println!("[FAIL] sender {node}: nack_recv={nack} (expected {count})");
                    pass = false;
                }
            }
        }
    }

    let errs: Vec<(u8, u32)> = stats.iter().map(|(nd, (_, _, e))| (*nd, *e)).collect();
    pass &= report_errors(&errs);
    println!(
        "[{}] notify {pattern:?} test",
        if pass { "PASS" } else { "FAIL" }
    );
    pass
}

// -------------------------------------------------------------------------------------------------
// Read-request ring test (checking requests working & coherency)
// -------------------------------------------------------------------------------------------------
/// Read-request-test traffic pattern.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum ReadPattern {
    /// each board reads its ring successor's source into its own destination
    Ring,
    /// every board reads from one shared source (node_id[0])
    #[value(alias = "fanin")]
    FanIn,
}

/// Per-board outcome of a read-request test.
struct BoardRr {
    completed: bool,            // all reads completed within the timeout
    mismatches: Vec<(u32, u8)>, // (ct index, pc) whose data != the software golden
}

/// One read a board performs:
/// pull `src_slot` from `src_node` into our own `dst_slot`.
/// `l` selects the per-loop byte set of the golden pattern.
struct Read {
    l: u32,
    src_node: u8,
    src_slot: u64,
    dst_slot: u64,
}

fn write_ct(hw: &mut ffi::HpuHw, pc_base: u64, logical: u64, data: &[u8]) {
    hw.write_abs(pc_base + logical * CT_MEM_BYTES, data);
}

fn read_ct(hw: &mut ffi::HpuHw, pc_base: u64, logical: u64, size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    hw.read_abs(pc_base + logical * CT_MEM_BYTES, &mut buf);
    buf
}

/// Poll mhdma_request::read_request until a completion appears (bounded)
fn poll_read_complete(hw: &mut ffi::HpuHw, regmap: &FlatRegmap, timeout_s: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_s);

    loop {
        if hw.reg_read(regmap, "mhdma_request::read_request") != 0 {
            let _ = hw.reg_read(regmap, "mhdma_request::read_request_req_id"); // pop
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Write the per-run pattern (both PCs) into every seeded slot.
fn seed_slots(hw: &mut ffi::HpuHw, node: u8, slots: &[(u32, u64)], seed_val: u32) {
    for &(l, slot) in slots {
        for (pc, (base, size)) in PCS.iter().enumerate() {
            write_ct(
                hw,
                *base,
                slot,
                &make_pattern(seed_val, node, l, pc as u8, *size),
            );
        }
    }
}

/// Issue + await every read (serialized: poll after each). Returns whether all completed in time.
fn issue_reads(hw: &mut ffi::HpuHw, regmap: &FlatRegmap, reads: &[Read], timeout_s: u64) -> bool {
    for r in reads {
        req_inject(
            hw,
            regmap,
            REQ_ID_READ,
            r.src_node,
            r.src_slot as u16,
            r.dst_slot as u16,
            1,
        );
        if !poll_read_complete(hw, regmap, timeout_s) {
            return false;
        }
    }
    true
}

/// Slots a board seeds (the ciphertexts that will be read from), as (loop index, logical slot),
/// shifted by `base` (0 for readreq_test; the per-round offset for the stress test).
fn write_plan(
    pattern: ReadPattern,
    node: u8,
    nodes: &[u8],
    count: u32,
    source: u8,
    base: u64,
) -> Vec<(u32, u64)> {
    let n = nodes.len();
    let p = ring_pos(nodes, node);

    match pattern {
        ReadPattern::Ring => (0..count).map(|l| (l, base + rq_src(p, l, n))).collect(),
        ReadPattern::FanIn if node == source => {
            // one distinct block per requester so each reader's golden is unique (catches
            // cross-wire)
            let total = (n as u32 - 1) * count;
            (0..total).map(|s| (s, base + s as u64)).collect()
        }
        ReadPattern::FanIn => Vec::new(),
    }
}

/// The reads a board performs this run, shifted by `base` (see write_plan).
fn read_plan(
    pattern: ReadPattern,
    node: u8,
    nodes: &[u8],
    count: u32,
    source: u8,
    base: u64,
) -> Vec<Read> {
    let n = nodes.len();
    let p = ring_pos(nodes, node);
    match pattern {
        ReadPattern::Ring => {
            let sp = (p + 1) % n;
            (0..count)
                .map(|l| Read {
                    l,
                    src_node: nodes[sp],
                    src_slot: base + rq_src(sp, l, n),
                    dst_slot: base + rq_dst(p, l, n),
                })
                .collect()
        }
        ReadPattern::FanIn if node == source => Vec::new(),
        ReadPattern::FanIn => (0..count)
            .map(|l| {
                let s = (p as u32 - 1) * count + l; // this requester's own source block; s is the golden key
                Read {
                    l: s,
                    src_node: source,
                    src_slot: base + s as u64,
                    dst_slot: base + count as u64 * p as u64 + l as u64,
                }
            })
            .collect(),
    }
}

/// Compare each read's dst against the software golden (the source's seed).
/// Returns (loop, pc) misses.
fn verify_reads(hw: &mut ffi::HpuHw, reads: &[Read], seed_val: u32) -> Vec<(u32, u8)> {
    let mut mismatches = Vec::new();
    for r in reads {
        for (pc, (base, size)) in PCS.iter().enumerate() {
            if read_ct(hw, *base, r.dst_slot, *size)
                != make_pattern(seed_val, r.src_node, r.l, pc as u8, *size)
            {
                mismatches.push((r.l, pc as u8));
            }
        }
    }
    mismatches
}

/// Read-request + data-coherency test.
pub fn readreq_test(
    hw: &mut ffi::HpuHw,
    config: &HpuConfig,
    regmap: &FlatRegmap,
    fpga_id: u8,
    pattern: ReadPattern,
    count: u32,
    timeout_s: u64,
) -> bool {
    let nodes = config.fpga.node_id.clone();
    let n = nodes.len();
    let peers = n as u32 - 1;
    let source = nodes[0]; // fan-in source

    if n < 2 {
        println!("[FAIL] read-request {pattern:?} needs >= 2 boards (node_id = {nodes:?})");
        return false;
    }

    // the fan-in source also receives count*(N-1) read-requests into its own queue
    let what = format!("read-request {pattern:?}");
    if !fifo_guard(&format!("{what} command-FIFO"), 1, count, REQ_FIFO_DEPTH)
        || (matches!(pattern, ReadPattern::FanIn)
            && !fifo_guard(&format!("{what} source cmdq"), peers, count, REQ_FIFO_DEPTH))
    {
        return false;
    }

    let span = match pattern {
        ReadPattern::Ring => 2 * n as u64 * count as u64,
        ReadPattern::FanIn => n as u64 * count as u64,
    };
    if span >= HW_MAX_ADDR {
        println!("[FAIL] count={count} needs {span} logical slots >= HW limit 0x{HW_MAX_ADDR:x}; lower -c");
        return false;
    }

    let run_id = rand::random::<u32>(); // per-run data salt
    let base = rand::random_range(0..HW_MAX_ADDR - span); // random address offset
    info!("read-request {pattern:?} over nodes {nodes:?} ({count} CT(s)/board, base=0x{base:x})");
    reset_boards(hw, config, regmap, fpga_id);

    // 1. seed the source slots that will be read (ring: every board; fanin: source only)
    on_each_node(hw, config, fpga_id, |h, node| {
        seed_slots(
            h,
            node,
            &write_plan(pattern, node, &nodes, count, source, base),
            run_id,
        );
    });

    // 2. issue every read, then verify each dst against the source's golden
    let results = on_each_node(hw, config, fpga_id, |h, node| {
        let reads = read_plan(pattern, node, &nodes, count, source, base);
        let completed = issue_reads(h, regmap, &reads, timeout_s);
        let mismatches = if completed {
            verify_reads(h, &reads, run_id)
        } else {
            Vec::new()
        };
        BoardRr {
            completed,
            mismatches,
        }
    });

    // 3. one post-traffic sweep: read_req_received + errors together
    let stats = on_each_node(hw, config, fpga_id, |h, _| {
        (
            h.reg_read(regmap, "mhdma_request::stat_nb_read_req_received"),
            h.reg_read(regmap, "mhdma_system::errors"),
        )
    });

    // 4. report
    let mut pass = true;
    for (node, rr) in &results {
        let is_source_sink = matches!(pattern, ReadPattern::FanIn) && *node == source;
        if !rr.completed {
            println!("[FAIL] board {node}: read-request timed out");
            pass = false;
        } else if !rr.mismatches.is_empty() {
            for (l, pc) in &rr.mismatches {
                println!("[FAIL] board {node}: ct{l} pc{pc} data != expected");
            }
            pass = false;
        } else if !is_source_sink {
            println!("[PASS] board {node}: {count} CT(s) match");
        }
    }
    for (node, (rreq, _)) in &stats {
        let exp = match pattern {
            ReadPattern::Ring => count,
            ReadPattern::FanIn if *node == source => count * peers,
            ReadPattern::FanIn => 0,
        };
        if *rreq != exp {
            println!("[FAIL] board {node}: read_req_received={rreq} (expected {exp})");
            pass = false;
        }
    }
    let errs: Vec<(u8, u32)> = stats.iter().map(|(nd, (_, e))| (*nd, *e)).collect();
    pass &= report_errors(&errs);
    println!(
        "[{}] read-request {pattern:?} test",
        if pass { "PASS" } else { "FAIL" }
    );
    pass
}

/// Intense read-request stress:
/// `rounds` of concurrent ring reads at randomized base slots, each with fresh data, to shake the module under
/// sustained load + address variety.
/// Verifies the payload every round and asserts no errors or read-request retries accumulate.
/// Stops at the first bad round.
pub fn readreq_stress(
    hw: &mut ffi::HpuHw,
    config: &HpuConfig,
    regmap: &FlatRegmap,
    fpga_id: u8,
    count: u32,
    rounds: u32,
    timeout_s: u64,
) -> bool {
    let nodes = config.fpga.node_id.clone();
    let n = nodes.len();
    let source = nodes[0];
    let span = 2 * n as u32 * count; // logical slots one round occupies

    if n < 2 {
        println!("[FAIL] read-request stress needs >= 2 boards (node_id = {nodes:?})");
        return false;
    }
    if !fifo_guard("read-request stress command-FIFO", 1, count, REQ_FIFO_DEPTH) {
        return false;
    }
    if span as u64 >= HW_MAX_ADDR {
        println!("[FAIL] read-request stress: -c {count} needs {span} slots >= HW limit 0x{HW_MAX_ADDR:x}; lower -c");
        return false;
    }

    info!("read-request stress: {rounds} round(s) x {count} CT(s)/board over nodes {nodes:?}");
    reset_boards(hw, config, regmap, fpga_id);
    // flush read-to-clear retry counters so the end-of-run read is this run's delta
    on_each_node(hw, config, fpga_id, |h, _| {
        let _ = h.reg_read(regmap, "mhdma_request::stat_read_req_timeout_retry");
        let _ = h.reg_read(regmap, "mhdma_request::stat_read_req_seq_num_retry");
    });

    let mut pass = true;
    let mut total_ct: u64 = 0;

    for round in 0..rounds {
        let salt = rand::random::<u32>();
        let base = rand::random_range(0..HW_MAX_ADDR - span as u64);

        on_each_node(hw, config, fpga_id, |h, node| {
            seed_slots(
                h,
                node,
                &write_plan(ReadPattern::Ring, node, &nodes, count, source, base),
                salt,
            );
        });
        let results = on_each_node(hw, config, fpga_id, |h, node| {
            let reads = read_plan(ReadPattern::Ring, node, &nodes, count, source, base);
            let completed = issue_reads(h, regmap, &reads, timeout_s);
            let mismatches = if completed {
                verify_reads(h, &reads, salt)
            } else {
                Vec::new()
            };
            BoardRr {
                completed,
                mismatches,
            }
        });

        let mut round_ok = true;
        for (node, rr) in &results {
            if !rr.completed {
                println!("[FAIL] round {round} board {node}: read-request timed out");
                round_ok = false;
            } else if !rr.mismatches.is_empty() {
                println!(
                    "[FAIL] round {round} board {node}: {} CT mismatch(es) (base=0x{base:x})",
                    rr.mismatches.len()
                );
                round_ok = false;
            }
        }
        if round_ok {
            total_ct += results.len() as u64 * count as u64;
        } else {
            pass = false;
            break;
        }
        if (round + 1) % 10 == 0 || round + 1 == rounds {
            info!(
                "  round {}/{rounds} ok ({total_ct} CT(s) so far)",
                round + 1
            );
        }
    }

    // one post-traffic sweep: retry counters + errors together
    let stats = on_each_node(hw, config, fpga_id, |h, _| {
        (
            h.reg_read(regmap, "mhdma_request::stat_read_req_timeout_retry"),
            h.reg_read(regmap, "mhdma_request::stat_read_req_seq_num_retry"),
            h.reg_read(regmap, "mhdma_system::errors"),
        )
    });
    for (node, (to, sq, _)) in &stats {
        if *to != 0 || *sq != 0 {
            println!(
                "[FAIL] board {node}: read-req retries timeout={to} seq_num={sq} (expected 0)"
            );
            pass = false;
        }
    }
    let errs: Vec<(u8, u32)> = stats.iter().map(|(nd, (_, _, e))| (*nd, *e)).collect();
    pass &= report_errors(&errs);
    println!(
        "[{}] read-request stress ({total_ct} CT(s) verified)",
        if pass { "PASS" } else { "FAIL" }
    );
    pass
}
