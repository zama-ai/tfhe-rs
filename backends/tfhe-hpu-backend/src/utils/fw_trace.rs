//! Ucore firmware DDR debug trace (multi-HPU IOp control / MHDMA events).
//!
//! The firmware (`print_ddr_debug`/`print_ddr_event` in `fw/arm/src/apps/in_band/ucore.c`) pushes
//! records in a circular buffer of `DEBUG_SIZE` (0x20000) u32 located just after a pointer word:
//!  - `@0x3FF00000` (`DEBUG_PTR`)  total number of words written since boot (un-wrapped)
//!  - `@0x3FF00004` (`DEBUG_ADDR`) circular buffer
//!
//! Each record starts with a header word `tag[31:20] | sub[19:16] | fields[15:0]` followed by a
//! fixed number of payload words. Keep in sync with the `DDR_TRC_*` table in `ucore.h`:
//!
//! | tag   | sub                          | fields[15:0]                | payload                       |
//! |-------|------------------------------|-----------------------------|-------------------------------|
//! | 0xBEE | site \| seen<<3              | iid<<8 \| nb_hpu<<4 \| state | -                            |
//! | 0xB2B | 0: free request              | tail_iid<<8 \| iid          | -                             |
//! | 0xB2B | 1: free done                 | iid                         | pool_free<<16 \| freed        |
//! | 0xD57 | site                         | iid                         | owned<<16 \| waiting<<8 \| resolved |
//! | 0xACC | 0                            | -                           | raw DOp ack                   |
//! | 0xC0D | 1: notify / 2: read complete | iop_state / src_store state | req_id, req_addr (mhdma_cmd_t) |
//!
//! Most of those events are only recorded when the debug interrupt count is odd.

use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::File;
use tfhe_hpu_backend::ffi;

const TAG_IOP_STATE: u32 = 0xBEE;
const TAG_B2B: u32 = 0xB2B;
const TAG_DST_CNT: u32 = 0xD57;
const TAG_ACK: u32 = 0xACC;
const TAG_MHDMA: u32 = 0xC0D;

const B2B_FREE_REQ: u32 = 0;
const B2B_FREE_DONE: u32 = 1;
const MHDMA_NOTIFY: u32 = 1;
const MHDMA_READ_DONE: u32 = 2;

// mhdma_cmd_t mode
const CMD_SRC: u32 = 1;
const CMD_DST: u32 = 2;

/// Longest record in words (header included), bounds the resync search after a wrap
const MAX_RECORD_WORDS: usize = 3;

const SYNC_OPCODE: u32 = 0b10_1111;

/// Extract a `width`-bit field starting at bit `lsb`.
fn bits(value: u32, lsb: u32, width: u32) -> u32 {
    (value >> lsb) & ((1u32 << width) - 1)
}

fn iop_state_str(state: u8) -> String {
    match state {
        0x0 => "done".to_string(),
        0xF => "unknown".to_string(),
        n => format!("running ({n} hpu left)"),
    }
}

fn operand_state_str(state: u8) -> &'static str {
    match state {
        5 => "none",
        6 => "read_pending",
        7 => "dma_pending",
        8 => "resolved",
        _ => "invalid",
    }
}

/// Decoded `mhdma_cmd_t` (c.f. `mhdma_driver.h`)
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MhdmaCmd {
    pub iid: u8,
    pub hid: u8,
    pub mode: &'static str,
    /// User flag (mode=user), number of HPU (end of IOp notify: mode=src) or tid (operand
    /// transfer: mode=dst, or mode=src for a read complete)
    pub flag: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tid: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bid: Option<u8>,
    pub opcode: u8,
    pub src_cid: u16,
    pub dst_cid: u16,
}

impl MhdmaCmd {
    /// `is_read_done` is needed since mode=src means end of IOp in a notify but source operand
    /// in a read complete
    fn from_words(req_id: u32, req_addr: u32, is_read_done: bool) -> Self {
        let pad = bits(req_id, 0, 8) as u8;
        let flag = bits(req_id, 8, 6) as u8;
        let mode = bits(req_id, 14, 2);
        let is_operand = mode == CMD_DST || (is_read_done && mode == CMD_SRC);
        Self {
            iid: bits(req_id, 24, 8) as u8,
            hid: bits(req_id, 16, 4) as u8,
            mode: match mode {
                0 => "user",
                1 => "src",
                2 => "dst",
                _ => "invalid",
            },
            flag,
            tid: is_operand.then_some(flag),
            bid: is_operand.then_some(pad),
            opcode: bits(req_id, 20, 4) as u8,
            src_cid: bits(req_addr, 0, 16) as u16,
            dst_cid: bits(req_addr, 16, 16) as u16,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "event")]
pub enum FwTraceEvent {
    /// Leading words of a record partially overwritten by the circular buffer
    Truncated,
    /// IOp state update (`iop_state[iid]`)
    IopState {
        site: &'static str,
        iid: u8,
        nb_hpu: u8,
        state: u8,
        state_str: String,
        locally_seen: bool,
    },
    /// `b2b_pool_free` entry: slots are only freed if the pool tail belongs to `iid`
    B2bFreeReq {
        iid: u8,
        tail_iid: u8,
        will_free: bool,
    },
    /// `b2b_pool_free` result
    B2bFreeDone { iid: u8, pool_free: u16, freed: u16 },
    /// Destination operands owned by the local HPU for `iid`
    DstCount {
        site: &'static str,
        iid: u8,
        owned: u8,
        waiting: u8,
        resolved: u8,
    },
    /// IOp ack received from the ISC carrying a SYNC DOp
    AckSync {
        iid: u8,
        hid: u8,
        flag: u8,
        is_inner: bool,
    },
    /// IOp ack received from the ISC carrying another DOp
    Ack { opcode: u8 },
    /// MHDMA notify received from a remote HPU
    MhdmaNotify {
        iop_state: u8,
        iop_state_str: String,
        #[serde(flatten)]
        cmd: MhdmaCmd,
    },
    /// MHDMA read complete
    MhdmaReadDone {
        /// Firmware reads `src_store.state[iid][tid][bid]`, only meaningful for mode=src
        #[serde(skip_serializing_if = "Option::is_none")]
        src_state: Option<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        src_state_str: Option<&'static str>,
        #[serde(flatten)]
        cmd: MhdmaCmd,
    },
    /// Word that doesn't match any known record header
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FwTraceEntry {
    /// Absolute index of the first word since firmware boot
    pub idx: u64,
    #[serde(flatten)]
    pub event: FwTraceEvent,
    pub raw: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FwTrace {
    pub fpga_id: u8,
    /// Total number of words written by the firmware since boot
    pub total_words: u64,
    pub wrapped: bool,
    /// Words overwritten by the circular buffer
    pub lost_words: u64,
    pub events: Vec<FwTraceEntry>,
}

/// Number of words of the record starting with `hdr`, None if not a known header
fn record_len(hdr: u32) -> Option<usize> {
    let sub = bits(hdr, 16, 4);
    match bits(hdr, 20, 12) {
        TAG_IOP_STATE if (1..=3).contains(&(sub & 0x7)) => Some(1),
        TAG_B2B if sub == B2B_FREE_REQ => Some(1),
        TAG_B2B if sub == B2B_FREE_DONE => Some(2),
        TAG_DST_CNT if (1..=3).contains(&sub) => Some(2),
        TAG_ACK if sub == 0 => Some(2),
        TAG_MHDMA if sub == MHDMA_NOTIFY || sub == MHDMA_READ_DONE => Some(3),
        _ => None,
    }
}

/// Decode a full record (length given by `record_len`)
fn decode_record(w: &[u32]) -> FwTraceEvent {
    let hdr = w[0];
    let sub = bits(hdr, 16, 4);
    let iid = bits(hdr, 0, 8) as u8;
    match bits(hdr, 20, 12) {
        TAG_IOP_STATE => {
            let state = bits(hdr, 0, 4) as u8;
            FwTraceEvent::IopState {
                site: match sub & 0x7 {
                    1 => "parse_iop",
                    2 => "iop_close",
                    _ => "remote_end_of_iop",
                },
                iid: bits(hdr, 8, 8) as u8,
                nb_hpu: bits(hdr, 4, 4) as u8,
                state,
                state_str: iop_state_str(state),
                locally_seen: bits(sub, 3, 1) == 1,
            }
        }
        TAG_B2B if sub == B2B_FREE_REQ => {
            let tail_iid = bits(hdr, 8, 8) as u8;
            FwTraceEvent::B2bFreeReq {
                iid,
                tail_iid,
                will_free: tail_iid == iid,
            }
        }
        TAG_B2B => FwTraceEvent::B2bFreeDone {
            iid,
            pool_free: bits(w[1], 16, 16) as u16,
            freed: bits(w[1], 0, 16) as u16,
        },
        TAG_DST_CNT => FwTraceEvent::DstCount {
            site: match sub {
                1 => "parse_iop",
                2 => "iop_teardown",
                _ => "iop_teardown_wait",
            },
            iid,
            owned: bits(w[1], 16, 8) as u8,
            waiting: bits(w[1], 8, 8) as u8,
            resolved: bits(w[1], 0, 8) as u8,
        },
        TAG_ACK => {
            let opcode = bits(w[1], 26, 6);
            if opcode == SYNC_OPCODE {
                FwTraceEvent::AckSync {
                    iid: bits(w[1], 16, 8) as u8,
                    hid: bits(w[1], 8, 3) as u8,
                    flag: bits(w[1], 0, 6) as u8,
                    is_inner: bits(w[1], 24, 1) == 1,
                }
            } else {
                FwTraceEvent::Ack {
                    opcode: opcode as u8,
                }
            }
        }
        TAG_MHDMA => {
            let is_read_done = sub == MHDMA_READ_DONE;
            let cmd = MhdmaCmd::from_words(w[1], w[2], is_read_done);
            let state = bits(hdr, 0, 8) as u8;
            if !is_read_done {
                FwTraceEvent::MhdmaNotify {
                    iop_state: state,
                    iop_state_str: iop_state_str(state),
                    cmd,
                }
            } else {
                let is_src = bits(w[1], 14, 2) == CMD_SRC;
                FwTraceEvent::MhdmaReadDone {
                    src_state: is_src.then_some(state),
                    src_state_str: is_src.then(|| operand_state_str(state)),
                    cmd,
                }
            }
        }
        _ => FwTraceEvent::Unknown,
    }
}

/// Check that `words` is a sequence of complete known records
fn parses_cleanly(words: &[u32]) -> bool {
    let mut pos = 0;
    while pos < words.len() {
        match record_len(words[pos]) {
            Some(len) if pos + len <= words.len() => pos += len,
            _ => return false,
        }
    }
    true
}

fn entry(idx: u64, words: &[u32], event: FwTraceEvent) -> FwTraceEntry {
    FwTraceEntry {
        idx,
        event,
        raw: words.iter().map(|w| format!("0x{w:08x}")).collect(),
    }
}

/// Re-order the circular buffer from oldest to newest and decode it.
/// `ptr` is the pointer word and `ring` the circular buffer content.
pub fn decode(fpga_id: u8, ptr: u32, ring: &[u32]) -> FwTrace {
    let depth = ring.len() as u64;
    let total_words = ptr as u64;
    let wrapped = total_words > depth;
    let words: Vec<u32> = if wrapped {
        let pos = (total_words % depth) as usize;
        ring[pos..]
            .iter()
            .chain(ring[..pos].iter())
            .copied()
            .collect()
    } else {
        ring[..total_words as usize].to_vec()
    };
    let first_idx = total_words - words.len() as u64;

    // After a wrap the oldest record could be cut: skip leading words until the stream parses
    let skip = if wrapped {
        (0..MAX_RECORD_WORDS.min(words.len()))
            .find(|s| parses_cleanly(&words[*s..]))
            .unwrap_or(0)
    } else {
        0
    };

    let mut events = Vec::new();
    if skip != 0 {
        events.push(entry(first_idx, &words[..skip], FwTraceEvent::Truncated));
    }
    let mut pos = skip;
    while pos < words.len() {
        let idx = first_idx + pos as u64;
        match record_len(words[pos]) {
            Some(len) if pos + len <= words.len() => {
                let rec = &words[pos..pos + len];
                events.push(entry(idx, rec, decode_record(rec)));
                pos += len;
            }
            _ => {
                events.push(entry(idx, &words[pos..=pos], FwTraceEvent::Unknown));
                pos += 1;
            }
        }
    }

    FwTrace {
        fpga_id,
        total_words,
        wrapped,
        lost_words: first_idx,
        events,
    }
}

fn event_name(event: &FwTraceEvent) -> &'static str {
    match event {
        FwTraceEvent::Truncated => "Truncated",
        FwTraceEvent::IopState { .. } => "IopState",
        FwTraceEvent::B2bFreeReq { .. } => "B2bFreeReq",
        FwTraceEvent::B2bFreeDone { .. } => "B2bFreeDone",
        FwTraceEvent::DstCount { .. } => "DstCount",
        FwTraceEvent::AckSync { .. } => "AckSync",
        FwTraceEvent::Ack { .. } => "Ack",
        FwTraceEvent::MhdmaNotify { .. } => "MhdmaNotify",
        FwTraceEvent::MhdmaReadDone { .. } => "MhdmaReadDone",
        FwTraceEvent::Unknown => "Unknown",
    }
}

/// Read the firmware trace from the board, decode it and write it as JSON in `filename`
pub fn fw_trace_dump(hw: &mut ffi::HpuHw, fpga_id: u8, addr: u64, depth: usize, filename: &str) {
    let mut buf = vec![0u32; 1 + depth];
    hw.read_abs(addr, &mut buf);
    let trace = decode(fpga_id, buf[0], &buf[1..]);

    let mut count = BTreeMap::new();
    for e in trace.events.iter() {
        *count.entry(event_name(&e.event)).or_insert(0usize) += 1;
    }
    println!(
        "Fw trace [@{addr:x}]: {} words written, {} ({} lost), {} events {count:?}",
        trace.total_words,
        if trace.wrapped {
            "wrapped"
        } else {
            "not wrapped"
        },
        trace.lost_words,
        trace.events.len(),
    );

    let file = File::create(filename).expect("Failed to create or open fw trace file");
    let buf_wr = std::io::BufWriter::new(file);
    serde_json::to_writer_pretty(buf_wr, &trace).expect("Could not write fw trace");
    println!("Fw trace written in {filename}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(tag: u32, sub: u32, fields: u32) -> u32 {
        (tag << 20) | (sub << 16) | fields
    }

    fn single(words: &[u32]) -> FwTraceEvent {
        let t = decode(0, words.len() as u32, words);
        assert_eq!(t.events.len(), 1, "{:?}", t.events);
        t.events[0].event.clone()
    }

    #[test]
    fn iop_state() {
        // seen=1 site=remote, iid=0x12, nb_hpu=8, state=3
        let ev = single(&[hdr(TAG_IOP_STATE, 3 | 1 << 3, 0x12 << 8 | 8 << 4 | 3)]);
        assert_eq!(
            ev,
            FwTraceEvent::IopState {
                site: "remote_end_of_iop",
                iid: 0x12,
                nb_hpu: 8,
                state: 3,
                state_str: "running (3 hpu left)".to_string(),
                locally_seen: true,
            }
        );
    }

    #[test]
    fn b2b() {
        let t = decode(
            0,
            3,
            &[
                hdr(TAG_B2B, B2B_FREE_REQ, 0x0505),
                hdr(TAG_B2B, B2B_FREE_DONE, 0x05),
                (4000 << 16) | 12,
            ],
        );
        assert_eq!(
            t.events[0].event,
            FwTraceEvent::B2bFreeReq {
                iid: 5,
                tail_iid: 5,
                will_free: true
            }
        );
        assert_eq!(
            t.events[1].event,
            FwTraceEvent::B2bFreeDone {
                iid: 5,
                pool_free: 4000,
                freed: 12
            }
        );
        assert_eq!(t.events[1].idx, 1);
        assert_eq!(t.events[1].raw, vec!["0xb2b10005", "0x0fa0000c"]);
    }

    #[test]
    fn dst_count() {
        let ev = single(&[hdr(TAG_DST_CNT, 2, 0xBE), 0x0003_0201]);
        assert_eq!(
            ev,
            FwTraceEvent::DstCount {
                site: "iop_teardown",
                iid: 0xBE,
                owned: 3,
                waiting: 2,
                resolved: 1
            }
        );
    }

    #[test]
    fn ack() {
        // sync: opcode 0b101111, is_inner, iid 7, hid 2, flag 9
        let raw = SYNC_OPCODE << 26 | 1 << 24 | 7 << 16 | 2 << 8 | 9;
        assert_eq!(
            single(&[hdr(TAG_ACK, 0, 0), raw]),
            FwTraceEvent::AckSync {
                iid: 7,
                hid: 2,
                flag: 9,
                is_inner: true
            }
        );
        assert_eq!(
            single(&[hdr(TAG_ACK, 0, 0), 0x1 << 26]),
            FwTraceEvent::Ack { opcode: 1 }
        );
    }

    #[test]
    fn mhdma() {
        // iid 0x81, opcode 3, hid 4, mode dst, tid 6, bid 0x22 ; src_cid 0x1234, dst_cid 0x5678
        let req_id = 0x81 << 24 | 3 << 20 | 4 << 16 | 2 << 14 | 6 << 8 | 0x22;
        let req_addr = 0x5678 << 16 | 0x1234;
        let ev = single(&[hdr(TAG_MHDMA, MHDMA_READ_DONE, 7), req_id, req_addr]);
        assert_eq!(
            ev,
            FwTraceEvent::MhdmaReadDone {
                src_state: None,
                src_state_str: None,
                cmd: MhdmaCmd {
                    iid: 0x81,
                    hid: 4,
                    mode: "dst",
                    flag: 6,
                    tid: Some(6),
                    bid: Some(0x22),
                    opcode: 3,
                    src_cid: 0x1234,
                    dst_cid: 0x5678,
                },
            }
        );
        let ev = single(&[hdr(TAG_MHDMA, MHDMA_NOTIFY, 0xF), 1 << 14 | 2 << 8, 0]);
        let FwTraceEvent::MhdmaNotify {
            iop_state_str, cmd, ..
        } = ev
        else {
            panic!("Expect MhdmaNotify")
        };
        assert_eq!(iop_state_str, "unknown");
        assert_eq!((cmd.mode, cmd.flag, cmd.tid), ("src", 2, None));

        // Read complete of a source operand: tid 1, bid 0x0F, src_store state reported
        let ev = single(&[
            hdr(TAG_MHDMA, MHDMA_READ_DONE, 7),
            1 << 14 | 1 << 8 | 0x0F,
            0,
        ]);
        let FwTraceEvent::MhdmaReadDone {
            src_state,
            src_state_str,
            cmd,
        } = ev
        else {
            panic!("Expect MhdmaReadDone")
        };
        assert_eq!((src_state, src_state_str), (Some(7), Some("dma_pending")));
        assert_eq!((cmd.mode, cmd.tid, cmd.bid), ("src", Some(1), Some(0x0F)));

        // Read complete of a user ct: no src_store state nor tid/bid
        let ev = single(&[hdr(TAG_MHDMA, MHDMA_READ_DONE, 8), 3 << 8 | 0x11, 0]);
        let json = serde_json::to_value(single_entry(ev)).unwrap();
        for key in ["src_state", "src_state_str", "tid", "bid"] {
            assert!(json.get(key).is_none(), "{key} in {json}");
        }
    }

    fn single_entry(event: FwTraceEvent) -> FwTraceEntry {
        entry(0, &[], event)
    }

    #[test]
    fn unknown_word() {
        let t = decode(0, 2, &[0xDEAD_BEEF, hdr(TAG_B2B, B2B_FREE_REQ, 0)]);
        assert_eq!(t.events[0].event, FwTraceEvent::Unknown);
        assert_eq!(t.events[1].idx, 1);
    }

    #[test]
    fn not_wrapped_ignores_stale_tail() {
        let ring = [hdr(TAG_B2B, B2B_FREE_REQ, 1), 0xDEAD_BEEF, 0xDEAD_BEEF];
        let t = decode(0, 1, &ring);
        assert!(!t.wrapped);
        assert_eq!(t.lost_words, 0);
        assert_eq!(t.events.len(), 1);
    }

    #[test]
    fn wrapped_reorder_and_resync() {
        // Write records sequentially in a ring of 6 words, total 11 words:
        //  rec A (3w, idx 0..3) rec B (1w, idx 3) rec C (3w, idx 4..7) rec D (2w, idx 7..9)
        //  rec E (2w, idx 9..11)
        let a = [hdr(TAG_MHDMA, 1, 0), 0, 0];
        let b = [hdr(TAG_B2B, B2B_FREE_REQ, 0x0202)];
        let c = [hdr(TAG_MHDMA, 2, 5), 0xC1, 0xC2];
        let d = [hdr(TAG_DST_CNT, 1, 4), 0x0001_0000];
        let e = [hdr(TAG_ACK, 0, 0), 0x1 << 26];
        let stream: Vec<u32> = [&a[..], &b, &c, &d, &e].concat();
        let mut ring = [0u32; 6];
        for (i, w) in stream.iter().enumerate() {
            ring[i % 6] = *w;
        }
        let t = decode(0, stream.len() as u32, &ring);
        assert!(t.wrapped);
        assert_eq!(t.lost_words, 5);
        // Oldest kept word is idx 5 (middle of C) -> 2 words truncated, then D and E
        assert_eq!(t.events[0].event, FwTraceEvent::Truncated);
        assert_eq!(t.events[0].idx, 5);
        assert_eq!(t.events[0].raw.len(), 2);
        assert_eq!(event_name(&t.events[1].event), "DstCount");
        assert_eq!(t.events[1].idx, 7);
        assert_eq!(event_name(&t.events[2].event), "Ack");
        assert_eq!(t.events[2].idx, 9);
        assert_eq!(t.events.len(), 3);
    }

    #[test]
    fn json_layout() {
        let t = decode(0, 1, &[hdr(TAG_B2B, B2B_FREE_REQ, 0x0102)]);
        let json = serde_json::to_value(&t.events[0]).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "idx": 0, "event": "B2bFreeReq", "iid": 2, "tail_iid": 1, "will_free": false,
                "raw": ["0xb2b00102"]
            })
        );
    }
}
