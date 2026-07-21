//!
//! Application used to convert a set of isc raw hardware trace
//! It produces:
//!  * a refined trace files: discrete event (Refill, Issue, RdUnlock, Retired) are gather in instruction lifetime
//!  * Each set are gather in a perfetto readable trace

use std::fs::File;
use std::io::BufReader;
use std::{collections::BTreeMap, fs};

use serde_json::json;
use tfhe_hpu_backend::asm::dop::ToAsm;
use tfhe_hpu_backend::prelude::*;

/// Define CLI arguments
use clap::Parser;
use zhc::utils::tracing::{Microseconds, Scope};
#[derive(Parser, Debug, Clone)]
#[command(long_about = "Isc hardware trace parsing")]
pub struct Args {
    /// Directory to search in
    #[arg(short, long, default_value = ".")]
    dir: String,

    /// Regex with a single named capture `(?P<idx>\d+)`
    /// e.g. `myopt_params_(?P<idx>\d+)\.json`
    #[arg(long = "in")]
    pattern: String,
}

#[derive(Debug)]
struct TraceArgs {
    files: BTreeMap<String, String>,
    base_name: String,
}

impl TryFrom<&Args> for TraceArgs {
    type Error = anyhow::Error;

    fn try_from(args: &Args) -> Result<Self, Self::Error> {
        let re = regex::Regex::new(&args.pattern)?;

        if !re.capture_names().flatten().any(|n| n == "idx") {
            anyhow::bail!("pattern must contain a named capture group `(?P<idx>...)`");
        }

        let base_name = {
            const IDX_MARKER: &str = "(?P<idx>";

            let idx_pos = args
                .pattern
                .find(IDX_MARKER)
                .ok_or_else(|| anyhow::anyhow!("cannot extract base_name from pattern"))?;

            // Everything before the capture group, strip trailing separator
            args.pattern[..idx_pos]
                .trim_end_matches(['_', '-', '.'])
                .to_owned()
        };

        let files = {
            let mut entries = fs::read_dir(&args.dir)?
                .map(|res| res.map(|e| e.file_name()))
                .collect::<Result<Vec<_>, _>>()?;
            entries.sort(); //Guarantee lexicographical order

            entries
                .into_iter()
                .filter_map(|e| {
                    let name = format!("{}/{}", args.dir, e.to_string_lossy());
                    let caps = re.captures(&name)?;
                    let idx = caps.name("idx")?.as_str().to_string();
                    Some((idx, name))
                })
                .collect::<BTreeMap<_, _>>()
        };

        Ok(Self { files, base_name })
    }
}

fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    println!("User Options: {args:?}");

    let trace_files = TraceArgs::try_from(&args)?;
    println!("{trace_files:?}");

    // For each trace
    // a) Load it as IscTraceStream
    // b) Refine it in IscInsnStream
    // c) Dump refined version in json for manual post-process
    let insn_streams = trace_files
        .files
        .iter()
        .map(|(idx, filename)| {
            let trace_file = File::open(filename)?;
            let isc: isc_trace::IscTraceStream =
                serde_json::from_reader(BufReader::new(trace_file))?;
            let mut insn_stream = insn_trace::InsnTraceStream::from(&isc);
            insn_stream.align_ts();

            // Dump as json
            let insn_filename = format!("{}/{}{}_insn.json", args.dir, trace_files.base_name, idx);
            let insn_file =
                File::create(insn_filename).expect("Failed to create or open trace dump file");
            let buf_wr = std::io::BufWriter::new(insn_file);
            serde_json::to_writer_pretty(buf_wr, &insn_stream).expect("Could not write trace dump");
            Ok((idx, insn_stream))
        })
        .collect::<Result<BTreeMap<_, _>, anyhow::Error>>()?;

    // Aggregate all stream in a perfetto compatible trace
    let mut ptrace = zhc::utils::tracing::Trace::default();
    for (i, (k, v)) in insn_streams.iter().enumerate() {
        // Create headers packed in a thread:
        // * Events: contains refill,retire events for each instructions
        // * for each pe:
        //   * Duration event (exec time of iop)
        //   * Load counter
        let cur_pid = i + 1; // pid 0 is a reserved value
        ptrace.set_process_name(cur_pid, format!("Node_{k}"));
        let tid_events = 1;
        let tid_pem = 2;
        let tid_pea = 3;
        let tid_ucore = 4;
        let tid_pbs = 5;
        ptrace.set_thread_name(cur_pid, tid_events, "PeEvents");
        ptrace.set_thread_name(cur_pid, tid_pem, "PeMem");
        ptrace.set_thread_name(cur_pid, tid_pea, "PeAlu");
        ptrace.set_thread_name(cur_pid, tid_ucore, "Ucore");
        ptrace.set_thread_name(cur_pid, tid_pbs, "PePbs");

        let mut pbs_cnt = 0;
        for insn in v.as_view().iter() {
            // All instruction generate Events
            ptrace.new_instant(
                insn.lifetime.refill as Microseconds,
                cur_pid,
                tid_events,
                "Refill",
                Some(json!({"asm": insn.insn_asm, "cmd": "Refill" })),
                Scope::Thread,
            );
            ptrace.new_instant(
                insn.lifetime.issue as Microseconds,
                cur_pid,
                tid_events,
                "Issue",
                Some(json!({"asm": insn.insn_asm, "cmd": "Issue" })),
                Scope::Thread,
            );
            ptrace.new_instant(
                insn.lifetime.rd_unlock as Microseconds,
                cur_pid,
                tid_events,
                "RdUnlock",
                Some(json!({"asm": insn.insn_asm, "cmd": "RdUnlock" })),
                Scope::Thread,
            );
            ptrace.new_instant(
                insn.lifetime.retire as Microseconds,
                cur_pid,
                tid_events,
                "Retire",
                Some(json!({"asm": insn.insn_asm, "cmd": "Retire" })),
                Scope::Thread,
            );

            let opcode = insn.insn.opcode();
            let target_tid = match opcode.optype() {
                hpu_asm::dop::DOpType::ARITH => tid_pea,
                hpu_asm::dop::DOpType::UCORE => tid_ucore,
                hpu_asm::dop::DOpType::MEM => tid_pem,
                hpu_asm::dop::DOpType::PBS => tid_pbs,
            };
            ptrace.new_complete(
                insn.lifetime.issue as Microseconds,
                cur_pid,
                target_tid,
                &insn.insn_asm,
                None,
                insn.lifetime.exec_cycles() as Microseconds,
            );

            // Handle side opcode effect
            match opcode.optype() {
                hpu_asm::dop::DOpType::PBS => {
                    // Pbs also handle load counter
                    // NB: Pbs could accept up-to 2 batch in issue mode. Thus to enhance counter readability, rd_unlock event is used.
                    // => Only 1 full batch could be between rd_unlock/retire state at a time
                    pbs_cnt += 1;
                    ptrace.new_counter(
                        insn.lifetime.rd_unlock as Microseconds,
                        cur_pid,
                        tid_pbs,
                        "Pbs_load",
                        Some(json!({"pbs_in_batch": pbs_cnt})),
                    );

                    if opcode.is_flush() {
                        pbs_cnt = 0;
                        ptrace.new_counter(
                            insn.lifetime.retire as Microseconds,
                            cur_pid,
                            tid_pbs,
                            "Pbs_load",
                            Some(json!({"pbs_in_batch": pbs_cnt})),
                        );
                        ptrace.new_instant(
                            insn.lifetime.rd_unlock as Microseconds,
                            cur_pid,
                            tid_pbs,
                            "PbsFlush",
                            Some(json!({"asm": insn.insn_asm})),
                            Scope::Thread,
                        );
                    }
                }
                _ => { /*Nothing to do */ }
            };
        }
    }

    let perfetto_filename = format!("{}/{}_perf.json", args.dir, trace_files.base_name);
    let perfetto_file =
        File::create(perfetto_filename).expect("Failed to create or open trace dump file");
    let buf_wr = std::io::BufWriter::new(perfetto_file);
    serde_json::to_writer_pretty(buf_wr, &ptrace).expect("Could not write trace dump");

    Ok(())
}
