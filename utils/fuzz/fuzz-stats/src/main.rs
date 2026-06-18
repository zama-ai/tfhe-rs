//! Corpus health statistics for the `ProvenCompactCiphertextList` fuzz corpus.
//!
//! For every input in a (minimized) corpus directory, runs deserialization + conformance, then —
//! if that passes — the verify and compute branches independently, and tallies a histogram of
//! [`ExecEndCause`] outcomes. This answers "how deep does the corpus actually get?".
//!
//! The histogram is a set of independent counters, not a partition: a single input that fails both
//! verify *and* compute bumps two failure buckets, so the counters need not sum to the input count.
//! `ExecSuccess` is bumped only when deserialization, verification, and computation all succeed.
//!
//! Each input is run under `catch_unwind` as a safety net; a nonzero exit code is returned if any
//! input panics (the minimized corpus is expected to be crash-free, so a panic here is a
//! regression). Unlike the harnesses, this is a plain (non-AFL) binary and runs multi-threaded
//! across inputs.

use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};

use fuzz_utils::{ExecEndCause, FUZZ_DOMAIN_SEPARATOR, FuzzContext, INPUT_MAX_SIZE, use_list};
use rayon::prelude::*;
use tfhe::ProvenCompactCiphertextList;
use tfhe::safe_serialization::safe_deserialize_conformant;
use tfhe::zk::ZkVerificationOutcome;

/// Histogram of outcomes over a set of inputs.
///
/// Counters are independent: failing verify and compute both increments two of them, so they need
/// not sum to `total`.
#[derive(Default, Clone, Copy)]
struct Histogram {
    total: usize,
    safe_deserialization_failed: usize,
    zk_verification_failed: usize,
    expand_failed: usize,
    expander_get_failed: usize,
    unsupported_type: usize,
    exec_success: usize,
    crashes: usize,
}

impl Histogram {
    fn merge(mut self, other: Self) -> Self {
        self.total += other.total;
        self.safe_deserialization_failed += other.safe_deserialization_failed;
        self.zk_verification_failed += other.zk_verification_failed;
        self.expand_failed += other.expand_failed;
        self.expander_get_failed += other.expander_get_failed;
        self.unsupported_type += other.unsupported_type;
        self.exec_success += other.exec_success;
        self.crashes += other.crashes;
        self
    }

    /// Labelled rows in display order, paired with their counts.
    fn rows(&self) -> [(&'static str, usize); 6] {
        [
            (
                "SafeDeserializationFailed",
                self.safe_deserialization_failed,
            ),
            ("ZkVerificationFailed", self.zk_verification_failed),
            ("ExpandFailed", self.expand_failed),
            ("ExpanderGetFailed", self.expander_get_failed),
            ("UnsupportedType", self.unsupported_type),
            ("ExecSuccess", self.exec_success),
        ]
    }
}

/// Run a single input: deserialize, then (if conformant) verify and compute independently.
fn classify(input: &[u8], ctx: &FuzzContext) -> Histogram {
    let mut hist = Histogram {
        total: 1,
        ..Default::default()
    };

    let Ok(ct_list) = safe_deserialize_conformant::<ProvenCompactCiphertextList>(
        input,
        INPUT_MAX_SIZE,
        &ctx.conformance_params,
    ) else {
        hist.safe_deserialization_failed = 1;
        return hist;
    };

    // Deserialization passed; the verify and compute branches are independent.
    let verify_ok = matches!(
        ct_list.verify(&ctx.crs, &ctx.pubkey, FUZZ_DOMAIN_SEPARATOR),
        ZkVerificationOutcome::Valid
    );
    if !verify_ok {
        hist.zk_verification_failed = 1;
    }

    let compute = match ct_list.expand_without_verification() {
        Ok(exp) => use_list(&exp),
        Err(_) => ExecEndCause::ExpandFailed,
    };
    match compute {
        ExecEndCause::ExpandFailed => hist.expand_failed = 1,
        ExecEndCause::ExpanderGetFailed => hist.expander_get_failed = 1,
        ExecEndCause::UnsupportedType => hist.unsupported_type = 1,
        // Reachable only via the verify branch / the deser gate, both handled above.
        ExecEndCause::SafeDeserializationFailed
        | ExecEndCause::ZkVerificationFailed
        | ExecEndCause::ExecSuccess => {}
    }

    if verify_ok && matches!(compute, ExecEndCause::ExecSuccess) {
        hist.exec_success = 1;
    }

    hist
}

/// Classify one input, catching panics so a single crashing input doesn't abort the whole run.
fn process(input: &[u8], ctx: &FuzzContext) -> Histogram {
    match std::panic::catch_unwind(AssertUnwindSafe(|| classify(input, ctx))) {
        Ok(hist) => hist,
        Err(_) => Histogram {
            total: 1,
            crashes: 1,
            ..Default::default()
        },
    }
}

fn collect_input_files(dir: &Path) -> Vec<PathBuf> {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| {
        eprintln!("error: cannot read corpus directory {}: {e}", dir.display());
        std::process::exit(2);
    });

    entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect()
}

fn print_table(hist: &Histogram, dir: &Path) {
    let pct = |n: usize| {
        if hist.total == 0 {
            0.0
        } else {
            100.0 * n as f64 / hist.total as f64
        }
    };

    println!("corpus: {} inputs ({})", hist.total, dir.display());
    println!("(counters are independent; an input may fail both verify and compute)");
    for (label, count) in hist.rows() {
        println!("  {label:<27} {count:>6} ({:>5.1}%)", pct(count));
    }
    println!(
        "  {:<27} {:>6} ({:>5.1}%)",
        "crashes",
        hist.crashes,
        pct(hist.crashes)
    );
}

fn print_json(hist: &Histogram, dir: &Path) {
    println!(
        "{{\"corpus_dir\":{:?},\"total\":{},\"safe_deserialization_failed\":{},\"zk_verification_failed\":{},\"expand_failed\":{},\"expander_get_failed\":{},\"unsupported_type\":{},\"exec_success\":{},\"crashes\":{}}}",
        dir.display().to_string(),
        hist.total,
        hist.safe_deserialization_failed,
        hist.zk_verification_failed,
        hist.expand_failed,
        hist.expander_get_failed,
        hist.unsupported_type,
        hist.exec_success,
        hist.crashes,
    );
}

fn usage() -> ! {
    eprintln!("Usage: fuzz-stats [--json] <corpus-dir>");
    eprintln!();
    eprintln!("Run every input in <corpus-dir> through deser + verify + compute and report a");
    eprintln!("histogram of outcomes. Exits nonzero if any input panics.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --json       Emit machine-readable JSON instead of a table");
    eprintln!("  -h, --help   Show this help message");
    std::process::exit(2);
}

fn main() {
    let mut json = false;
    let mut dir: Option<PathBuf> = None;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => usage(),
            _ => dir = Some(PathBuf::from(arg)),
        }
    }
    let Some(dir) = dir else { usage() };

    let ctx = FuzzContext::load();
    // The server key lives in a thread-local; install it on the main thread and every rayon worker.
    ctx.install_server_key();
    rayon::broadcast(|_| ctx.install_server_key());

    let files = collect_input_files(&dir);

    let hist = files
        .par_iter()
        .map(|path| match std::fs::read(path) {
            Ok(input) => process(&input, &ctx),
            Err(_) => Histogram {
                total: 1,
                ..Default::default()
            },
        })
        .reduce(Histogram::default, Histogram::merge);

    if json {
        print_json(&hist, &dir);
    } else {
        print_table(&hist, &dir);
    }

    if hist.crashes > 0 {
        std::process::exit(1);
    }
}
