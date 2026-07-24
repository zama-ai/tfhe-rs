//! Corpus health statistics for the `ProvenCompactCiphertextList` fuzz corpus.
//!
//! For every input in a (minimized) corpus directory, runs deserialization + conformance. Then,
//! if that passes, runs the verify and compute branches independently. Finally, produces a
//! histogram of [`ExecEndCause`] outcomes.

use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};

use clap::Parser;
use fuzz_utils::{ExecEndCause, FUZZ_DOMAIN_SEPARATOR, FuzzContext, INPUT_MAX_SIZE, use_list};
use rayon::prelude::*;
use serde::Serialize;
use tfhe::ProvenCompactCiphertextList;
use tfhe::safe_serialization::safe_deserialize_conformant;
use tfhe::zk::ZkVerificationOutcome;

/// Histogram of outcomes over a set of inputs.
///
/// Counters are independent: failing verify and compute both increments two of them, so they need
/// not sum to `total`.
#[derive(Default, Clone, Copy, Serialize)]
struct Histogram {
    total: usize,
    safe_deserialization_failed: usize,
    zk_verification_failed: usize,
    expand_failed: usize,
    expander_get_failed: usize,
    unsupported_type: usize,
    compression_failed: usize,
    exec_success: usize,
    crashes: usize,
}

impl Histogram {
    fn merge(mut self, other: Self) -> Self {
        let Self {
            total,
            safe_deserialization_failed,
            zk_verification_failed,
            expand_failed,
            expander_get_failed,
            unsupported_type,
            compression_failed,
            exec_success,
            crashes,
        } = other;
        self.total += total;
        self.safe_deserialization_failed += safe_deserialization_failed;
        self.zk_verification_failed += zk_verification_failed;
        self.expand_failed += expand_failed;
        self.expander_get_failed += expander_get_failed;
        self.unsupported_type += unsupported_type;
        self.compression_failed += compression_failed;
        self.exec_success += exec_success;
        self.crashes += crashes;
        self
    }

    /// Labelled rows in display order, paired with their counts.
    fn rows(&self) -> [(ExecEndCause, usize); 7] {
        [
            (
                ExecEndCause::SafeDeserializationFailed,
                self.safe_deserialization_failed,
            ),
            (
                ExecEndCause::ZkVerificationFailed,
                self.zk_verification_failed,
            ),
            (ExecEndCause::ExpandFailed, self.expand_failed),
            (ExecEndCause::ExpanderGetFailed, self.expander_get_failed),
            (ExecEndCause::UnsupportedType, self.unsupported_type),
            (ExecEndCause::CompressionFailed, self.compression_failed),
            (ExecEndCause::ExecSuccess, self.exec_success),
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

    // Deserialization passed. The verify and compute branches are independent.
    let verify_ok = matches!(
        ct_list.verify(&ctx.crs, &ctx.pubkey, FUZZ_DOMAIN_SEPARATOR),
        ZkVerificationOutcome::Valid
    );
    if !verify_ok {
        hist.zk_verification_failed = 1;
    }

    let compute_result = match ct_list.expand_without_verification() {
        Ok(exp) => use_list(&exp),
        Err(_) => ExecEndCause::ExpandFailed,
    };
    match compute_result {
        ExecEndCause::ExpandFailed => hist.expand_failed = 1,
        ExecEndCause::ExpanderGetFailed => hist.expander_get_failed = 1,
        ExecEndCause::UnsupportedType => hist.unsupported_type = 1,
        ExecEndCause::CompressionFailed => hist.compression_failed = 1,
        // Reachable only via the verify branch / the deser gate, both handled above.
        ExecEndCause::SafeDeserializationFailed | ExecEndCause::ZkVerificationFailed => {}
        ExecEndCause::ExecSuccess => {
            if verify_ok {
                hist.exec_success = 1;
            }
        }
    }

    hist
}

/// Classify one input, catching panics so a single crashing input doesn't abort the whole run.
///
/// If `save_crashes_dir` is set and the input panics, copy it in there so the postcampaign step can
/// count and archive it alongside the AFL-side crashes.
fn process(
    path: &Path,
    input: &[u8],
    ctx: &FuzzContext,
    save_crashes_dir: Option<&Path>,
) -> Histogram {
    match std::panic::catch_unwind(AssertUnwindSafe(|| classify(input, ctx))) {
        Ok(hist) => hist,
        Err(_) => {
            if let Some(dir) = save_crashes_dir
                && let Some(name) = path.file_name()
            {
                let dst = dir.join(name);
                // Best-effort: a failed copy just means we lose the archive, not the count.
                if let Err(e) = std::fs::copy(path, &dst) {
                    eprintln!(
                        "warning: could not archive panicking input {} → {}: {e}",
                        path.display(),
                        dst.display()
                    );
                }
            }
            Histogram {
                total: 1,
                crashes: 1,
                ..Default::default()
            }
        }
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

fn print_table(hist: &Histogram) {
    let pct = |n: usize| {
        if hist.total == 0 {
            0.0
        } else {
            100.0 * n as f64 / hist.total as f64
        }
    };

    println!("corpus: {} unique inputs", hist.total);
    println!("(counters are independent; an input may fail both verify and compute)");
    for (variant, count) in hist.rows() {
        // Derived Debug ignores the formatter's width, so format to a String first.
        let label = format!("{variant:?}");
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
    #[derive(Serialize)]
    struct Report<'a> {
        corpus_dir: String,
        // Flatten so `Histogram`'s fields appear at the top level next to `corpus_dir`.
        #[serde(flatten)]
        histogram: &'a Histogram,
    }
    let report = Report {
        corpus_dir: dir.display().to_string(),
        histogram: hist,
    };
    println!("{}", serde_json::to_string(&report).unwrap());
}

/// Run every input in a corpus directory through deser + verify + compute and report a histogram
/// of outcomes.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Corpus directory to analyze.
    corpus_dir: PathBuf,

    /// Emit machine-readable JSON instead of a table.
    #[arg(long)]
    json: bool,

    /// If set, copy any panicking corpus input into this directory. AFL sometimes leaves flaky
    /// (nondeterministic) crashes in the queue instead of the crashes/ dir; this promotes them.
    #[arg(long, value_name = "DIR")]
    save_crashes: Option<PathBuf>,
}

fn main() {
    let args = Args::parse();
    let dir = args.corpus_dir;

    let ctx = FuzzContext::load();
    ctx.set_server_key();
    rayon::broadcast(|_| ctx.set_server_key());

    if let Some(save_dir) = &args.save_crashes
        && let Err(e) = std::fs::create_dir_all(save_dir)
    {
        eprintln!(
            "error: cannot create --save-crashes directory {}: {e}",
            save_dir.display()
        );
        std::process::exit(2);
    }
    let save_crashes = args.save_crashes.as_deref();

    let files = collect_input_files(&dir);

    let hist = files
        .par_iter()
        .map(|path| match std::fs::read(path) {
            Ok(input) => process(path, &input, &ctx, save_crashes),
            Err(_) => Histogram {
                total: 1,
                ..Default::default()
            },
        })
        .reduce(Histogram::default, Histogram::merge);

    if args.json {
        print_json(&hist, &dir);
    } else {
        print_table(&hist);
    }
}
