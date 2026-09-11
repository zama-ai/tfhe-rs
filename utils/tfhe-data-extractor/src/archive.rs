//! The quarterly benchmark archive: one row per published operation, latency
//! and throughput side by side.
//!
//! A report, not a table, hence its place beside [`format`](crate::format)
//! rather than inside it. The archive repository merges this CSV into its own
//! `cells.csv` and formats the figures itself, so it wants raw numbers rather
//! than `8.70 ms`, and nothing here builds a [`Grid`](crate::format::Grid).

use std::fmt;
use std::str::FromStr;

use benchmark_spec::tfhe::hlapi::dex::{Dex, DexFlavor};
use benchmark_spec::tfhe::hlapi::erc7984::{Erc7984, TransferFlavor};
use benchmark_spec::tfhe::hlapi::noise_squash::NoiseSquashingKind;
use benchmark_spec::{
    BenchPath, BenchmarkMetric, HlapiBench, IntegerBench, IntegerOp, IntegerOpBySign,
    IntegerPackingOp, TfheLayer, ZkPkeBench,
};

use crate::db::like_escape;
use crate::format::render::csv::write_record;
use crate::format::{Measured, three_significant_digits};

/// A publication label and the benchmark its figures are read from.
pub struct ArchiveOp {
    /// The `op` column, and the key the merge into `cells.csv` joins on:
    /// renaming one rewrites the whole history of a row.
    pub label: &'static str,
    /// Every id the label reads from, the way `integer.rs` elects
    /// `gt_parallelized` for the whole "Comparisons (ge, gt, le, lt)" row.
    ///
    /// More than one when the same operation is spelled differently depending
    /// on where it ran: the cuda benches call the unparallelized names, the
    /// parallelism being the device's and not rayon's. One published row all
    /// the same, and the election decides between them like it decides between
    /// two machines.
    ///
    /// Typed rather than spelled out, so a renamed operation breaks the build
    /// instead of quietly matching nothing.
    pub paths: &'static [BenchPath],
    /// Ciphertext width to pin, when the bench is measured at several. `None`
    /// takes whatever comes back, which the application-level benches need.
    pub bit_size: Option<i64>,
}

/// An unsigned integer operation, the only sign the archive publishes.
///
/// These three keep the catalogue readable: four levels of parentheses on every
/// row would not be.
const fn integer_op(op: IntegerOp) -> BenchPath {
    integer(IntegerBench::Ops(IntegerOpBySign::Unsigned(op)))
}

const fn integer(bench: IntegerBench) -> BenchPath {
    BenchPath::Tfhe(TfheLayer::Integer(bench))
}

const fn hlapi(bench: HlapiBench) -> BenchPath {
    BenchPath::Tfhe(TfheLayer::Hlapi(bench))
}

/// Every row the archive publishes, save the one the spec cannot spell.
///
/// Listed whether or not the database can answer today. An entry whose
/// benchmark still stores pre-spec ids comes back as `missing`, and that line
/// is the point: the figure has to be produced, the row is not exempt.
///
/// The flavours are not an editorial choice: `overflow` and `no_cmux` are the
/// only ones the 8-GPU box has ever measured, and theirs are the figures the
/// published history holds (23.5 ms for `overflow` in mid-2026, against 24 ms
/// published for 2026Q1).
pub const ARCHIVE_OPS: &[ArchiveOp] = &[
    // The four integer rows carry the cuda spelling beside the cpu one, without
    // which no GPU figure could ever win them.
    ArchiveOp {
        label: "add",
        paths: &[
            integer_op(IntegerOp::AddParallelized),
            integer_op(IntegerOp::Add),
        ],
        bit_size: Some(64),
    },
    ArchiveOp {
        label: "mul",
        paths: &[
            integer_op(IntegerOp::MulParallelized),
            integer_op(IntegerOp::Mul),
        ],
        bit_size: Some(64),
    },
    ArchiveOp {
        label: "div",
        paths: &[
            integer_op(IntegerOp::DivRemParallelized),
            integer_op(IntegerOp::DivRem),
        ],
        bit_size: Some(64),
    },
    ArchiveOp {
        label: "comparison",
        paths: &[
            integer_op(IntegerOp::GtParallelized),
            integer_op(IntegerOp::Gt),
        ],
        bit_size: Some(64),
    },
    // The compression and zero-knowledge benchmarks store no width of their
    // own, hence no `bit_size` to pin: the type tag carries it.
    ArchiveOp {
        label: "compress",
        paths: &[integer(IntegerBench::PackingCompression(
            IntegerPackingOp::Pack,
        ))],
        bit_size: None,
    },
    ArchiveOp {
        label: "decompress",
        paths: &[integer(IntegerBench::PackingCompression(
            IntegerPackingOp::Unpack,
        ))],
        bit_size: None,
    },
    ArchiveOp {
        label: "zkpok_server",
        paths: &[integer(IntegerBench::Zk(ZkPkeBench::Proof))],
        bit_size: None,
    },
    // `Verify` rather than `VerifyAndExpand`, the archive publishing the
    // verification alone. Nothing stored can confirm it yet, both spellings
    // being pre-spec, so this one is a reading of the label and no more.
    ArchiveOp {
        label: "zkpok_verify",
        paths: &[integer(IntegerBench::Zk(ZkPkeBench::Verify))],
        bit_size: None,
    },
    ArchiveOp {
        label: "sns",
        paths: &[hlapi(HlapiBench::NoiseSquashing(
            NoiseSquashingKind::NoiseSquash,
        ))],
        bit_size: None,
    },
    ArchiveOp {
        label: "erc7984_transfer",
        paths: &[hlapi(HlapiBench::Erc7984(Erc7984::Transfer(
            TransferFlavor::Overflow,
        )))],
        bit_size: None,
    },
    ArchiveOp {
        label: "batch_swap_intents",
        paths: &[hlapi(HlapiBench::Dex(Dex::SwapRequest(DexFlavor::NoCmux)))],
        bit_size: None,
    },
    ArchiveOp {
        label: "redistribute_swap_tokens",
        paths: &[hlapi(HlapiBench::Dex(Dex::SwapClaim(DexFlavor::NoCmux)))],
        bit_size: None,
    },
];

/// The rows no catalogue entry can express, with the id they would come from.
///
/// Only the browser proof, and not for want of a migrated emitter: the wasm ids
/// carry no crate segment at all, so they have no path in the spec, and
/// [`Layer::Wasm`](crate::cli::Layer::Wasm) says as much. There is no `BenchPath` to
/// write down, which is the whole difference with an entry that merely comes
/// back empty.
pub struct PendingOp {
    /// The `op` column it would fill.
    pub label: &'static str,
    /// The id it would read, in the spelling the database holds.
    pub stored_id: &'static str,
}

pub const PENDING_OPS: &[PendingOp] = &[PendingOp {
    label: "zkpok_browser",
    stored_id: "wasm::compact_fhe_uint_proven_encryption_*_chrome",
}];

/// Every row the published page carries, whether this tool can fill it or not.
/// Spelled out here rather than added up at the call site, the split between
/// the two lists being an implementation detail of the catalogue.
pub fn published_rows() -> usize {
    ARCHIVE_OPS.len() + PENDING_OPS.len()
}

pub struct Machine {
    /// As the runner registers it.
    pub stored: &'static str,
    /// As the archive spells it. Only the GPU boxes differ, and the same one
    /// answers to two stored names, having been renamed mid-history.
    pub published: &'static str,
}

/// The fleet an operation may be elected from.
///
/// An allow-list, because electing on the best figure would otherwise hand a
/// row to `rtx4090` or an HPU box and publish a machine the archive's own
/// legend does not list. Adding one means a new footnote on the page.
const FLEET: &[Machine] = &[
    Machine {
        stored: "n3-H100-SXM5x8",
        published: "8xH100-SXM5",
    },
    Machine {
        stored: "H100-SXM-8-80G",
        published: "8xH100-SXM5",
    },
    Machine {
        stored: "hpc8a.96xlarge",
        published: "hpc8a.96xlarge",
    },
    Machine {
        stored: "hpc7a.96xlarge",
        published: "hpc7a.96xlarge",
    },
    Machine {
        stored: "m6i.4xlarge",
        published: "m6i.4xlarge",
    },
];

pub fn fleet() -> Vec<String> {
    FLEET.iter().map(|m| m.stored.to_string()).collect()
}

fn published_name(stored: &str) -> &str {
    FLEET
        .iter()
        .find(|m| m.stored == stored)
        .map_or(stored, |m| m.published)
}

/// A publication quarter, `2026Q2`. A label and nothing more: which results it
/// tags is decided by the window, never by this.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Quarter {
    year: u16,
    index: u8,
}

impl fmt::Display for Quarter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}Q{}", self.year, self.index)
    }
}

impl FromStr for Quarter {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (year, index) = s
            .split_once('Q')
            .ok_or_else(|| format!("expected <year>Q<1-4>, got `{s}`"))?;

        let year = year
            .parse::<u16>()
            .map_err(|_| format!("`{year}` is not a year"))?;
        let index = index
            .parse::<u8>()
            .map_err(|_| format!("`{index}` is not a quarter number"))?;

        if !(1..=4).contains(&index) {
            return Err(format!("quarter {index} is outside 1..=4"));
        }

        Ok(Self { year, index })
    }
}

/// One archive row, before serialization.
pub struct ArchiveRow {
    pub op: &'static str,
    pub latency_ns: Option<f64>,
    pub throughput_ops_s: Option<f64>,
    /// Elected, not configured.
    pub hardware: String,
}

/// The rows of one quarter, plus what the run could not account for.
pub struct Archive {
    /// Only the operations with at least one figure. One with none is left out
    /// rather than merged in empty, which would publish a hole.
    pub rows: Vec<ArchiveRow>,
    pub missing: Vec<&'static str>,
    /// Where the election is worth a second look: a rate beaten on another
    /// machine, or missing from the one latency picked.
    pub notes: Vec<String>,
}

/// Elects, for each catalogue entry, the machine with the best latency, then
/// reads that machine's best rate.
///
/// The query has already reduced each id to its most recent value, so the
/// dimensions left to arbitrate are the ones the id spells out: machine,
/// backend, parameter set, PBS kind, batch size. Better wins between them,
/// which is why none of them needs a flag. The backend is arbitrated like the
/// rest: a label reading both spellings of an operation publishes whichever of
/// the two ran faster, and names the machine it ran on.
///
/// Only the machine is held across the two figures, since it is the only
/// configuration the published row names. A multi-bit latency next to a
/// classical rate is therefore expected, and fine.
pub fn build(measured: &[Measured]) -> Archive {
    // `BenchPath` is `Copy` but not `Eq`, so the join is on rendered paths.
    let paths: Vec<String> = measured
        .iter()
        .map(|m| m.spec.bench_path().to_string())
        .collect();

    let mut archive = Archive {
        rows: Vec::with_capacity(ARCHIVE_OPS.len()),
        missing: Vec::new(),
        notes: Vec::new(),
    };

    for op in ARCHIVE_OPS {
        // Rendered once per label rather than once per comparison.
        let wanted: Vec<String> = op.paths.iter().map(|path| path.to_string()).collect();
        let mut latencies: Vec<&Measured> = Vec::new();
        let mut rates: Vec<&Measured> = Vec::new();

        for (m, path) in measured.iter().zip(&paths) {
            if !wanted.contains(path) || op.bit_size.is_some_and(|bits| bits != m.bit_size) {
                continue;
            }
            match m.spec.metric() {
                BenchmarkMetric::Latency => latencies.push(m),
                BenchmarkMetric::Throughput => rates.push(m),
                // The archive publishes no counts and no key sizes.
                BenchmarkMetric::PbsCount | BenchmarkMetric::KeySize => {}
            }
        }

        // `total_cmp` rather than `partial_cmp`: a stored NaN would make every
        // comparison false and leave the winner to input order.
        let best_latency = latencies.iter().min_by(|a, b| a.value.total_cmp(&b.value));
        let best_rate_overall = rates.iter().max_by(|a, b| a.value.total_cmp(&b.value));

        // With no latency to elect on, the best rate carries the machine alone.
        let machine = match best_latency.or(best_rate_overall) {
            Some(m) => m.hardware.as_str(),
            None => {
                archive.missing.push(op.label);
                continue;
            }
        };

        let best_rate = rates
            .iter()
            .filter(|m| m.hardware == machine)
            .max_by(|a, b| a.value.total_cmp(&b.value));

        // Both cases leave a better figure on the table.
        match (best_rate, best_rate_overall) {
            (Some(local), Some(overall)) if overall.value > local.value => {
                archive.notes.push(format!(
                    "{}: rate {:.0} kept from {machine}, {:.0} on {} left out",
                    op.label, local.value, overall.value, overall.hardware,
                ));
            }
            (None, Some(overall)) => {
                archive.notes.push(format!(
                    "{}: no rate on {machine}, which latency elected; {:.0} on {} left out",
                    op.label, overall.value, overall.hardware,
                ));
            }
            _ => {}
        }

        archive.rows.push(ArchiveRow {
            op: op.label,
            latency_ns: best_latency.map(|m| m.value),
            throughput_ops_s: best_rate.map(|m| m.value),
            hardware: published_name(machine).to_string(),
        });
    }

    archive
}

impl Archive {
    /// Reports on stderr every published row this run does not cover, whether
    /// because nothing came back or because the bench is not extractable yet.
    pub fn report(&self) {
        if !self.missing.is_empty() {
            eprintln!(
                "warning: {} operation(s) without any result: {}. \
                 Either the benchmark did not run on a fleet machine inside the \
                 window, or its ids are still stored in the pre-spec spelling.",
                self.missing.len(),
                self.missing.join(", "),
            );
        }

        for op in PENDING_OPS {
            eprintln!(
                "note: `{}` stays manual, `{}` has no path in the spec",
                op.label, op.stored_id,
            );
        }

        if !self.notes.is_empty() {
            eprintln!(
                "note: {} row(s) where the election is worth a look:",
                self.notes.len()
            );
            for note in &self.notes {
                eprintln!("  {note}");
            }
        }
    }
}

/// Column order is part of the contract with the archive repository, `note`
/// included: always empty here, but dropping it would misalign the merge.
const HEADER: &[&str] = &[
    "op",
    "quarter",
    "latency_ns",
    "throughput_ops_s",
    "hardware",
    "source",
    "note",
];

/// What produced the row, as `cells.csv` spells it.
const SOURCE: &str = "extractor";

/// The merge input. The quarter is the same on every row; the machine is not,
/// each operation having elected its own.
pub fn render(archive: &Archive, quarter: Quarter) -> String {
    let quarter = quarter.to_string();
    let mut out = String::new();
    write_record(&mut out, HEADER.iter().copied());

    for row in &archive.rows {
        // Nanoseconds are whole numbers; a rate is not, and reads at three
        // significant digits like the published figures do.
        let latency = row.latency_ns.map(|ns| format!("{ns:.0}"));
        let throughput = row.throughput_ops_s.map(three_significant_digits);

        write_record(
            &mut out,
            [
                row.op,
                quarter.as_str(),
                // Empty, not `N/A`: that is how `cells.csv` spells a figure
                // that was never measured.
                latency.as_deref().unwrap_or(""),
                throughput.as_deref().unwrap_or(""),
                row.hardware.as_str(),
                SOURCE,
                "",
            ]
            .into_iter(),
        );
    }

    out
}

/// SQL `LIKE` patterns selecting exactly the ids the archive reads, both
/// metrics included.
///
/// Same shape as [`Resolved::like_patterns`](crate::profile::Resolved::like_patterns):
/// the path is exact and the single `%` is the hole left for the backend, the
/// metric, the parameter set and the type. One per spelling, so there are more
/// of them than there are published rows, and `LIKE ANY` sends them in one bind
/// whatever their number.
pub fn like_patterns(name_suffix: &str) -> Vec<String> {
    ARCHIVE_OPS
        .iter()
        .flat_map(|op| {
            op.paths.iter().map(move |path| {
                format!(
                    "{}::%{}",
                    like_escape(&path.to_string()),
                    like_escape(name_suffix)
                )
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Existence is now the compiler's problem; spelling is not. A segment
    /// renamed in the spec silently changes both the SQL pattern and the join
    /// key, and stops matching the results already stored under the old
    /// spelling. Pinning the rendered form turns that into a visible diff.
    ///
    /// Rendered per label rather than as a flat list, so which rows read two
    /// spellings and which read one is on the page.
    #[test]
    fn the_catalogue_renders_the_ids_the_database_holds() {
        let rendered: Vec<String> = ARCHIVE_OPS
            .iter()
            .map(|op| {
                let ids: Vec<String> = op.paths.iter().map(|path| path.to_string()).collect();
                format!("{}: {}", op.label, ids.join(" "))
            })
            .collect();

        assert_eq!(
            rendered,
            [
                "add: tfhe::integer::ops::unsigned::add_parallelized \
                 tfhe::integer::ops::unsigned::add",
                "mul: tfhe::integer::ops::unsigned::mul_parallelized \
                 tfhe::integer::ops::unsigned::mul",
                "div: tfhe::integer::ops::unsigned::div_rem_parallelized \
                 tfhe::integer::ops::unsigned::div_rem",
                "comparison: tfhe::integer::ops::unsigned::gt_parallelized \
                 tfhe::integer::ops::unsigned::gt",
                "compress: tfhe::integer::packing_compression::pack",
                "decompress: tfhe::integer::packing_compression::unpack",
                "zkpok_server: tfhe::integer::zk::proof",
                "zkpok_verify: tfhe::integer::zk::verify",
                "sns: tfhe::hlapi::noise_squashing::noise_squash",
                "erc7984_transfer: tfhe::hlapi::erc7984::transfer::overflow",
                "batch_swap_intents: tfhe::hlapi::dex::swap_request::no_cmux",
                "redistribute_swap_tokens: tfhe::hlapi::dex::swap_claim::no_cmux",
            ],
        );
    }

    /// Two entries under one label would make the second unreachable, the
    /// lookup keeping the first value it finds.
    #[test]
    fn a_label_is_never_published_twice() {
        let mut labels: Vec<&str> = ARCHIVE_OPS.iter().map(|op| op.label).collect();
        labels.extend(PENDING_OPS.iter().map(|op| op.label));
        let count = labels.len();

        labels.sort_unstable();
        labels.dedup();

        assert_eq!(labels.len(), count, "duplicate label in the catalogue");
    }

    #[test]
    fn quarter_round_trips() {
        assert_eq!("2026Q2".parse::<Quarter>().unwrap().to_string(), "2026Q2");
    }

    #[test]
    fn quarter_rejects_what_cells_csv_would_not_hold() {
        for spelling in ["2026Q5", "2026Q0", "2026", "Q2", "2026q2", "20260Q2x"] {
            assert!(
                spelling.parse::<Quarter>().is_err(),
                "`{spelling}` should not parse",
            );
        }
    }

    #[test]
    fn gpu_hardware_is_published_under_its_marketing_name() {
        assert_eq!(published_name("n3-H100-SXM5x8"), "8xH100-SXM5");
        // Both spellings of the 8-GPU box publish as one machine.
        assert_eq!(published_name("H100-SXM-8-80G"), "8xH100-SXM5");
        // No alias needed, and none invented.
        assert_eq!(published_name("hpc7a.96xlarge"), "hpc7a.96xlarge");
    }

    /// The allow-list is what keeps a machine the archive legend does not
    /// describe from winning a row on the strength of its figures alone.
    #[test]
    fn the_fleet_excludes_what_the_archive_never_published() {
        let fleet = fleet();
        for stranger in ["rtx4090", "n3-L40x4", "hpu_x8", "H100-SXM-2-80G"] {
            assert!(
                !fleet.iter().any(|m| m == stranger),
                "{stranger} is in the fleet"
            );
        }
    }
}
