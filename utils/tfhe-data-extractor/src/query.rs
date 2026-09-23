//! Turning the command line into a fetch: which benchmarks the report is about,
//! and the filters the mode decides rather than the user.

use benchmark_spec::{BenchPathKind, BenchmarkMetric};

use crate::cli::{Args, BENCH_DATE_FORMAT, Mode};
use crate::db::{self, PbsKind};
use crate::{archive, profile};

/// The half of a fetch that the mode decides, owned because the query borrows
/// it. What the tables are told, the archive elects.
pub struct QueryInputs {
    machines: Vec<String>,
    /// `None` applies no backend filter: the machine already implies one, and
    /// the column has drifted from the ids.
    backend: Option<String>,
    /// `None` keeps both metrics, which the archive needs since they share a
    /// row.
    metric: Option<BenchmarkMetric>,
    pbs_kind: PbsKind,
    /// Sent as text: the `insert_time` column may be `timestamp` or
    /// `timestamptz`, and a SQL cast copes with either where a typed bind would
    /// have to pick one.
    bench_date: Option<String>,
}

impl QueryInputs {
    pub fn from_args(args: &Args, mode: &Mode) -> Self {
        let bench_date = args
            .bench_date
            .map(|date| date.format(BENCH_DATE_FORMAT).to_string());

        match mode {
            Mode::Archive(_) => Self {
                machines: archive::fleet(),
                backend: None,
                metric: None,
                // The faster parameter set wins on the figures, so there is
                // nothing to pin here either.
                pbs_kind: PbsKind::Any,
                bench_date,
            },
            Mode::Tables => Self {
                machines: vec![
                    args.hardware
                        .clone()
                        .expect("clap requires --hardware outside the archive"),
                ],
                backend: Some(args.backend.to_string()),
                metric: args.bench_type.as_metric(),
                pbs_kind: args.pbs_kind,
                bench_date,
            },
        }
    }

    pub fn query<'a>(&'a self, args: &'a Args, selection: &'a Selection) -> db::FetchQuery<'a> {
        db::FetchQuery {
            machines: &self.machines,
            backend: self.backend.as_deref(),
            branch: &args.branch,
            like_patterns: &selection.like_patterns,
            exclude_non_default: selection.exclude_non_default,
            param_pattern: selection.param_pattern.as_deref(),
            metric: self.metric,
            pbs_kind: self.pbs_kind,
            project_version: args.project_version.as_deref(),
            bench_date: self.bench_date.as_deref(),
            time_span_days: args.time_span_days as i32,
        }
    }
}

/// Which benchmarks the report is about, as SQL-ready patterns.
pub struct Selection {
    /// One exact prefix per bench path (profile), or one broad layer pattern.
    like_patterns: Vec<String>,
    /// `LIKE` pattern pinning the parameter set, if any.
    param_pattern: Option<String>,
    /// Drop the `unchecked_` variants by name. Only needed for the broad
    /// pattern: a profile already spells out the operations it wants.
    exclude_non_default: bool,
}

impl Selection {
    /// A regression profile gives an explicit allow-list of bench paths;
    /// without one, fall back to a broad per-layer pattern. Both are anchored on
    /// the crate prefix, so legacy ids are excluded.
    pub fn from_args(args: &Args, mode: &Mode) -> anyhow::Result<Self> {
        // The archive reads a fixed catalogue of operations, so neither a layer
        // nor a profile decides what it selects: the catalogue does.
        if let Mode::Archive(_) = mode {
            return Ok(Self {
                like_patterns: archive::like_patterns(&args.name_suffix),
                param_pattern: args
                    .param
                    .as_deref()
                    .map(|p| format!("%{}%", db::like_escape(p))),
                exclude_non_default: false,
            });
        }

        let (like_patterns, param_filter, exclude_non_default) = match (
            args.regression_profiles.as_deref(),
            args.regression_selected_profile.as_deref(),
        ) {
            (Some(path), Some(name)) => {
                let profiles = profile::Profiles::load(path)?;
                let selected = profiles.get(args.backend, name)?;
                let resolved = selected.resolve();
                if !resolved.unresolved.is_empty() {
                    eprintln!(
                        "warning: {} profile entries not in the spec: {}",
                        resolved.unresolved.len(),
                        resolved.unresolved.join(", "),
                    );
                }
                (
                    resolved.like_patterns(&args.name_suffix),
                    // `--param` wins over the profile's own filter.
                    args.param
                        .clone()
                        .or_else(|| selected.parameters_filter.clone()),
                    false,
                )
            }
            (Some(_), None) | (None, Some(_)) => {
                anyhow::bail!("--regression-profiles and --regression-selected-profile go together")
            }
            (None, None) => (
                vec![format!(
                    "{}::{}::{}%{}",
                    BenchPathKind::Tfhe,
                    db::like_escape(&args.layer.layer_kind().to_string()),
                    args.bench_subset.path_segment(),
                    db::like_escape(&args.name_suffix),
                )],
                args.param.clone(),
                true,
            ),
        };

        Ok(Self {
            like_patterns,
            param_pattern: param_filter
                .as_deref()
                .map(|p| format!("%{}%", db::like_escape(p))),
            exclude_non_default,
        })
    }

    /// Human-readable lines, shared by `--dry-run` and the no-result report.
    pub fn describe(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(pattern) = &self.param_pattern {
            lines.push(format!("parameter set: {pattern}"));
        }
        lines.push(format!("{} id pattern(s):", self.like_patterns.len()));
        lines.extend(self.like_patterns.iter().map(|p| format!("  {p}")));
        lines
    }
}

/// Lists every filter the query applied, so that a run without a single result
/// says why rather than just how many.
///
/// Reads the query rather than the arguments, so it cannot describe a filter
/// the fetch did not use: the archive overrides four of them, and a report
/// echoing `--bench-type` there would send the reader hunting for the wrong
/// thing.
pub fn report_no_rows(query: &db::FetchQuery<'_>, selection: &Selection) {
    eprintln!("no result matched. Filters applied:");
    eprintln!("  hardware: {}", query.machines.join(", "));
    eprintln!("  backend:  {}", query.backend.unwrap_or("any"));
    eprintln!("  branch:   {}", query.branch);
    match query.metric {
        Some(metric) => eprintln!("  metric:   {metric:?}"),
        None => eprintln!("  metric:   latency and throughput"),
    }
    eprintln!("  pbs kind: {:?}", query.pbs_kind);
    match query.project_version {
        Some(version) => eprintln!("  version:  {version}"),
        None => eprintln!(
            "  window:   {} days back from {}",
            query.time_span_days,
            query.bench_date.unwrap_or("now"),
        ),
    }
    for line in selection.describe() {
        eprintln!("  {line}");
    }
}
