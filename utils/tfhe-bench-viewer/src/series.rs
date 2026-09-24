//! A curve on the plots: a path picked in the tree, then narrowed one
//! dimension at a time. It owns no data; the store does.
//!
//! Every dimension follows the same rule: `None` means "whatever the data
//! offers first", a value picked by hand is kept until it stops existing. So a
//! series is never empty because of a stale choice, and the dropdowns never
//! offer a combination that has no results.

use benchmark_spec::{Backend, BenchPath, BenchmarkMetric, BenchmarkSpec, OperandType};

use crate::data::{Point, Store};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Series {
    /// The chosen bench path, segment by segment. A raw series holds the whole
    /// stored id as its single segment.
    pub segments: Vec<String>,
    /// Whether the id behind this series parsed. A raw one is not in the tree,
    /// so it is not picked but named, and nothing about it can be inferred.
    pub raw: bool,
    pub backend: Option<Backend>,
    pub metric: Option<BenchmarkMetric>,
    pub machine: Option<String>,
    pub bits: Option<i64>,
    pub params: Option<String>,
    pub variant: Option<String>,
    pub visible: bool,
    /// Fixed at creation and never reassigned: the colour belongs to the
    /// series, not to its rank in the list.
    pub color_slot: usize,
}

/// What each dimension currently resolves to, and what it could resolve to.
///
/// Built in one pass, because each list is the set of values available *under
/// the dimensions above it*: the machines of this backend, the sizes of this
/// machine, and so on.
pub struct Options {
    /// Empty for a raw series: an unparsed id names no backend.
    pub backends: Vec<Backend>,
    /// Both metrics for a raw series, since the data cannot say which one it
    /// is and the reader has to declare it.
    pub metrics: Vec<BenchmarkMetric>,
    pub machines: Vec<String>,
    pub bits: Vec<i64>,
    pub params: Vec<String>,
    pub variants: Vec<String>,
    pub resolved: Resolved,
    /// How many stored results the resolved combination holds, which is the
    /// number of points the curve will draw.
    pub matching: usize,
}

#[derive(Clone)]
pub struct Resolved {
    /// `None` for a raw series.
    pub backend: Option<Backend>,
    pub metric: BenchmarkMetric,
    /// False when the metric is a declaration rather than a reading. Which of
    /// the two plots a raw series lands in is then a choice, and one the label
    /// says out loud.
    pub metric_known: bool,
    pub machine: String,
    pub bits: i64,
    pub params: String,
    pub variant: String,
}

/// One plotted point.
pub struct Sample {
    pub at: f64,
    pub value: f64,
}

impl Series {
    /// A series over an id the grammar does not parse. Its value is still a
    /// value, so it is still plottable; only its name stays opaque.
    pub fn raw(id: String, color_slot: usize) -> Self {
        Self {
            segments: vec![id],
            raw: true,
            ..Self::new(color_slot)
        }
    }

    pub fn new(color_slot: usize) -> Self {
        Self {
            segments: Vec::new(),
            raw: false,
            backend: None,
            metric: None,
            machine: None,
            bits: None,
            params: None,
            variant: None,
            visible: true,
            color_slot,
        }
    }

    pub fn path(&self) -> String {
        self.segments.join("::")
    }

    /// A series over a path walked down the tree.
    pub fn picked(segments: Vec<String>, color_slot: usize) -> Self {
        Self {
            segments,
            ..Self::new(color_slot)
        }
    }

    /// The id prefix the stored results share, spelled by the spec rather than
    /// by this crate. A raw series has nothing to rebuild: its name is the
    /// stored string itself.
    pub fn id_prefix(&self, resolved: &Resolved) -> String {
        let path = self.path();
        match path.parse::<BenchPath>() {
            Ok(bench_path) => BenchmarkSpec::new(
                bench_path,
                resolved.backend.unwrap_or(Backend::Cpu),
                &resolved.params,
                OperandType::CipherText,
                None,
                resolved.metric,
                None,
            )
            .to_string(),
            Err(_) => path,
        }
    }

    pub fn points<'a>(&self, store: &'a Store) -> &'a [Point] {
        match store.points.get(&self.path()) {
            Some(points) => points.as_slice(),
            None => &[],
        }
    }

    /// Narrows the points one dimension at a time, collecting what each level
    /// had to offer on the way down. `None` when the path holds no result at
    /// all, which is the only case the interface cannot narrow out of.
    pub fn options(&self, store: &Store) -> Option<Options> {
        let mut points: Vec<&Point> = self.points(store).iter().collect();
        if points.is_empty() {
            return None;
        }

        // An unparsed id names no backend, so there is nothing to narrow on and
        // nothing to offer.
        let backends: Vec<Backend> = distinct(&points, |p| p.backend)
            .into_iter()
            .flatten()
            .collect();
        let backend = (!backends.is_empty()).then(|| pick(self.backend, &backends));
        points.retain(|p| p.backend == backend);

        let known: Vec<BenchmarkMetric> = distinct(&points, |p| p.metric)
            .into_iter()
            .flatten()
            .collect();
        let metric_known = !known.is_empty();
        // With nothing in the name to read it from, which plot the series
        // belongs in becomes the reader's call, so both are offered.
        let metrics = if metric_known {
            known
        } else {
            vec![BenchmarkMetric::Latency, BenchmarkMetric::Throughput]
        };
        let metric = pick(self.metric, &metrics);
        if metric_known {
            points.retain(|p| p.metric == Some(metric));
        }

        let (machines, machine) = narrow(&mut points, self.machine.clone(), |p| p.machine.clone());
        let (bits, bit_size) = narrow(&mut points, self.bits, |p| p.bits);
        let (params, param_set) = narrow(&mut points, self.params.clone(), |p| p.params.clone());
        let (variants, variant) = narrow(&mut points, self.variant.clone(), |p| p.variant.clone());

        Some(Options {
            backends,
            metrics,
            machines,
            bits,
            params,
            variants,
            resolved: Resolved {
                backend,
                metric,
                metric_known,
                machine,
                bits: bit_size,
                params: param_set,
                variant,
            },
            matching: points.len(),
        })
    }

    /// The curve itself: one point per insertion, oldest first.
    pub fn curve(&self, store: &Store, resolved: &Resolved) -> Vec<Sample> {
        let mut samples: Vec<Sample> = self
            .points(store)
            .iter()
            .filter(|p| {
                p.backend == resolved.backend
                    && (!resolved.metric_known || p.metric == Some(resolved.metric))
                    && p.machine == resolved.machine
                    && p.bits == resolved.bits
                    && p.params == resolved.params
                    && p.variant == resolved.variant
            })
            .map(|p| Sample {
                at: p.at,
                value: p.value,
            })
            .collect();

        samples.sort_by(|a, b| a.at.total_cmp(&b.at));
        samples
    }
}

/// Settles one dimension: what the surviving points offer, what the series
/// settles on, and the points that hold it.
fn narrow<T, F>(points: &mut Vec<&Point>, chosen: Option<T>, of: F) -> (Vec<T>, T)
where
    T: Clone + Ord,
    F: Fn(&Point) -> T,
{
    let mut available = distinct(points, &of);
    available.sort();
    let picked = pick(chosen, &available);
    points.retain(|point| of(point) == picked);
    (available, picked)
}

/// The values a dimension takes, without repeats. Sorting is left to the
/// caller: the spec's own enums have no meaningful order, unlike a machine name
/// or a size.
fn distinct<T, F>(points: &[&Point], mut of: F) -> Vec<T>
where
    T: PartialEq,
    F: FnMut(&Point) -> T,
{
    let mut values: Vec<T> = Vec::new();
    for point in points {
        let value = of(*point);
        if !values.contains(&value) {
            values.push(value);
        }
    }
    values
}

/// The choice, when the data still holds it; the first option otherwise.
///
/// `available` is never empty here: it was built from the points that survived
/// the dimensions above.
fn pick<T: PartialEq + Clone>(chosen: Option<T>, available: &[T]) -> T {
    match chosen {
        Some(value) if available.contains(&value) => value,
        _ => available[0].clone(),
    }
}
