//! Composes and parses the name of a stored benchmark result:
//!
//! ```text
//! {bench_id}_{statistic}(_{variant})?
//! ```

use std::fmt;
use std::str::FromStr;

use strum::{Display, EnumString};

use crate::BenchmarkSpec;
use crate::error::SpecParseError;

/// Which statistic of a criterion estimate a stored value holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum Statistic {
    Mean,
    StdDev,
}

impl Statistic {
    fn marker(self) -> &'static str {
        match self {
            Self::Mean => "_mean",
            Self::StdDev => "_std_dev",
        }
    }
}

/// Composes the name of a stored result.
///
/// Takes the bench id as a string, not a [`BenchmarkSpec`]: results are written
/// for every benchmark, including those whose id predates the spec grammar.
pub fn measured_name(bench_id: &str, statistic: Statistic, variant: Option<&str>) -> String {
    let mut name = format!("{bench_id}{}", statistic.marker());
    if let Some(variant) = variant.filter(|v| !v.is_empty()) {
        name.push('_');
        name.push_str(variant);
    }
    name
}

/// A stored result name, parsed back into its parts.
#[derive(Debug)]
pub struct MeasuredId {
    pub spec: BenchmarkSpec,
    pub statistic: Statistic,
    /// Run flavour: `avx512`, `regression`, or a compound string built by a
    /// workflow. Free-form; only ever handled as a whole.
    pub variant: Option<String>,
}

impl fmt::Display for MeasuredId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&measured_name(
            &self.spec.to_string(),
            self.statistic,
            self.variant.as_deref(),
        ))
    }
}

impl FromStr for MeasuredId {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (bench_id, statistic, rest) = split_statistic(s)
            .ok_or_else(|| SpecParseError::Unknown(format!("no statistic in {s:?}")))?;

        Ok(Self {
            spec: bench_id.parse()?,
            statistic,
            variant: rest.strip_prefix('_').and_then(|variant| {
                if variant.is_empty() {
                    None
                } else {
                    Some(variant.to_string())
                }
            }),
        })
    }
}

/// Splits a stored name around its statistic marker.
///
/// Uses the first marker, not the last: parameter aliases are uppercase so they
/// cannot hold one, but a variant can (`_chrome_mean`) and belongs to the tail.
fn split_statistic(s: &str) -> Option<(&str, Statistic, &str)> {
    [Statistic::Mean, Statistic::StdDev]
        .into_iter()
        .filter_map(|statistic| s.find(statistic.marker()).map(|at| (at, statistic)))
        .min_by_key(|(at, _)| *at)
        .map(|(at, statistic)| (&s[..at], statistic, &s[at + statistic.marker().len()..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let names = [
            "tfhe::shortint::ops::add::PARAM_MESSAGE_2_CARRY_2_KS_PBS_mean_avx512",
            "tfhe::shortint::ops::add::PARAM_MESSAGE_2_CARRY_2_KS_PBS_std_dev_avx512",
            // No variant: the parser's default is an empty suffix (`cli.rs:50`).
            "tfhe::hlapi::ops::add::PARAM_MESSAGE_2_CARRY_2::FheUint64_mean",
            // A workflow-built compound variant stays opaque.
            "tfhe::hlapi::ops::add::PARAM_MESSAGE_2_CARRY_2::FheUint64_mean_batch_size_4-schedule_fifo",
        ];
        for name in names {
            let id: MeasuredId = name
                .parse()
                .unwrap_or_else(|e| panic!("parse {name:?}: {e:?}"));
            assert_eq!(id.to_string(), name, "round-trip mismatch");
        }
    }

    /// `marker()` is a hand-written mirror of the strum name, so that splitting
    /// needs no allocation. This keeps the two from drifting.
    #[test]
    fn markers_match_the_strum_names() {
        for statistic in [Statistic::Mean, Statistic::StdDev] {
            assert_eq!(statistic.marker(), format!("_{statistic}"));
        }
    }

    #[test]
    fn a_variant_holding_a_marker_stays_in_the_tail() {
        let id: MeasuredId = "tfhe::shortint::ops::add::PARAM_2_mean_chrome_mean"
            .parse()
            .unwrap();
        assert_eq!(id.statistic, Statistic::Mean);
        assert_eq!(id.variant.as_deref(), Some("chrome_mean"));
    }
}
