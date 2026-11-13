use benchmark_spec::{BenchmarkMetric, BenchmarkSpec, MeasuredId};
use tfhe_benchmark_parser::model::ParsingFailure;

/// Accepts a full stored name too: wasm CSV rows already carry their statistic.
pub(super) fn declared_metric(test_name: &str) -> Result<BenchmarkMetric, ParsingFailure> {
    test_name
        .parse::<BenchmarkSpec>()
        .or_else(|_| {
            test_name
                .parse::<MeasuredId>()
                .map(|measured| measured.spec)
        })
        .map(|spec| spec.metric())
        .map_err(|err| ParsingFailure {
            source: test_name.to_string(),
            error: format!("id does not follow the benchmark spec: {err}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use benchmark_spec::{KeyKind, ShortintBench, Statistic, measured_name};

    const METRICS: [BenchmarkMetric; 4] = [
        BenchmarkMetric::Latency,
        BenchmarkMetric::Throughput,
        BenchmarkMetric::PbsCount,
        BenchmarkMetric::KeySize,
    ];

    fn id(metric: BenchmarkMetric) -> String {
        BenchmarkSpec::new_shortint(ShortintBench::Keys(KeyKind::Bsk), "PARAM_X", metric)
            .to_string()
    }

    #[test]
    fn every_metric_is_read_back_from_the_id() {
        for metric in METRICS {
            assert_eq!(declared_metric(&id(metric)).ok(), Some(metric));
        }
    }

    #[test]
    fn a_stored_name_is_read_through_its_id() {
        for metric in METRICS {
            let stored = measured_name(&id(metric), Statistic::Mean, Some("chrome"));
            assert_eq!(declared_metric(&stored).ok(), Some(metric));
        }
    }

    #[test]
    fn a_pre_spec_id_is_a_failure() {
        let failure = declared_metric("boolean_key_sizes_DEFAULT_PARAMETERS_ksk").unwrap_err();
        assert_eq!(failure.source, "boolean_key_sizes_DEFAULT_PARAMETERS_ksk");
    }
}
