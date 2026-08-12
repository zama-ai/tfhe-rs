//! Bench-id parsing: the inverse of [`BenchmarkSpec`]'s `Display`.

use std::str::FromStr;

use crate::error::SpecParseError;
use crate::{Backend, BenchPath, BenchmarkMetric, BenchmarkSpec, OperandType};

/// Parses a full benchmark id back into a [`BenchmarkSpec`], following the
/// grammar produced by its `Display`:
///
/// ```text
/// {crate::layer::bench}(::{backend})?(::{metric})?::{param}(::scalar)?(::{type})?(::{n}_elements)?
/// ```
impl FromStr for BenchmarkSpec {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // The bench path is the longest `::`-prefix that parses; everything after
        // is the positional trailing (backend / metric / param / …).
        let (bench_crate, trailing) = split_bench_path(s)
            .ok_or_else(|| SpecParseError::Unknown(format!("no known bench path in {s:?}")))?;

        let tokens: Vec<&str> = if trailing.is_empty() {
            Vec::new()
        } else {
            trailing.split("::").collect()
        };
        if tokens.iter().any(|t| t.is_empty()) {
            return Err(SpecParseError::Unknown(format!("empty segment in {s:?}")));
        }

        let mut it = tokens.into_iter().peekable();

        let backend =
            it.next_if(|t| matches!(*t, "cuda" | "hpu"))
                .map_or(Backend::Cpu, |t| match t {
                    "cuda" => Backend::Cuda,
                    _ => Backend::Hpu,
                });

        let operand_type = match it.next_if_eq(&"scalar") {
            Some(_) => OperandType::PlainText,
            None => OperandType::CipherText,
        };

        let metric = if it.next_if_eq(&"throughput").is_some() {
            BenchmarkMetric::Throughput
        } else if it.next_if_eq(&"pbs_count").is_some() {
            BenchmarkMetric::PbsCount
        } else if it.next_if_eq(&"key_size").is_some() {
            BenchmarkMetric::KeySize
        } else {
            BenchmarkMetric::Latency
        };

        // `zk` benches carry no parameter set: `Display` skips the segment
        // altogether, so there is nothing to consume here.
        let param_name = if matches!(bench_crate, BenchPath::Zk(_)) {
            String::new()
        } else {
            it.next()
                .ok_or_else(|| SpecParseError::Unknown(format!("missing param in {s:?}")))?
                .to_string()
        };

        // Remaining tokens: the optional `<n>_elements` marker is always last;
        // anything before it is the type name (which may itself span several
        // `::` segments, e.g. `key_x::value_y`).
        let rest: Vec<&str> = it.collect();
        let (type_toks, num_elements) = match rest.last().and_then(|t| parse_elements(t)) {
            Some(n) => (&rest[..rest.len() - 1], Some(n)),
            None => (&rest[..], None),
        };
        let type_name = (!type_toks.is_empty()).then(|| type_toks.join("::"));

        Ok(BenchmarkSpec {
            bench_crate,
            backend,
            param_name,
            operand_type,
            type_name,
            metric,
            num_elements,
        })
    }
}

/// `<n>_elements` -> `n`.
fn parse_elements(tok: &str) -> Option<usize> {
    tok.strip_suffix("_elements")?.parse().ok()
}

/// Longest `::`-prefix of `s` that parses as a [`BenchPath`], plus the rest.
fn split_bench_path(s: &str) -> Option<(BenchPath, &str)> {
    let mut end = s.len();
    loop {
        let prefix = &s[..end];
        if let Ok(bc) = prefix.parse::<BenchPath>() {
            return Some((bc, s[end..].strip_prefix("::").unwrap_or("")));
        }
        end = prefix.rfind("::")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `zk` ids carry no parameter set, so the id is built from the spec rather
    /// than spelled out.
    #[test]
    fn roundtrip_zk_id() {
        use crate::zk::msm::{MsmBench, MsmFlavor};

        let id = BenchmarkSpec::new_zk_msm(
            MsmBench::G1(MsmFlavor::Bls12_446),
            Backend::Cuda,
            BenchmarkMetric::Latency,
            Some(10),
        )
        .to_string();

        let parsed: BenchmarkSpec = id.parse().unwrap_or_else(|e| panic!("parse {id:?}: {e:?}"));
        assert_eq!(parsed.to_string(), id, "round-trip mismatch");
    }

    #[test]
    fn roundtrip_ids() {
        let ids = [
            "tfhe::shortint::ops::add::PARAM_MESSAGE_2_CARRY_2_KS_PBS",
            "tfhe::hlapi::ops::mul::cuda::PARAM_MESSAGE_2_CARRY_2::FheUint128",
            "tfhe::hlapi::ops::add::hpu::throughput::PARAM_MESSAGE_2_CARRY_2::FheUint64",
            "tfhe::hlapi::ops::left_shift::PARAM_MESSAGE_2_CARRY_2::scalar::FheUint64",
            "tfhe::hlapi::erc7984::transfer::whitepaper::PARAM_MESSAGE_2_CARRY_2::10_elements",
            "tfhe::hlapi::dex::swap_claim::no_cmux::cuda::throughput::PARAM_MESSAGE_2_CARRY_2::FheUint64::10_elements",
            // Multi-segment type names: everything between the param and the
            // trailing `_elements` marker belongs to the type name.
            "tfhe::hlapi::kv_store::get::PARAM_MESSAGE_2_CARRY_2::key_FheUint32::value_FheUint64",
            "tfhe::core_crypto::keyswitch::cuda::PARAM_MESSAGE_2_CARRY_2::64b::gemm::trivial_indices",
        ];
        for id in ids {
            let spec: BenchmarkSpec = id.parse().unwrap_or_else(|e| panic!("parse {id:?}: {e:?}"));
            assert_eq!(spec.to_string(), id, "round-trip mismatch");
        }
    }

    #[test]
    fn unknown_bench_path_is_rejected() {
        // Legacy id (no crate prefix, `integer::` straight away).
        assert!(
            "integer::add::PARAM_MESSAGE_2_CARRY_2::64_bits"
                .parse::<BenchmarkSpec>()
                .is_err()
        );
    }

    /// Ids no `Display` could ever have produced. Each one trips a different
    /// guard, so a regression in any single one of them surfaces here.
    #[test]
    fn malformed_ids_are_rejected() {
        let ids = [
            // Nothing in there resolves to a bench path.
            "",
            "tfhe",
            "zk",
            "tfhe::shortint",
            "tfhe::not_a_layer::add::PARAM_MESSAGE_2_CARRY_2",
            "tfhe::shortint::ops::not_an_op::PARAM_MESSAGE_2_CARRY_2",
            "zk::not_a_layer::G1_bls12_446",
            // Tokens are snake_case, and matched exactly.
            "TFHE::shortint::ops::add::PARAM_MESSAGE_2_CARRY_2",
            "tfhe::Shortint::ops::add::PARAM_MESSAGE_2_CARRY_2",
            // `::` is the only separator, and it never doubles up.
            "::tfhe::shortint::ops::add::PARAM_MESSAGE_2_CARRY_2",
            "tfhe::shortint::ops::add::PARAM_MESSAGE_2_CARRY_2::",
            "tfhe::shortint::ops::add::::PARAM_MESSAGE_2_CARRY_2",
            "tfhe::shortint::ops::add::PARAM_MESSAGE_2_CARRY_2::::FheUint64",
            "tfhe:shortint:ops:add:PARAM_MESSAGE_2_CARRY_2",
            "tfhe/shortint/ops/add/PARAM_MESSAGE_2_CARRY_2",
            // Surrounding whitespace is not trimmed anywhere.
            " tfhe::shortint::ops::add::PARAM_MESSAGE_2_CARRY_2",
            "tfhe::shortint::ops::add ::PARAM_MESSAGE_2_CARRY_2",
            // A bench path on its own is not an id: the parameter set is
            // mandatory for everything but `zk`, and the id stops too early.
            "tfhe::shortint::ops::add",
            "tfhe::hlapi::ops::mul::cuda",
            "tfhe::hlapi::ops::add::hpu::throughput",
        ];
        for id in ids {
            assert!(
                id.parse::<BenchmarkSpec>().is_err(),
                "{id:?} parsed but should not have"
            );
        }
    }
}
