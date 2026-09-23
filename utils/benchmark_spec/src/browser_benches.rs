//! Bench ids of the browser suite, exported to the JavaScript harness by the
//! `benchmark-spec-js` crate. Kept here so they can be tested natively, that
//! crate being a `cdylib` only.

use crate::{
    Backend, BenchPath, BenchmarkMetric, BenchmarkSpec, CiphertextKind, ComputeLoad, HlapiBench,
    IntegerBench, KeyKind, OperandType, PrecisionTag, Serializable, SpecParseError, TfheLayer,
    TypeTag, ZkPkeBench, ZkPkeConfig, ZkScheme,
};

fn hlapi(bench: HlapiBench) -> BenchPath {
    BenchPath::Tfhe(TfheLayer::Hlapi(bench))
}

fn zk(op: ZkPkeBench) -> BenchPath {
    BenchPath::Tfhe(TfheLayer::Integer(IntegerBench::Zk(op)))
}

fn bench_id(
    bench_path: BenchPath,
    param_name: &str,
    type_tag: Option<TypeTag>,
    metric: BenchmarkMetric,
    num_elements: Option<u64>,
) -> String {
    BenchmarkSpec::new(
        bench_path,
        Backend::Wasm,
        param_name,
        OperandType::CipherText,
        type_tag,
        metric,
        num_elements,
    )
    .to_string()
}

pub fn cpk_gen(param_name: &str, bits: u32) -> String {
    bench_id(
        hlapi(HlapiBench::KeyGen(KeyKind::Cpk)),
        param_name,
        Some(PrecisionTag::Bits(bits).into()),
        BenchmarkMetric::Latency,
        None,
    )
}

pub fn compressed_server_key_gen(param_name: &str) -> String {
    bench_id(
        hlapi(HlapiBench::KeyGen(KeyKind::ServerKeyCompressed)),
        param_name,
        None,
        BenchmarkMetric::Latency,
        None,
    )
}

pub fn compressed_server_key_serialize(param_name: &str) -> String {
    bench_id(
        hlapi(HlapiBench::Serialize(Serializable::ServerKeyCompressed)),
        param_name,
        None,
        BenchmarkMetric::Latency,
        None,
    )
}

pub fn compact_list_encrypt(param_name: &str, bits: u32, num_elements: u64) -> String {
    bench_id(
        hlapi(HlapiBench::Encrypt(CiphertextKind::CompactList)),
        param_name,
        Some(PrecisionTag::Bits(bits).into()),
        BenchmarkMetric::Latency,
        Some(num_elements),
    )
}

pub fn compact_list_serialize(param_name: &str, bits: u32, num_elements: u64) -> String {
    bench_id(
        hlapi(HlapiBench::Serialize(Serializable::CompactList)),
        param_name,
        Some(PrecisionTag::Bits(bits).into()),
        BenchmarkMetric::Latency,
        Some(num_elements),
    )
}

/// `compute_load` is `proof` / `verify`, `scheme` is `v1` / `v2`.
fn zk_pke_tag(
    bits_packed: u32,
    crs_bits: u32,
    compute_load: &str,
    scheme: &str,
) -> Result<TypeTag, SpecParseError> {
    Ok(ZkPkeConfig {
        bits_packed: Some(bits_packed),
        crs_bits,
        compute_load: Some(compute_load.parse::<ComputeLoad>()?),
        scheme: scheme.parse::<ZkScheme>()?,
    }
    .into())
}

pub fn zk_proof(
    param_name: &str,
    bits_packed: u32,
    crs_bits: u32,
    compute_load: &str,
    scheme: &str,
) -> Result<String, SpecParseError> {
    Ok(bench_id(
        zk(ZkPkeBench::Proof),
        param_name,
        Some(zk_pke_tag(bits_packed, crs_bits, compute_load, scheme)?),
        BenchmarkMetric::Latency,
        None,
    ))
}

pub fn zk_proven_list_size(
    param_name: &str,
    bits_packed: u32,
    crs_bits: u32,
    compute_load: &str,
    scheme: &str,
) -> Result<String, SpecParseError> {
    Ok(bench_id(
        zk(ZkPkeBench::ProvenList),
        param_name,
        Some(zk_pke_tag(bits_packed, crs_bits, compute_load, scheme)?),
        BenchmarkMetric::KeySize,
        None,
    ))
}

#[cfg(test)]
mod tests {
    use crate::{MeasuredId, Statistic, measured_name};

    use super::*;

    const PARAM: &str = "V1_8_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128";

    #[test]
    fn ids_are_spelled_as_the_harness_publishes_them() {
        assert_eq!(
            cpk_gen(PARAM, 32),
            "tfhe::hlapi::key_gen::cpk::wasm\
             ::V1_8_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128::32_bits"
        );
        assert_eq!(
            compressed_server_key_gen(PARAM),
            "tfhe::hlapi::key_gen::server_key_compressed::wasm\
             ::V1_8_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128"
        );
        assert_eq!(
            compressed_server_key_serialize(PARAM),
            "tfhe::hlapi::serialize::server_key_compressed::wasm\
             ::V1_8_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128"
        );
        assert_eq!(
            compact_list_encrypt(PARAM, 32, 5),
            "tfhe::hlapi::encrypt::compact_list::wasm\
             ::V1_8_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128::32_bits::5_elements"
        );
        assert_eq!(
            compact_list_serialize(PARAM, 256, 5),
            "tfhe::hlapi::serialize::compact_list::wasm\
             ::V1_8_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128::256_bits::5_elements"
        );
        assert_eq!(
            zk_proof(PARAM, 64, 2048, "proof", "v2").unwrap(),
            "tfhe::integer::zk::proof::wasm::V1_8_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128\
             ::64_bits_packed::2048_bits_crs::compute_load_proof::zk_v2"
        );
        assert_eq!(
            zk_proven_list_size(PARAM, 64, 2048, "proof", "v2").unwrap(),
            "tfhe::integer::zk::proven_list::wasm::key_size\
             ::V1_8_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128\
             ::64_bits_packed::2048_bits_crs::compute_load_proof::zk_v2"
        );
    }

    /// Same suffixing as the harness and the web driver, then read back as
    /// `wasm_benchmarks_parser` does.
    #[test]
    fn stored_names_parse_back_to_the_spec() {
        let ids = [
            cpk_gen(PARAM, 256),
            compressed_server_key_gen(PARAM),
            compressed_server_key_serialize(PARAM),
            compact_list_encrypt(PARAM, 32, 5),
            compact_list_serialize(PARAM, 256, 5),
            zk_proof(PARAM, 64, 2048, "verify", "v2").unwrap(),
            zk_proven_list_size(PARAM, 64, 2048, "verify", "v2").unwrap(),
        ];

        for id in ids {
            for flavour in [None, Some("cross_origin")] {
                let stored = format!("{}_chrome", measured_name(&id, Statistic::Mean, flavour));

                let measured: MeasuredId = stored
                    .parse()
                    .unwrap_or_else(|e| panic!("parsing back {stored:?}: {e:?}"));

                assert_eq!(measured.spec.to_string(), id);
                assert_eq!(measured.spec.param_name(), PARAM);
                assert_eq!(measured.spec.backend(), Backend::Wasm);
            }
        }
    }

    #[test]
    fn free_form_zk_arguments_are_rejected_when_unknown() {
        assert!(zk_proof(PARAM, 64, 2048, "compute_load_proof", "v2").is_err());
        assert!(zk_proof(PARAM, 64, 2048, "proof", "ZKV2").is_err());
    }
}
