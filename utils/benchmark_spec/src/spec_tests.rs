//! Round-trip tests for the [`BenchmarkSpec`] grammar: every constructor
//! renders an id that parses back to the same string.

use crate::tfhe::hlapi::dex::Dex;
use crate::tfhe::hlapi::erc7984::Erc7984;

use super::*;

#[test]
fn hlapi_cpu_latency() {
    let spec = BenchmarkSpec::new_hlapi_ops(
        HlIntegerOp::Add,
        "PARAM_MESSAGE_2_CARRY_2",
        OperandType::CipherText,
        Some(FheType::Uint(64).into()),
        BenchmarkMetric::Latency,
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::hlapi::ops::add::PARAM_MESSAGE_2_CARRY_2::FheUint64"
    );
}

#[test]
fn hlapi_cuda_latency() {
    let spec = BenchmarkSpec::new(
        BenchCrate::Tfhe(TfheLayer::Hlapi(HlapiBench::Ops(HlIntegerOp::Mul))),
        Backend::Cuda,
        "PARAM_MESSAGE_2_CARRY_2",
        OperandType::CipherText,
        Some(FheType::Uint(128).into()),
        BenchmarkMetric::Latency,
        None,
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::hlapi::ops::mul::cuda::PARAM_MESSAGE_2_CARRY_2::FheUint128"
    );
}

#[test]
fn hlapi_hpu_throughput() {
    let spec = BenchmarkSpec::new(
        BenchCrate::Tfhe(TfheLayer::Hlapi(HlapiBench::Ops(HlIntegerOp::Add))),
        Backend::Hpu,
        "PARAM_MESSAGE_2_CARRY_2",
        OperandType::CipherText,
        Some(FheType::Uint(64).into()),
        BenchmarkMetric::Throughput,
        None,
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::hlapi::ops::add::hpu::throughput::PARAM_MESSAGE_2_CARRY_2::FheUint64"
    );
}

#[test]
fn hlapi_scalar() {
    let spec = BenchmarkSpec::new_hlapi_ops(
        HlIntegerOp::LeftShift,
        "PARAM_MESSAGE_2_CARRY_2",
        OperandType::PlainText,
        Some(FheType::Uint(64).into()),
        BenchmarkMetric::Latency,
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::hlapi::ops::left_shift::PARAM_MESSAGE_2_CARRY_2::scalar::FheUint64"
    );
}

#[test]
fn hlapi_no_type_tag() {
    let spec = BenchmarkSpec::new_hlapi_ops(
        HlIntegerOp::Neg,
        "PARAM_MESSAGE_2_CARRY_2",
        OperandType::CipherText,
        None,
        BenchmarkMetric::Latency,
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::hlapi::ops::neg::PARAM_MESSAGE_2_CARRY_2"
    );
}

#[test]
fn integer_ops_latency() {
    let spec = BenchmarkSpec::new_integer_ops(
        IntegerOpBySign::Unsigned(IntegerOp::AddParallelized),
        "PARAM_MESSAGE_2_CARRY_2",
        Some(PrecisionTag::Bits(64).into()),
        BenchmarkMetric::Latency,
        None,
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::integer::ops::unsigned::add_parallelized::PARAM_MESSAGE_2_CARRY_2::64_bits"
    );
}

#[test]
fn integer_ops_signed() {
    let spec = BenchmarkSpec::new_integer_ops(
        IntegerOpBySign::Signed(IntegerOp::MulParallelized),
        "PARAM_MESSAGE_2_CARRY_2",
        Some(PrecisionTag::Bits(64).into()),
        BenchmarkMetric::Latency,
        None,
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::integer::ops::signed::mul_parallelized::PARAM_MESSAGE_2_CARRY_2::64_bits"
    );
}

#[test]
fn integer_ops_throughput_with_num_elements() {
    let spec = BenchmarkSpec::new_integer_ops(
        IntegerOpBySign::Unsigned(IntegerOp::SumCiphertextsParallelized),
        "PARAM_MESSAGE_2_CARRY_2",
        Some(PrecisionTag::Bits(64).into()),
        BenchmarkMetric::Throughput,
        Some(5),
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::integer::ops::unsigned::sum_ciphertexts_parallelized::throughput::PARAM_MESSAGE_2_CARRY_2::64_bits::5_elements"
    );
}

#[test]
fn integer_ops_ilog2_serialization() {
    let spec = BenchmarkSpec::new_integer_ops(
        IntegerOpBySign::Unsigned(IntegerOp::CheckedIlog2Parallelized),
        "PARAM_MESSAGE_2_CARRY_2",
        Some(PrecisionTag::Bits(8).into()),
        BenchmarkMetric::Latency,
        None,
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::integer::ops::unsigned::checked_ilog2_parallelized::PARAM_MESSAGE_2_CARRY_2::8_bits"
    );
}

#[test]
fn hlapi_erc7984_with_num_elements() {
    use crate::tfhe::hlapi::erc7984::{Erc7984, TransferFlavor};

    let spec = BenchmarkSpec::new_hlapi(
        HlapiBench::Erc7984(Erc7984::Transfer(TransferFlavor::Whitepaper)),
        "PARAM_MESSAGE_2_CARRY_2",
        OperandType::CipherText,
        None,
        BenchmarkMetric::Latency,
        Some(10),
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::hlapi::erc7984::transfer::whitepaper::PARAM_MESSAGE_2_CARRY_2::10_elements"
    );
}

#[test]
fn hlapi_erc7984_without_num_elements() {
    use crate::tfhe::hlapi::erc7984::{Erc7984, TransferFlavor};

    let spec = BenchmarkSpec::new_hlapi(
        HlapiBench::Erc7984(Erc7984::Transfer(TransferFlavor::NoCmux)),
        "PARAM_MESSAGE_2_CARRY_2",
        OperandType::CipherText,
        None,
        BenchmarkMetric::Latency,
        None,
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::hlapi::erc7984::transfer::no_cmux::PARAM_MESSAGE_2_CARRY_2"
    );
}

#[test]
fn hlapi_erc7984_num_elements_with_backend() {
    use crate::tfhe::hlapi::erc7984::TransferFlavor;

    let spec = BenchmarkSpec::new(
        BenchCrate::Tfhe(TfheLayer::Hlapi(HlapiBench::Erc7984(Erc7984::Transfer(
            TransferFlavor::Overflow,
        )))),
        Backend::Cuda,
        "PARAM_MESSAGE_2_CARRY_2",
        OperandType::CipherText,
        None,
        BenchmarkMetric::Latency,
        Some(5),
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::hlapi::erc7984::transfer::overflow::cuda::PARAM_MESSAGE_2_CARRY_2::5_elements"
    );
}

#[test]
fn hlapi_erc7984_num_elements_with_throughput() {
    use crate::tfhe::hlapi::erc7984::{Erc7984, TransferFlavor};

    let spec = BenchmarkSpec::new_hlapi(
        HlapiBench::Erc7984(Erc7984::Transfer(TransferFlavor::Safe)),
        "PARAM_MESSAGE_2_CARRY_2",
        OperandType::CipherText,
        None,
        BenchmarkMetric::Throughput,
        Some(20),
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::hlapi::erc7984::transfer::safe::throughput::PARAM_MESSAGE_2_CARRY_2::20_elements"
    );
}

#[test]
fn hlapi_erc7984_with_pbs_count() {
    use crate::tfhe::hlapi::erc7984::{Erc7984, TransferFlavor};

    let spec = BenchmarkSpec::new_hlapi(
        HlapiBench::Erc7984(Erc7984::Transfer(TransferFlavor::Safe)),
        "PARAM_MESSAGE_2_CARRY_2",
        OperandType::CipherText,
        None,
        BenchmarkMetric::PbsCount,
        None,
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::hlapi::erc7984::transfer::safe::pbs_count::PARAM_MESSAGE_2_CARRY_2"
    );
}

#[test]
fn hlapi_dex_swap_request_latency() {
    use crate::tfhe::hlapi::dex::{Dex, DexFlavor};

    let spec = BenchmarkSpec::new_hlapi(
        HlapiBench::Dex(Dex::SwapRequest(DexFlavor::Whitepaper)),
        "PARAM_MESSAGE_2_CARRY_2",
        OperandType::CipherText,
        Some(FheType::Uint(64).into()),
        BenchmarkMetric::Latency,
        None,
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::hlapi::dex::swap_request::whitepaper::PARAM_MESSAGE_2_CARRY_2::FheUint64"
    );
}

#[test]
fn hlapi_dex_swap_claim_throughput_with_elements() {
    use crate::tfhe::hlapi::dex::DexFlavor;

    let spec = BenchmarkSpec::new(
        BenchCrate::Tfhe(TfheLayer::Hlapi(HlapiBench::Dex(Dex::SwapClaim(
            DexFlavor::NoCmux,
        )))),
        Backend::Cuda,
        "PARAM_MESSAGE_2_CARRY_2",
        OperandType::CipherText,
        Some(FheType::Uint(64).into()),
        BenchmarkMetric::Throughput,
        Some(10),
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::hlapi::dex::swap_claim::no_cmux::cuda::throughput::PARAM_MESSAGE_2_CARRY_2::FheUint64::10_elements"
    );
}

#[test]
fn hlapi_dex_with_pbs_count() {
    use crate::tfhe::hlapi::dex::{Dex, DexFlavor};

    let spec = BenchmarkSpec::new_hlapi(
        HlapiBench::Dex(Dex::SwapRequest(DexFlavor::Finalize)),
        "PARAM_MESSAGE_2_CARRY_2",
        OperandType::CipherText,
        Some(FheType::Uint(64).into()),
        BenchmarkMetric::PbsCount,
        None,
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::hlapi::dex::swap_request::finalize::pbs_count::PARAM_MESSAGE_2_CARRY_2::FheUint64"
    );
}

/// The gates keep their ids now that the boolean layer also carries key sizes.
#[test]
fn boolean_gate_and_key_size() {
    let gate = BenchmarkSpec::new_boolean(
        BooleanBench::And,
        "DEFAULT_PARAMETERS",
        BenchmarkMetric::Latency,
    );
    assert_eq!(gate.to_string(), "tfhe::boolean::and::DEFAULT_PARAMETERS");

    let key = BenchmarkSpec::new_boolean(
        BooleanBench::Keys(KeyKind::Ksk),
        "DEFAULT_PARAMETERS",
        BenchmarkMetric::KeySize,
    );
    assert_eq!(
        key.to_string(),
        "tfhe::boolean::keys::ksk::key_size::DEFAULT_PARAMETERS"
    );
}

#[test]
fn shortint_key_size() {
    let spec = BenchmarkSpec::new_shortint(
        ShortintBench::Keys(KeyKind::BskCompressed),
        "PARAM_MESSAGE_2_CARRY_2",
        BenchmarkMetric::KeySize,
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::shortint::keys::bsk_compressed::key_size::PARAM_MESSAGE_2_CARRY_2"
    );
}

/// A ciphertext size, sized by how many values the list holds.
#[test]
fn hlapi_ciphertext_size() {
    let spec = BenchmarkSpec::new_hlapi(
        HlapiBench::Ciphertexts(CiphertextKind::CompactList),
        "PARAM_MESSAGE_2_CARRY_2",
        OperandType::CipherText,
        Some(PrecisionTag::Bits(32).into()),
        BenchmarkMetric::KeySize,
        Some(5),
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::hlapi::ciphertexts::compact_list::key_size::PARAM_MESSAGE_2_CARRY_2::32_bits::5_elements"
    );
}

/// A bench with no op enum under it, and a tag spanning two segments.
#[test]
fn hlapi_bitonic_shuffle() {
    let spec = BenchmarkSpec::new(
        BenchCrate::Tfhe(TfheLayer::Hlapi(HlapiBench::BitonicShuffle)),
        Backend::Cuda,
        "PARAM_MESSAGE_2_CARRY_2",
        OperandType::CipherText,
        Some(
            ShuffleConfig {
                value_bits: 64,
                key_bits: 16,
            }
            .into(),
        ),
        BenchmarkMetric::Latency,
        Some(16),
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::hlapi::bitonic_shuffle::cuda::PARAM_MESSAGE_2_CARRY_2::64_bits::key_16_bits::16_elements"
    );
}

/// `Display` writes the trailing segments in a fixed order and `FromStr`
/// consumes them in the same one, with nothing tying the two together.
#[test]
fn trailing_segments_round_trip_in_every_combination() {
    let bench_crate = BenchCrate::Tfhe(TfheLayer::Integer(IntegerBench::Ops(
        IntegerOpBySign::Unsigned(IntegerOp::AddParallelized),
    )));

    // One plain tag, one spanning several `::` segments, one that could be
    // mistaken for the trailing `_elements` marker.
    let tags = [
        None,
        Some(TypeTag::Type(FheType::Uint(64))),
        Some(TypeTag::KeyValue {
            key: FheType::Uint(32),
            value: FheType::Uint(64),
        }),
        Some(TypeTag::CudaKeyswitch(CudaKeyswitchConfig::new(
            32, None, None,
        ))),
        Some(TypeTag::Shuffle(ShuffleConfig {
            value_bits: 64,
            key_bits: 16,
        })),
    ];

    for backend in [Backend::Cpu, Backend::Cuda, Backend::Hpu] {
        for metric in [
            BenchmarkMetric::Latency,
            BenchmarkMetric::Throughput,
            BenchmarkMetric::PbsCount,
            BenchmarkMetric::KeySize,
        ] {
            for operand_type in [OperandType::CipherText, OperandType::PlainText] {
                for tag in &tags {
                    for num_elements in [None, Some(4)] {
                        let spec = BenchmarkSpec::new(
                            bench_crate,
                            backend,
                            "PARAM_MESSAGE_2_CARRY_2_KS_PBS",
                            operand_type,
                            *tag,
                            metric,
                            num_elements,
                        );

                        let id = spec.to_string();
                        let reparsed: BenchmarkSpec = id
                            .parse()
                            .unwrap_or_else(|e| panic!("parsing back {id:?}: {e:?}"));
                        assert_eq!(reparsed.to_string(), id, "round-trip mismatch");
                    }
                }
            }
        }
    }
}
