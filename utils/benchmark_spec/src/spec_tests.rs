//! Round-trip tests for the [`BenchmarkSpec`] grammar: every constructor
//! renders an id that parses back to the same string.

use crate::tfhe::hlapi::dex::Dex;
use crate::tfhe::hlapi::erc7984::Erc7984;

use super::*;

struct Ty(&'static str);

impl TypeName for Ty {
    fn type_name(&self) -> String {
        self.0.to_string()
    }
}

#[test]
fn hlapi_cpu_latency() {
    let spec = BenchmarkSpec::new_hlapi_ops(
        HlIntegerOp::Add,
        "PARAM_MESSAGE_2_CARRY_2",
        OperandType::CipherText,
        Some(&Ty("FheUint64")),
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
        Some(&Ty("FheUint128")),
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
        Some(&Ty("FheUint64")),
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
        Some(&Ty("FheUint64")),
        BenchmarkMetric::Latency,
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::hlapi::ops::left_shift::PARAM_MESSAGE_2_CARRY_2::scalar::FheUint64"
    );
}

#[test]
fn hlapi_no_type_name() {
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
        Some(&Ty("64_bits")),
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
        Some(&Ty("64_bits")),
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
        Some(&Ty("64_bits")),
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
        Some(&Ty("8_bits")),
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
        Some(&Ty("FheUint64")),
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
        Some(&Ty("FheUint64")),
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
        Some(&Ty("FheUint64")),
        BenchmarkMetric::PbsCount,
        None,
    );
    assert_eq!(
        spec.to_string(),
        "tfhe::hlapi::dex::swap_request::finalize::pbs_count::PARAM_MESSAGE_2_CARRY_2::FheUint64"
    );
}
