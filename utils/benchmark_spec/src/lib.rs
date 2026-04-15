mod backend;
mod bench_crate;
pub mod tfhe;
mod traits;

pub use backend::Backend;
pub use bench_crate::BenchCrate;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::{env, fmt};
pub use tfhe::hlapi::HlapiBench;
pub use tfhe::{CoreCryptoBench, HlIntegerOp, ShortintBench, TfheLayer};

use crate::tfhe::hlapi::dex::Dex;
use crate::tfhe::hlapi::erc7984::Erc7984;

pub struct BenchmarkTestResult {
    file: File,
}

impl BenchmarkTestResult {
    pub fn new(file_name: &str) -> Self {
        let file_path = Path::new(file_name);
        Self::from_path(file_path)
    }

    pub fn from_path(path: &Path) -> Self {
        if !path.exists() {
            File::create(path).expect("cannot create benchmark result file");
        }
        let file = OpenOptions::new()
            .append(true)
            .open(path)
            .expect("cannot open benchmark result file");
        Self { file }
    }

    pub fn write_result(&mut self, name: &str, value: usize) {
        let line = format!("{name},{value}\n");
        let error_message = format!("cannot write {name} result into file");
        self.file.write_all(line.as_bytes()).expect(&error_message);
    }
}

pub trait TypeName {
    fn type_name(&self) -> String;
}

pub struct TypedKeyValue<'a> {
    key: &'a str,
    value: &'a str,
}

impl<'a> TypedKeyValue<'a> {
    pub fn new(key: &'a str, value: &'a str) -> Self {
        Self { key, value }
    }
}

impl TypeName for TypedKeyValue<'_> {
    fn type_name(&self) -> String {
        format!("key_{}::value_{}", self.key, self.value)
    }
}

impl TypeName for str {
    fn type_name(&self) -> String {
        self.to_string()
    }
}

#[derive(Serialize)]
pub enum OperandType {
    CipherText,
    PlainText,
}

impl OperandType {
    pub fn is_scalar(&self) -> bool {
        matches!(self, OperandType::PlainText)
    }
}

/// Benchmark type driven by the `__TFHE_RS_BENCH_TYPE` environment variable.
///
/// Only `Latency` and `Throughput` can come from the environment; `PbsCount`
/// is hard-coded at specific call sites.
#[derive(Clone, Copy, Serialize)]
pub enum BenchmarkType {
    Latency,
    Throughput,
}

/// The metric being recorded by a benchmark, used in [`BenchmarkSpec`].
#[derive(Clone, Copy, Serialize)]
pub enum BenchmarkMetric {
    Latency,
    Throughput,
    PbsCount,
}

impl From<BenchmarkType> for BenchmarkMetric {
    fn from(ct: BenchmarkType) -> Self {
        match ct {
            BenchmarkType::Latency => BenchmarkMetric::Latency,
            BenchmarkType::Throughput => BenchmarkMetric::Throughput,
        }
    }
}

impl BenchmarkType {
    /// Retrieves the benchmark type from the environment variable `__TFHE_RS_BENCH_TYPE`.
    fn from_env() -> Result<Self, String> {
        let raw_value = env::var("__TFHE_RS_BENCH_TYPE").unwrap_or("latency".to_string());
        match raw_value.to_lowercase().as_str() {
            "latency" => Ok(BenchmarkType::Latency),
            "throughput" => Ok(BenchmarkType::Throughput),
            _ => Err(format!("benchmark type '{raw_value}' is not supported")),
        }
    }
}

/// Retrieves the benchmark type from the environment variable `__TFHE_RS_BENCH_TYPE`.
///
/// Returns only `Latency` or `Throughput` — never `PbsCount`.
pub fn get_bench_type() -> &'static BenchmarkType {
    use std::sync::OnceLock;
    static BENCH_TYPE: OnceLock<BenchmarkType> = OnceLock::new();
    BENCH_TYPE.get_or_init(|| BenchmarkType::from_env().unwrap())
}

/// Enforces the naming convention for benchmark IDs.
///
/// ```text
/// {crate}::{layer}::{bench}::{op}(::{backend})?(::{benchmark_type})?::{param}(::scalar)?(::{type})?(::{num_elements}_elements)?
/// ```
///
/// `param_name` and `type_name` are kept as `&str` because their values
/// are generated dynamically: `type_name` comes from `stringify!()` in
/// bench macros, and `param_name` comes from `NamedParam::name()` at runtime.
pub struct BenchmarkSpec<'a, T: TypeName + ?Sized> {
    pub bench_crate: BenchCrate,
    pub backend: Backend,
    pub param_name: &'a str,
    pub operand_type: &'a OperandType,
    pub type_name: Option<&'a T>,
    pub bench_type: BenchmarkMetric,
    pub num_elements: Option<usize>,
}

impl<'a, T: TypeName + ?Sized> BenchmarkSpec<'a, T> {
    pub fn new(
        bench_crate: BenchCrate,
        backend: Backend,
        param_name: &'a str,
        operand_type: &'a OperandType,
        type_name: Option<&'a T>,
        bench_type: impl Into<BenchmarkMetric>,
        num_elements: Option<usize>,
    ) -> Self {
        Self {
            bench_crate,
            backend,
            param_name,
            operand_type,
            type_name,
            bench_type: bench_type.into(),
            num_elements,
        }
    }

    pub fn new_hlapi_ops(
        hlapi_op: HlIntegerOp,
        param_name: &'a str,
        operand_type: &'a OperandType,
        type_name: Option<&'a T>,
        bench_type: impl Into<BenchmarkMetric>,
        backend: Backend,
    ) -> Self {
        Self {
            bench_crate: BenchCrate::Tfhe(TfheLayer::Hlapi(HlapiBench::Ops(hlapi_op))),
            backend,
            param_name,
            operand_type,
            type_name,
            bench_type: bench_type.into(),
            num_elements: None,
        }
    }

    pub fn new_hlapi_erc7984(
        hlapi_erc7984_op: Erc7984,
        param_name: &'a str,
        operand_type: &'a OperandType,
        type_name: Option<&'a T>,
        bench_type: impl Into<BenchmarkMetric>,
        backend: Backend,
        num_elements: Option<usize>,
    ) -> Self {
        Self {
            bench_crate: BenchCrate::Tfhe(TfheLayer::Hlapi(HlapiBench::Erc7984(hlapi_erc7984_op))),
            backend,
            param_name,
            operand_type,
            type_name,
            bench_type: bench_type.into(),
            num_elements,
        }
    }
    pub fn new_hlapi_dex(
        hlapi_dex: Dex,
        param_name: &'a str,
        operand_type: &'a OperandType,
        type_name: Option<&'a T>,
        bench_type: impl Into<BenchmarkMetric>,
        backend: Backend,
        num_elements: Option<usize>,
    ) -> Self {
        Self {
            bench_crate: BenchCrate::Tfhe(TfheLayer::Hlapi(HlapiBench::Dex(hlapi_dex))),
            backend,
            param_name,
            operand_type,
            type_name,
            bench_type: bench_type.into(),
            num_elements,
        }
    }

    pub fn new_hlapi(
        hlapi_bench: HlapiBench,
        param_name: &'a str,
        operand_type: &'a OperandType,
        type_name: Option<&'a T>,
        bench_type: impl Into<BenchmarkMetric>,
        backend: Backend,
        num_elements: Option<usize>,
    ) -> Self {
        Self {
            bench_crate: BenchCrate::Tfhe(TfheLayer::Hlapi(hlapi_bench)),
            backend,
            param_name,
            operand_type,
            type_name,
            bench_type: bench_type.into(),
            num_elements,
        }
    }

    pub fn new_shortint(
        shortint_bench: ShortintBench,
        param_name: &'a str,
        bench_type: impl Into<BenchmarkMetric>,
        backend: Backend,
    ) -> Self {
        Self {
            bench_crate: BenchCrate::Tfhe(TfheLayer::Shortint(shortint_bench)),
            backend,
            param_name,
            operand_type: &OperandType::CipherText,
            type_name: None,
            bench_type: bench_type.into(),
            num_elements: None,
        }
    }

    pub fn new_core_crypto(
        core_crypto_bench: CoreCryptoBench,
        param_name: &'a str,
        bench_type: impl Into<BenchmarkMetric>,
        backend: Backend,
    ) -> Self {
        Self {
            bench_crate: BenchCrate::Tfhe(TfheLayer::CoreCrypto(core_crypto_bench)),
            backend,
            param_name,
            operand_type: &OperandType::CipherText,
            type_name: None,
            bench_type: bench_type.into(),
            num_elements: None,
        }
    }
}

impl<T: TypeName + ?Sized> fmt::Display for BenchmarkSpec<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.bench_crate.fmt_crate(f)?;
        if !matches!(self.backend, Backend::Cpu) {
            write!(f, "::{}", self.backend)?;
        }
        match self.bench_type {
            BenchmarkMetric::Throughput => write!(f, "::throughput")?,
            BenchmarkMetric::PbsCount => write!(f, "::pbs_count")?,
            BenchmarkMetric::Latency => {}
        }
        write!(f, "::{}", self.param_name)?;
        if self.operand_type.is_scalar() {
            write!(f, "::scalar")?;
        }
        if let Some(type_name) = self.type_name {
            write!(f, "::{}", type_name.type_name())?;
        }
        if let Some(num_elements) = self.num_elements {
            write!(f, "::{num_elements}_elements")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hlapi_cpu_latency() {
        let spec = BenchmarkSpec::new(
            BenchCrate::Tfhe(TfheLayer::Hlapi(HlapiBench::Ops(HlIntegerOp::Add))),
            Backend::Cpu,
            "PARAM_MESSAGE_2_CARRY_2",
            &OperandType::CipherText,
            Some("FheUint64"),
            BenchmarkMetric::Latency,
            None,
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
            &OperandType::CipherText,
            Some("FheUint128"),
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
            &OperandType::CipherText,
            Some("FheUint64"),
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
        let spec = BenchmarkSpec::new(
            BenchCrate::Tfhe(TfheLayer::Hlapi(HlapiBench::Ops(HlIntegerOp::LeftShift))),
            Backend::Cpu,
            "PARAM_MESSAGE_2_CARRY_2",
            &OperandType::PlainText,
            Some("FheUint64"),
            BenchmarkMetric::Latency,
            None,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::ops::left_shift::PARAM_MESSAGE_2_CARRY_2::scalar::FheUint64"
        );
    }

    #[test]
    fn hlapi_no_type_name() {
        let spec = BenchmarkSpec::<str>::new(
            BenchCrate::Tfhe(TfheLayer::Hlapi(HlapiBench::Ops(HlIntegerOp::Neg))),
            Backend::Cpu,
            "PARAM_MESSAGE_2_CARRY_2",
            &OperandType::CipherText,
            None,
            BenchmarkMetric::Latency,
            None,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::ops::neg::PARAM_MESSAGE_2_CARRY_2"
        );
    }

    #[test]
    fn hlapi_erc7984_with_num_elements() {
        use crate::tfhe::hlapi::erc7984::TransferOp;

        let spec = BenchmarkSpec::<str>::new_hlapi_erc7984(
            Erc7984::Transfer(TransferOp::Whitepaper),
            "PARAM_MESSAGE_2_CARRY_2",
            &OperandType::CipherText,
            None,
            BenchmarkMetric::Latency,
            Backend::Cpu,
            Some(10),
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::erc7984::transfer::whitepaper::PARAM_MESSAGE_2_CARRY_2::10_elements"
        );
    }

    #[test]
    fn hlapi_erc7984_without_num_elements() {
        use crate::tfhe::hlapi::erc7984::TransferOp;

        let spec = BenchmarkSpec::<str>::new_hlapi_erc7984(
            Erc7984::Transfer(TransferOp::NoCmux),
            "PARAM_MESSAGE_2_CARRY_2",
            &OperandType::CipherText,
            None,
            BenchmarkMetric::Latency,
            Backend::Cpu,
            None,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::erc7984::transfer::no_cmux::PARAM_MESSAGE_2_CARRY_2"
        );
    }

    #[test]
    fn hlapi_erc7984_num_elements_with_backend() {
        use crate::tfhe::hlapi::erc7984::TransferOp;

        let spec = BenchmarkSpec::<str>::new_hlapi_erc7984(
            Erc7984::Transfer(TransferOp::Overflow),
            "PARAM_MESSAGE_2_CARRY_2",
            &OperandType::CipherText,
            None,
            BenchmarkMetric::Latency,
            Backend::Cuda,
            Some(5),
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::erc7984::transfer::overflow::cuda::PARAM_MESSAGE_2_CARRY_2::5_elements"
        );
    }

    #[test]
    fn hlapi_erc7984_num_elements_with_throughput() {
        use crate::tfhe::hlapi::erc7984::TransferOp;

        let spec = BenchmarkSpec::<str>::new_hlapi_erc7984(
            Erc7984::Transfer(TransferOp::Safe),
            "PARAM_MESSAGE_2_CARRY_2",
            &OperandType::CipherText,
            None,
            BenchmarkMetric::Throughput,
            Backend::Cpu,
            Some(20),
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::erc7984::transfer::safe::throughput::PARAM_MESSAGE_2_CARRY_2::20_elements"
        );
    }

    #[test]
    fn hlapi_erc7984_with_pbs_count() {
        use crate::tfhe::hlapi::erc7984::TransferOp;

        let spec = BenchmarkSpec::<str>::new_hlapi_erc7984(
            Erc7984::Transfer(TransferOp::Safe),
            "PARAM_MESSAGE_2_CARRY_2",
            &OperandType::CipherText,
            None,
            BenchmarkMetric::PbsCount,
            Backend::Cpu,
            None,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::erc7984::transfer::safe::pbs_count::PARAM_MESSAGE_2_CARRY_2"
        );
    }

    #[test]
    fn hlapi_dex_swap_request_latency() {
        use crate::tfhe::hlapi::dex::DexOp;

        let spec = BenchmarkSpec::new_hlapi_dex(
            Dex::SwapRequest(DexOp::Whitepaper),
            "PARAM_MESSAGE_2_CARRY_2",
            &OperandType::CipherText,
            Some("FheUint64"),
            BenchmarkMetric::Latency,
            Backend::Cpu,
            None,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::dex::swap_request::whitepaper::PARAM_MESSAGE_2_CARRY_2::FheUint64"
        );
    }

    #[test]
    fn hlapi_dex_swap_claim_throughput_with_elements() {
        use crate::tfhe::hlapi::dex::DexOp;

        let spec = BenchmarkSpec::new_hlapi_dex(
            Dex::SwapClaim(DexOp::NoCmux),
            "PARAM_MESSAGE_2_CARRY_2",
            &OperandType::CipherText,
            Some("FheUint64"),
            BenchmarkMetric::Throughput,
            Backend::Cuda,
            Some(10),
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::dex::swap_claim::no_cmux::cuda::throughput::PARAM_MESSAGE_2_CARRY_2::FheUint64::10_elements"
        );
    }

    #[test]
    fn hlapi_dex_with_pbs_count() {
        use crate::tfhe::hlapi::dex::DexOp;

        let spec = BenchmarkSpec::new_hlapi_dex(
            Dex::SwapRequest(DexOp::Finalize),
            "PARAM_MESSAGE_2_CARRY_2",
            &OperandType::CipherText,
            Some("FheUint64"),
            BenchmarkMetric::PbsCount,
            Backend::Cpu,
            None,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::dex::swap_request::finalize::pbs_count::PARAM_MESSAGE_2_CARRY_2::FheUint64"
        );
    }

    #[test]
    fn hlapi_noise_squash_latency() {
        let spec = BenchmarkSpec::new_hlapi(
            HlapiBench::NoiseSquash,
            "PARAM_MESSAGE_2_CARRY_2",
            &OperandType::CipherText,
            Some("FheUint64"),
            BenchmarkType::Latency,
            Backend::Cpu,
            None,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::noise_squash::PARAM_MESSAGE_2_CARRY_2::FheUint64"
        );
    }

    #[test]
    fn hlapi_decomp_noise_squash_comp_throughput() {
        let spec = BenchmarkSpec::new_hlapi(
            HlapiBench::DecompNoiseSquashComp,
            "PARAM_MESSAGE_2_CARRY_2",
            &OperandType::CipherText,
            Some("FheUint64"),
            BenchmarkType::Throughput,
            Backend::Cuda,
            None,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::decomp_noise_squash_comp::cuda::throughput::PARAM_MESSAGE_2_CARRY_2::FheUint64"
        );
    }

    #[test]
    fn hlapi_kv_store_get_with_elements() {
        use crate::tfhe::hlapi::kv_store::KvStoreOp;

        let spec = BenchmarkSpec::new_hlapi(
            HlapiBench::KvStore(KvStoreOp::Get),
            "PARAM_MESSAGE_2_CARRY_2",
            &OperandType::CipherText,
            Some("FheUint64"),
            BenchmarkType::Latency,
            Backend::Cpu,
            Some(1024),
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::kv_store::get::PARAM_MESSAGE_2_CARRY_2::FheUint64::1024_elements"
        );
    }

    #[test]
    fn shortint_cpu_latency() {
        let spec = BenchmarkSpec::<str>::new_shortint(
            ShortintBench::UncheckedAdd,
            "PARAM_MESSAGE_2_CARRY_2_KS_PBS",
            BenchmarkMetric::Latency,
            Backend::Cpu,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::shortint::unchecked_add::PARAM_MESSAGE_2_CARRY_2_KS_PBS"
        );
    }

    #[test]
    fn shortint_scalar_op() {
        let spec = BenchmarkSpec::<str>::new_shortint(
            ShortintBench::UncheckedScalarAdd,
            "PARAM_MESSAGE_2_CARRY_2_KS_PBS",
            BenchmarkMetric::Latency,
            Backend::Cpu,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::shortint::unchecked_scalar_add::PARAM_MESSAGE_2_CARRY_2_KS_PBS"
        );
    }

    #[test]
    fn shortint_cuda_latency() {
        let spec = BenchmarkSpec::<str>::new_shortint(
            ShortintBench::ProgrammableBootstrap,
            "PARAM_MESSAGE_2_CARRY_2_KS_PBS",
            BenchmarkMetric::Latency,
            Backend::Cuda,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::shortint::programmable_bootstrap::cuda::PARAM_MESSAGE_2_CARRY_2_KS_PBS"
        );
    }

    #[test]
    fn hlapi_kv_store_with_typed_key_value() {
        use crate::tfhe::hlapi::kv_store::KvStoreOp;

        let tkv = TypedKeyValue::new("FheUint64", "FheUint32");
        let spec = BenchmarkSpec::new_hlapi(
            HlapiBench::KvStore(KvStoreOp::Update),
            "PARAM_MESSAGE_2_CARRY_2",
            &OperandType::CipherText,
            Some(&tkv),
            BenchmarkType::Latency,
            Backend::Cpu,
            Some(512),
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::kv_store::update::PARAM_MESSAGE_2_CARRY_2::key_FheUint64::value_FheUint32::512_elements"
        );
    }

    #[test]
    fn core_crypto_cpu_latency() {
        let spec = BenchmarkSpec::<str>::new_core_crypto(
            CoreCryptoBench::Keyswitch,
            "PARAM_MESSAGE_2_CARRY_2_KS_PBS",
            BenchmarkMetric::Latency,
            Backend::Cpu,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::core_crypto::keyswitch::PARAM_MESSAGE_2_CARRY_2_KS_PBS"
        );
    }

    #[test]
    fn core_crypto_cpu_throughput() {
        let spec = BenchmarkSpec::<str>::new_core_crypto(
            CoreCryptoBench::PbsMemOptimized,
            "PARAM_MESSAGE_2_CARRY_2_KS_PBS",
            BenchmarkMetric::Throughput,
            Backend::Cpu,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::core_crypto::pbs_mem_optimized::throughput::PARAM_MESSAGE_2_CARRY_2_KS_PBS"
        );
    }

    #[test]
    fn core_crypto_cuda_latency() {
        let spec = BenchmarkSpec::<str>::new_core_crypto(
            CoreCryptoBench::KsPbs,
            "PARAM_MESSAGE_2_CARRY_2_KS_PBS",
            BenchmarkMetric::Latency,
            Backend::Cuda,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::core_crypto::ks_pbs::cuda::PARAM_MESSAGE_2_CARRY_2_KS_PBS"
        );
    }

    #[test]
    fn core_crypto_with_type_name() {
        let spec = BenchmarkSpec::new(
            BenchCrate::Tfhe(TfheLayer::CoreCrypto(CoreCryptoBench::MultiBitPbs)),
            Backend::Cpu,
            "PARAM_MESSAGE_2_CARRY_2_KS_PBS",
            &OperandType::CipherText,
            Some("parallelized"),
            BenchmarkMetric::Latency,
            None,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::core_crypto::multi_bit_pbs::PARAM_MESSAGE_2_CARRY_2_KS_PBS::parallelized"
        );
    }
}
