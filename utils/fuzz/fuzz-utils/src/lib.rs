use std::fmt::Display;
use std::fs::File;
use std::ops::{Add, Mul, Sub};
use std::path::{Path, PathBuf};

use tfhe::core_crypto::commons::parameters::*;
use tfhe::integer::ciphertext::IntegerProvenCompactCiphertextListConformanceParams;
use tfhe::prelude::{CiphertextList, Tagged};
use tfhe::safe_serialization::safe_deserialize;
use tfhe::shortint::parameters::list_compression::ClassicCompressionParameters;
use tfhe::shortint::parameters::*;
use tfhe::shortint::{CarryModulus, MessageModulus};
use tfhe::zk::CompactPkeCrs;
use tfhe::{
    CompactCiphertextListExpander, CompactPublicKey, CompressedCiphertextListBuilder, FheInt8,
    FheInt16, FheInt32, FheInt64, FheTypes, FheUint8, FheUint16, FheUint32, FheUint64,
    HlCompressible, HlExpandable, ServerKey, set_server_key,
};

#[cfg(fuzzing)]
use afl::fuzz;

// Provided by the AFL runtime (linked by cargo-afl). Required for the file path mode used by cmin.
#[cfg(fuzzing)]
unsafe extern "C" {
    fn __afl_manual_init();
}

const MEGA: u64 = 1024 * 1024;
pub const INPUT_MAX_SIZE: u64 = 64 * MEGA;
pub const AUX_MAX_SIZE: u64 = 64 * MEGA;

/// Metadata bound into the ZK proof. Must match between corpus generation and verification.
pub const FUZZ_DOMAIN_SEPARATOR: &[u8] = b"fuzz";

pub const INSECURE_FUZZ_PARAMS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(10),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(256),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(0),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(0),
    pbs_base_log: DecompositionBaseLog(24),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(32),
    ks_level: DecompositionLevelCount(1),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: f64::NEG_INFINITY,
    ciphertext_modulus: tfhe::shortint::CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
};

pub const INSECURE_FUZZ_COMPRESSION_PARAMS: CompressionParameters =
    CompressionParameters::Classic(ClassicCompressionParameters {
        br_level: DecompositionLevelCount(1),
        br_base_log: DecompositionBaseLog(24),
        packing_ks_level: DecompositionLevelCount(1),
        packing_ks_base_log: DecompositionBaseLog(30),
        packing_ks_polynomial_size: PolynomialSize(256),
        packing_ks_glwe_dimension: GlweDimension(1),
        lwe_per_glwe: LweCiphertextCount(256),
        // Must be <= polynomial_size.to_blind_rotation_input_modulus_log() = log2(256) + 1 = 9.
        storage_log_modulus: CiphertextModulusLog(9),
        packing_ks_key_noise_distribution: DynamicDistribution::new_t_uniform(0),
    });

pub const INSECURE_FUZZ_PKE_PARAMS: CompactPublicKeyEncryptionParameters =
    CompactPublicKeyEncryptionParameters {
        encryption_lwe_dimension: LweDimension(32),
        encryption_noise_distribution: DynamicDistribution::new_t_uniform(0),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        ciphertext_modulus: tfhe::shortint::CiphertextModulus::new_native(),
        expansion_kind: CompactCiphertextListExpansionKind::RequiresCasting,
        zk_scheme: SupportedCompactPkeZkScheme::V2,
    }
    .validate();

pub const INSECURE_FUZZ_KS_PARAMS: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
        destination_key: EncryptionKeyChoice::Small,
    };

/// Path to the directory containing auxiliary data files (server key, CRS, public key).
pub struct AuxDataDir(PathBuf);

impl AuxDataDir {
    pub fn new() -> Self {
        Self(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../aux_data"))
    }

    pub fn server_key_path(&self) -> PathBuf {
        self.0.join("server_key.bin")
    }

    pub fn crs_path(&self) -> PathBuf {
        self.0.join("crs.bin")
    }

    pub fn public_key_path(&self) -> PathBuf {
        self.0.join("public_key.bin")
    }
}

impl Default for AuxDataDir {
    fn default() -> Self {
        Self::new()
    }
}

impl AsRef<Path> for AuxDataDir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

/// Path to the directory containing the seed corpus for the fuzzers.
pub struct CorpusDir(PathBuf);

impl CorpusDir {
    pub fn new() -> Self {
        Self(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../corpus"))
    }

    pub fn input_path(&self) -> PathBuf {
        self.0.join("input.bin")
    }
}

impl AsRef<Path> for CorpusDir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Default for CorpusDir {
    fn default() -> Self {
        Self::new()
    }
}

pub fn load_server_key() -> ServerKey {
    let f = File::open(AuxDataDir::new().server_key_path()).unwrap();

    safe_deserialize(f, AUX_MAX_SIZE).unwrap()
}

pub fn load_crs() -> CompactPkeCrs {
    let f = File::open(AuxDataDir::new().crs_path()).unwrap();

    safe_deserialize(f, AUX_MAX_SIZE).unwrap()
}

pub fn load_public_key() -> CompactPublicKey {
    let f = File::open(AuxDataDir::new().public_key_path()).unwrap();

    safe_deserialize(f, AUX_MAX_SIZE).unwrap()
}

fn test_integer<FheType>(
    exp: &CompactCiphertextListExpander,
    i: usize,
    builder: &mut CompressedCiphertextListBuilder,
) -> ExecEndCause
where
    FheType: HlExpandable
        + Tagged
        + Clone
        + Add<FheType, Output = FheType>
        + Sub<FheType, Output = FheType>
        + Mul<FheType, Output = FheType>
        + HlCompressible,
{
    let ct = match exp.get::<FheType>(i) {
        Ok(Some(ct)) => ct,
        Ok(None) => {
            return ExecEndCause::ExpanderGetFailed;
        }
        Err(_) => {
            return ExecEndCause::ExpanderGetFailed;
        }
    };
    let res = ct.clone() + ct.clone();
    let res = res * ct.clone();
    let res = res - ct;
    builder.push(res);

    ExecEndCause::ExecSuccess
}

pub fn use_list(exp: &CompactCiphertextListExpander) -> ExecEndCause {
    let mut builder = CompressedCiphertextListBuilder::new();
    for i in 0..exp.len() {
        let Some(kind) = exp.get_kind_of(i) else {
            return ExecEndCause::ExpanderGetFailed;
        };

        let res = match kind {
            FheTypes::Uint8 => test_integer::<FheUint8>(exp, i, &mut builder),
            FheTypes::Uint16 => test_integer::<FheUint16>(exp, i, &mut builder),
            FheTypes::Uint32 => test_integer::<FheUint32>(exp, i, &mut builder),
            FheTypes::Uint64 => test_integer::<FheUint64>(exp, i, &mut builder),
            FheTypes::Int8 => test_integer::<FheInt8>(exp, i, &mut builder),
            FheTypes::Int16 => test_integer::<FheInt16>(exp, i, &mut builder),
            FheTypes::Int32 => test_integer::<FheInt32>(exp, i, &mut builder),
            FheTypes::Int64 => test_integer::<FheInt64>(exp, i, &mut builder),
            _ => ExecEndCause::UnsupportedType,
        };
        if !matches!(res, ExecEndCause::ExecSuccess) {
            return res;
        }
    }

    // Compress the results to exercise compression code
    if builder.build().is_err() {
        return ExecEndCause::CompressionFailed;
    }

    ExecEndCause::ExecSuccess
}

/// The reason why the execution of a sample ended (without crash)
///
/// All these cases are considered "successes" from the point of view of the fuzzer, meaning that no
/// crash occurred and potential error were correctly caught.
/// This type is only used for debug and statistics purpose
#[derive(Debug)]
pub enum ExecEndCause {
    SafeDeserializationFailed,
    ZkVerificationFailed,
    ExpandFailed,
    ExpanderGetFailed,
    UnsupportedType,
    CompressionFailed,
    ExecSuccess,
}

impl Display for ExecEndCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecEndCause::SafeDeserializationFailed => write!(
                f,
                "Error caught during deserialization or conformance checks"
            ),
            ExecEndCause::ZkVerificationFailed => write!(f, "Invalid zk proof"),
            ExecEndCause::ExpandFailed => write!(f, "Failed to expand ciphertext list"),
            ExecEndCause::ExpanderGetFailed => write!(f, "Failed to get ciphertext from expander"),
            ExecEndCause::UnsupportedType => write!(f, "Type is not supported by exec harness"),
            ExecEndCause::CompressionFailed => write!(f, "Failed to compress the result list"),
            ExecEndCause::ExecSuccess => write!(f, "Sample executed without error"),
        }
    }
}

/// Auxiliary data shared by all harnesses and `fuzz-stats`.
///
/// Holds everything needed to process an input: the conformance parameters that gate
/// deserialization, the CRS and public key used for verification, and the server key used for
/// computation.
pub struct FuzzContext {
    pub conformance_params: IntegerProvenCompactCiphertextListConformanceParams,
    pub crs: CompactPkeCrs,
    pub pubkey: CompactPublicKey,
    pub server_key: ServerKey,
}

impl FuzzContext {
    /// Load all auxiliary data from the `aux_data` directory.
    pub fn load() -> Self {
        let server_key = load_server_key();
        let pubkey = load_public_key();
        let crs = load_crs();

        let conformance_params =
            IntegerProvenCompactCiphertextListConformanceParams::from_public_key_encryption_parameters_and_crs_parameters(
                INSECURE_FUZZ_PKE_PARAMS,
                &crs,
            )
            .allow_unpacked();

        Self {
            conformance_params,
            crs,
            pubkey,
            server_key,
        }
    }

    pub fn set_server_key(&self) {
        set_server_key(self.server_key.clone());
    }
}

pub fn harness_main(
    handle_input: impl Fn(
        &[u8],
        &IntegerProvenCompactCiphertextListConformanceParams,
        &CompactPkeCrs,
        &CompactPublicKey,
    ) -> ExecEndCause
    + std::panic::RefUnwindSafe,
) {
    let ctx = FuzzContext::load();
    ctx.set_server_key();

    // Running afl-cmin -T for parallel corpus minimization use file path arguments to provide the
    // testcases to the target. However this is currently not handled by the `fuzz!` macro.
    #[cfg(fuzzing)]
    if let Some(path) = std::env::args_os().nth(1) {
        // Register panic hooks to propagate crashes and init afl.
        // This initialization is also done inside `fuzz!`
        std::panic::set_hook(Box::new(|_| std::process::abort()));
        unsafe { __afl_manual_init() };

        let input = std::fs::read(path).unwrap_or_default();
        handle_input(&input, &ctx.conformance_params, &ctx.crs, &ctx.pubkey);
    } else {
        fuzz!(|input: &[u8]| {
            handle_input(input, &ctx.conformance_params, &ctx.crs, &ctx.pubkey);
        });
    }

    #[cfg(not(fuzzing))]
    {
        use std::io::Read;

        let mut input: Vec<u8> = Vec::new();

        std::io::stdin().read_to_end(&mut input).unwrap();
        let res = handle_input(&input, &ctx.conformance_params, &ctx.crs, &ctx.pubkey);
        println!("{res}");
    }
}
