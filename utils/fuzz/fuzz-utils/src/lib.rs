use std::fmt::Display;
use std::fs::File;
use std::ops::{Add, BitAnd, BitOr, BitXor, Mul, Sub};
use std::path::{Path, PathBuf};

#[cfg(feature = "gpu")]
use tfhe::{ClientKey, CompressedServerKey, CudaServerKey};

use tfhe::core_crypto::commons::parameters::*;
use tfhe::integer::U256;
use tfhe::integer::ciphertext::IntegerProvenCompactCiphertextListConformanceParams;
use tfhe::prelude::{CiphertextList, FheTryTrivialEncrypt, ReRandomize, Tagged};
use tfhe::safe_serialization::safe_deserialize;
use tfhe::shortint::parameters::list_compression::ClassicCompressionParameters;
use tfhe::shortint::parameters::*;
use tfhe::shortint::{CarryModulus, MessageModulus};
use tfhe::zk::CompactPkeCrs;
use tfhe::{
    CompactCiphertextListExpander, CompactPublicKey, CompressedCiphertextListBuilder, FheBool,
    FheInt8, FheInt16, FheInt32, FheInt64, FheTypes, FheUint8, FheUint16, FheUint32, FheUint64,
    FheUint128, FheUint160, FheUint256, FheUint512, FheUint1024, FheUint2048, HlCompressible,
    HlExpandable, ReRandomizationContext, Seed, ServerKey, set_server_key,
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

pub const INSECURE_FUZZ_GPU_PARAMS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(16),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32),
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

// The compute params use polynomial_size=32, which caps storage_log_modulus at
// log2(32)+1 = 6 (enforced by CompressionPrivateKeys::new_compression_key_with_engine).
pub const INSECURE_FUZZ_GPU_COMPRESSION_PARAMS: CompressionParameters =
    CompressionParameters::Classic(ClassicCompressionParameters {
        br_level: DecompositionLevelCount(1),
        br_base_log: DecompositionBaseLog(24),
        packing_ks_level: DecompositionLevelCount(1),
        packing_ks_base_log: DecompositionBaseLog(30),
        packing_ks_polynomial_size: PolynomialSize(256),
        packing_ks_glwe_dimension: GlweDimension(1),
        lwe_per_glwe: LweCiphertextCount(256),
        storage_log_modulus: CiphertextModulusLog(6),
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

// GPU compact PKE must encrypt under the big LWE key (polynomial_size × glwe_dimension = 32)
// so that the ZK expand output dimension matches the compute key's big LWE dimension. The CPU
// harness reuses INSECURE_FUZZ_PKE_PARAMS (encryption_lwe_dimension=32) because the CPU path
// is not constrained by DISPATCH_POLY_SIZE, but the GPU ZK expansion kernel in zk.cuh uses
// casting_params.big_lwe_dimension = max(PKE_dim, KSK_output_dim) as both the parsing
// dimension for compact input and the output dimension of expanded ciphertexts — so PKE_dim
// must equal big_compute_dim for the expanded ciphertexts to land in the right LWE space.
// polynomial_size=32 requires TFHE_CUDA_FUZZING in dispatch.cuh (gated in build.rs on AFL_CXX).
pub const INSECURE_FUZZ_GPU_PKE_PARAMS: CompactPublicKeyEncryptionParameters =
    CompactPublicKeyEncryptionParameters {
        encryption_lwe_dimension: LweDimension(32), // = polynomial_size × glwe_dimension
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

// destination_key: Small mirrors production GPU params (PARAM_KEYSWITCH_TO_SMALL).
// The casting KSK goes from PKE (256) → compute small (64); DISPATCH_POLY_SIZE in the CUDA
// ZK expansion kernel dispatches on casting_big_dim = max(256, 64) = 256 ≥ 256 ✓.
pub const INSECURE_FUZZ_GPU_KS_PARAMS: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
        destination_key: EncryptionKeyChoice::Small,
    };

/// Path to the directory containing auxiliary data files (server key, CRS, public key).
pub struct AuxDataDir(PathBuf);

impl AuxDataDir {
    pub fn new() -> Self {
        let path = std::env::var("TFHE_FUZZ_AUX_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../aux_data"));
        Self(path)
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

    pub fn gpu_client_key_path(&self) -> PathBuf {
        self.0.join("gpu_client_key.bin")
    }

    pub fn gpu_crs_path(&self) -> PathBuf {
        self.0.join("gpu_crs.bin")
    }

    pub fn gpu_public_key_path(&self) -> PathBuf {
        self.0.join("gpu_public_key.bin")
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

    pub fn gpu_input_path(&self) -> PathBuf {
        self.0.join("gpu_input.bin")
    }

    pub fn gpu_scalars_input_path(&self) -> PathBuf {
        self.0.join("gpu_scalars_input.bin")
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

/// Bool-specific driver: FheBool has no Add/Sub/Mul; exercise the bitwise ops instead.
fn compute_bool(ct: FheBool, builder: &mut CompressedCiphertextListBuilder) {
    let res = ct.clone().bitxor(ct.clone());
    let res = res.bitand(ct.clone());
    let res = res.bitor(ct);
    builder.push(res);
}

fn compute_integer<FheType>(ct: FheType, builder: &mut CompressedCiphertextListBuilder)
where
    FheType: Tagged
        + Clone
        + Add<FheType, Output = FheType>
        + Sub<FheType, Output = FheType>
        + Mul<FheType, Output = FheType>
        + HlCompressible,
{
    let res = ct.clone() + ct.clone();
    let res = res * ct.clone();
    let res = res - ct;
    builder.push(res);
}

/// Holds one expanded ciphertext of a fhevm backend-ciphertext variant.
///
/// The accepted set is `ALL = H ∪ W` where:
/// - `H = {Bool, U8, U16, U32, U64, U128, U160, U256}` — fhevm host-executor types (see
///   `fhevm_support_spec_test.md` §3 and `fhevm-operator-registry.md`).
/// - `W = {U512, U1024, U2048}` — backend-only large-integer wrappers (fhevm `FheBytes64/128/256`).
///
/// Any other `FheTypes` variant — notably signed integers and backend-only `U4` — is rejected
/// with [`ExecEndCause::UnsupportedType`] by [`FhevmCt::extract`].
pub enum FhevmCt {
    Bool(FheBool),
    U8(FheUint8),
    U16(FheUint16),
    U32(FheUint32),
    U64(FheUint64),
    U128(FheUint128),
    U160(FheUint160),
    U256(FheUint256),
    U512(FheUint512),
    U1024(FheUint1024),
    U2048(FheUint2048),
}

impl FhevmCt {
    fn extract(
        exp: &CompactCiphertextListExpander,
        i: usize,
        kind: FheTypes,
    ) -> Result<Self, ExecEndCause> {
        fn get<T: HlExpandable + Tagged>(
            exp: &CompactCiphertextListExpander,
            i: usize,
        ) -> Result<T, ExecEndCause> {
            match exp.get::<T>(i) {
                Ok(Some(ct)) => Ok(ct),
                Ok(None) | Err(_) => Err(ExecEndCause::ExpanderGetFailed),
            }
        }
        Ok(match kind {
            FheTypes::Bool => Self::Bool(get(exp, i)?),
            FheTypes::Uint8 => Self::U8(get(exp, i)?),
            FheTypes::Uint16 => Self::U16(get(exp, i)?),
            FheTypes::Uint32 => Self::U32(get(exp, i)?),
            FheTypes::Uint64 => Self::U64(get(exp, i)?),
            FheTypes::Uint128 => Self::U128(get(exp, i)?),
            FheTypes::Uint160 => Self::U160(get(exp, i)?),
            FheTypes::Uint256 => Self::U256(get(exp, i)?),
            FheTypes::Uint512 => Self::U512(get(exp, i)?),
            FheTypes::Uint1024 => Self::U1024(get(exp, i)?),
            FheTypes::Uint2048 => Self::U2048(get(exp, i)?),
            _ => return Err(ExecEndCause::UnsupportedType),
        })
    }

    fn add_to_re_randomization_context(&self, context: &mut ReRandomizationContext) {
        match self {
            Self::Bool(x) => context.add_ciphertext(x),
            Self::U8(x) => context.add_ciphertext(x),
            Self::U16(x) => context.add_ciphertext(x),
            Self::U32(x) => context.add_ciphertext(x),
            Self::U64(x) => context.add_ciphertext(x),
            Self::U128(x) => context.add_ciphertext(x),
            Self::U160(x) => context.add_ciphertext(x),
            Self::U256(x) => context.add_ciphertext(x),
            Self::U512(x) => context.add_ciphertext(x),
            Self::U1024(x) => context.add_ciphertext(x),
            Self::U2048(x) => context.add_ciphertext(x),
        }
    }

    fn re_randomise(
        &mut self,
        cpk: &CompactPublicKey,
        seed: tfhe::integer::ciphertext::ReRandomizationSeed,
    ) -> tfhe::Result<()> {
        match self {
            Self::Bool(x) => x.re_randomize(cpk, seed),
            Self::U8(x) => x.re_randomize(cpk, seed),
            Self::U16(x) => x.re_randomize(cpk, seed),
            Self::U32(x) => x.re_randomize(cpk, seed),
            Self::U64(x) => x.re_randomize(cpk, seed),
            Self::U128(x) => x.re_randomize(cpk, seed),
            Self::U160(x) => x.re_randomize(cpk, seed),
            Self::U256(x) => x.re_randomize(cpk, seed),
            Self::U512(x) => x.re_randomize(cpk, seed),
            Self::U1024(x) => x.re_randomize(cpk, seed),
            Self::U2048(x) => x.re_randomize(cpk, seed),
        }
    }

    fn compute_and_push(self, builder: &mut CompressedCiphertextListBuilder) {
        match self {
            Self::Bool(ct) => compute_bool(ct, builder),
            Self::U8(ct) => compute_integer(ct, builder),
            Self::U16(ct) => compute_integer(ct, builder),
            Self::U32(ct) => compute_integer(ct, builder),
            Self::U64(ct) => compute_integer(ct, builder),
            Self::U128(ct) => compute_integer(ct, builder),
            Self::U256(ct) => compute_integer(ct, builder),
            // U160 (eaddress) and the FheBytes wrappers (U512/U1024/U2048) are compressed
            // as-is: fhevm exposes no arithmetic ops on them.
            Self::U160(ct) => {
                builder.push(ct);
            }
            Self::U512(ct) => {
                builder.push(ct);
            }
            Self::U1024(ct) => {
                builder.push(ct);
            }
            Self::U2048(ct) => {
                builder.push(ct);
            }
        }
    }
}

/// GPU variant of [`use_list`] restricted to the fhevm host-executor ciphertext types.
///
/// See [`FhevmCt`] for the accepted type set.
pub fn use_list_gpu(exp: &CompactCiphertextListExpander) -> ExecEndCause {
    let mut cts = Vec::with_capacity(exp.len());
    for i in 0..exp.len() {
        let Some(kind) = exp.get_kind_of(i) else {
            return ExecEndCause::ExpanderGetFailed;
        };
        match FhevmCt::extract(exp, i, kind) {
            Ok(ct) => cts.push(ct),
            Err(cause) => return cause,
        }
    }

    let mut builder = CompressedCiphertextListBuilder::new();
    for ct in cts {
        ct.compute_and_push(&mut builder);
    }

    if builder.build().is_err() {
        return ExecEndCause::CompressionFailed;
    }

    ExecEndCause::ExecSuccess
}

/// Deterministic byte cursor over the fuzz input, used to derive scalar operands for
/// trivial encryption and OPRF generation.
///
/// Cycles over the input bytes so that short inputs still produce a complete scalar set.
/// Zero-length inputs yield all-zero scalars. The cursor is stable across runs: identical
/// `bytes` and the same read sequence always produce the same values — required for AFL
/// crash replay.
pub struct ScalarSource<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ScalarSource<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn next_byte(&mut self) -> u8 {
        if self.bytes.is_empty() {
            return 0;
        }
        let b = self.bytes[self.pos % self.bytes.len()];
        self.pos = self.pos.wrapping_add(1);
        b
    }

    fn fill(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            *b = self.next_byte();
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut out = [0u8; 8];
        self.fill(&mut out);
        u64::from_le_bytes(out)
    }

    pub fn next_u128(&mut self) -> u128 {
        let mut out = [0u8; 16];
        self.fill(&mut out);
        u128::from_le_bytes(out)
    }

    pub fn next_u256(&mut self) -> U256 {
        U256::from((self.next_u128(), self.next_u128()))
    }

    /// U160 values live in a U256 container with the top 96 bits cleared, matching the
    /// fhevm `eaddress` representation.
    pub fn next_u160(&mut self) -> U256 {
        let lo = self.next_u128();
        let hi_u32 = self.next_u64() as u32 as u128;
        U256::from((lo, hi_u32))
    }

    pub fn next_bool(&mut self) -> bool {
        self.next_byte() & 1 == 1
    }
}

/// Pick a `random_bits_count` value `k` for a bounded OPRF call.
///
/// Cycles `k` over `[min_log2 + 1, bit_count]` from the fuzz cursor so the OPRF is exercised
/// with every supported upper bound in that interval. Across the per-type calls in
/// [`generate_scalar_ops_gpu`], `min_log2` is set to the width of the next-smaller standard
/// integer type (`0` for U8, `8` for U16, `16` for U32, `32` for U64, `64` for U128,
/// `128` for U256), partitioning the full `random_bits_count` range `[1, 256]` into disjoint
/// per-type intervals.
fn next_random_bits(source: &mut ScalarSource, bit_count: u64, min_log2: u64) -> u64 {
    let raw = source.next_byte() as u64;
    let lo = min_log2 + 1;
    let range = bit_count - lo + 1;
    lo + (raw % range)
}

/// Builds one OPRF ciphertext and one trivial ciphertext for each fhevm host-executor type
/// and pushes them into `builder`.
///
/// Dispatch matches the fhevm `generate_random_number` table (see
/// `fhevm-operator-registry.md` opcodes 24/26/27):
///   - Bool uses the unbounded `generate_oblivious_pseudo_random` (no `random_bits` argument).
///   - U8/U16/U32/U64/U128/U256 use `generate_oblivious_pseudo_random_bounded(seed, random_bits)`
///     with `random_bits` cycled over a per-type interval of the full `[1, 256]` supported range
///     (U8: 1-8, U16: 9-16, U32: 17-32, U64: 33-64, U128: 65-128, U256: 129-256) so the OPRF kernel
///     is exercised at every supported upper bound across one input.
///   - U160 (eaddress) has no host random-generation node per the registry, so it only exercises
///     `try_encrypt_trivial`.
///
/// The server key must already be set on this thread.
pub fn generate_scalar_ops_gpu(
    builder: &mut CompressedCiphertextListBuilder,
    source: &mut ScalarSource,
) {
    // Bool: unbounded OPRF + trivial encrypt
    let b_seed = source.next_u128();
    builder.push(FheBool::generate_oblivious_pseudo_random(Seed(b_seed)));
    let b_val = source.next_bool();
    if let Ok(ct) = FheBool::try_encrypt_trivial(b_val) {
        builder.push(ct);
    }

    // U8: random_bits_count ∈ [1, 8].
    let seed = source.next_u128();
    let random_bits = next_random_bits(source, 8, 0);
    builder.push(FheUint8::generate_oblivious_pseudo_random_bounded(
        Seed(seed),
        random_bits,
    ));
    let v = source.next_byte();
    if let Ok(ct) = FheUint8::try_encrypt_trivial(v) {
        builder.push(ct);
    }

    // U16: random_bits_count ∈ [9, 16].
    let seed = source.next_u128();
    let random_bits = next_random_bits(source, 16, 8);
    builder.push(FheUint16::generate_oblivious_pseudo_random_bounded(
        Seed(seed),
        random_bits,
    ));
    let v = source.next_u64() as u16;
    if let Ok(ct) = FheUint16::try_encrypt_trivial(v) {
        builder.push(ct);
    }

    // U32: random_bits_count ∈ [17, 32].
    let seed = source.next_u128();
    let random_bits = next_random_bits(source, 32, 16);
    builder.push(FheUint32::generate_oblivious_pseudo_random_bounded(
        Seed(seed),
        random_bits,
    ));
    let v = source.next_u64() as u32;
    if let Ok(ct) = FheUint32::try_encrypt_trivial(v) {
        builder.push(ct);
    }

    // U64: random_bits_count ∈ [33, 64].
    let seed = source.next_u128();
    let random_bits = next_random_bits(source, 64, 32);
    builder.push(FheUint64::generate_oblivious_pseudo_random_bounded(
        Seed(seed),
        random_bits,
    ));
    let v = source.next_u64();
    if let Ok(ct) = FheUint64::try_encrypt_trivial(v) {
        builder.push(ct);
    }

    // U128: random_bits_count ∈ [65, 128].
    let seed = source.next_u128();
    let random_bits = next_random_bits(source, 128, 64);
    builder.push(FheUint128::generate_oblivious_pseudo_random_bounded(
        Seed(seed),
        random_bits,
    ));
    let v = source.next_u128();
    if let Ok(ct) = FheUint128::try_encrypt_trivial(v) {
        builder.push(ct);
    }

    // U256: random_bits_count ∈ [129, 256].
    let seed = source.next_u128();
    let random_bits = next_random_bits(source, 256, 128);
    builder.push(FheUint256::generate_oblivious_pseudo_random_bounded(
        Seed(seed),
        random_bits,
    ));
    let v = source.next_u256();
    if let Ok(ct) = FheUint256::try_encrypt_trivial(v) {
        builder.push(ct);
    }

    // U160 (eaddress): trivial encrypt only — no host random-generation node.
    let v = source.next_u160();
    if let Ok(ct) = FheUint160::try_encrypt_trivial(v) {
        builder.push(ct);
    }
}

/// GPU variant that re-randomizes every ciphertext against `public_key` before computing on it.
///
/// Mirrors [`use_list_gpu`] but inserts a re-randomization pass after decompression. The
/// seed generator is driven by `input_seed` through the function-description slot of the
/// [`ReRandomizationContext`], which makes AFL replays deterministic: identical input bytes
/// produce identical post-rerand ciphertexts.
pub fn use_list_gpu_rerand(
    exp: &CompactCiphertextListExpander,
    public_key: &CompactPublicKey,
    input_seed: &[u8],
) -> ExecEndCause {
    let mut cts = Vec::with_capacity(exp.len());
    for i in 0..exp.len() {
        let Some(kind) = exp.get_kind_of(i) else {
            return ExecEndCause::ExpanderGetFailed;
        };
        match FhevmCt::extract(exp, i, kind) {
            Ok(ct) => cts.push(ct),
            Err(cause) => return cause,
        }
    }

    let mut re_rand_context = ReRandomizationContext::new(*b"FUZZ_Rrd", [input_seed], *b"FUZZ_Enc");
    for ct in &cts {
        ct.add_to_re_randomization_context(&mut re_rand_context);
    }
    let mut seed_gen = re_rand_context.finalize();

    for ct in &mut cts {
        let seed = match seed_gen.next_seed() {
            Ok(seed) => seed,
            Err(_) => return ExecEndCause::ReRandomizationFailed,
        };
        if ct.re_randomise(public_key, seed).is_err() {
            return ExecEndCause::ReRandomizationFailed;
        }
    }

    let mut builder = CompressedCiphertextListBuilder::new();
    for ct in cts {
        ct.compute_and_push(&mut builder);
    }

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
    ReRandomizationFailed,
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
            ExecEndCause::ReRandomizationFailed => write!(f, "Failed to re-randomize a ciphertext"),
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

#[cfg(feature = "gpu")]
pub struct GpuFuzzContext {
    pub cuda_server_key: CudaServerKey,
    pub conformance_params: IntegerProvenCompactCiphertextListConformanceParams,
    pub public_key: CompactPublicKey,
}

#[cfg(feature = "gpu")]
impl GpuFuzzContext {
    pub fn set_server_key(&self) {
        set_server_key(self.cuda_server_key.clone());
    }

    pub fn load() -> Self {
        let aux = AuxDataDir::new();

        let f = File::open(aux.gpu_client_key_path()).unwrap();
        let client_key: ClientKey = safe_deserialize(f, AUX_MAX_SIZE).unwrap();
        let cuda_server_key = CompressedServerKey::new(&client_key).decompress_to_gpu();

        let f = File::open(aux.gpu_crs_path()).unwrap();
        let crs: CompactPkeCrs = safe_deserialize(f, AUX_MAX_SIZE).unwrap();
        let conformance_params =
            IntegerProvenCompactCiphertextListConformanceParams::from_public_key_encryption_parameters_and_crs_parameters(
                INSECURE_FUZZ_GPU_PKE_PARAMS,
                &crs,
            )
            .allow_unpacked();

        let f = File::open(aux.gpu_public_key_path()).unwrap();
        let public_key: CompactPublicKey = safe_deserialize(f, AUX_MAX_SIZE).unwrap();

        Self {
            cuda_server_key,
            conformance_params,
            public_key,
        }
    }
}

/// CPU-side context for GPU campaign corpus analysis.
///
/// Loads the same GPU aux files as `GpuFuzzContext` but decompresses the client key to a
/// CPU `ServerKey` instead of a `CudaServerKey`. This lets `fuzz-stats --gpu` run without
/// the CUDA backend, avoiding the `TFHE_CUDA_FUZZING` / polynomial_size=32 requirement.
#[cfg(feature = "gpu")]
pub struct GpuCorpusCpuContext {
    pub server_key: ServerKey,
    pub conformance_params: IntegerProvenCompactCiphertextListConformanceParams,
}

#[cfg(feature = "gpu")]
impl GpuCorpusCpuContext {
    pub fn load() -> Self {
        let aux = AuxDataDir::new();

        let f = File::open(aux.gpu_client_key_path()).unwrap();
        let client_key: ClientKey = safe_deserialize(f, AUX_MAX_SIZE).unwrap();
        let server_key = CompressedServerKey::new(&client_key).decompress();

        let f = File::open(aux.gpu_crs_path()).unwrap();
        let crs: CompactPkeCrs = safe_deserialize(f, AUX_MAX_SIZE).unwrap();
        let conformance_params =
            IntegerProvenCompactCiphertextListConformanceParams::from_public_key_encryption_parameters_and_crs_parameters(
                INSECURE_FUZZ_GPU_PKE_PARAMS,
                &crs,
            )
            .allow_unpacked();

        Self {
            server_key,
            conformance_params,
        }
    }

    pub fn set_server_key(&self) {
        set_server_key(self.server_key.clone());
    }
}

#[cfg(feature = "gpu")]
pub fn harness_cuda_main(
    handle_input: impl Fn(&[u8], &GpuFuzzContext) -> ExecEndCause + std::panic::RefUnwindSafe,
) {
    #[cfg(fuzzing)]
    if let Some(path) = std::env::args_os().nth(1) {
        std::panic::set_hook(Box::new(|_| std::process::abort()));
        unsafe { __afl_manual_init() };
        let ctx = GpuFuzzContext::load();
        set_server_key(ctx.cuda_server_key.clone());
        let input = std::fs::read(path).unwrap_or_default();
        handle_input(&input, &ctx);
    } else {
        // CUDA contexts are not fork-safe: any context created before AFL's forkserver
        // fork is invalid in the child. Call __afl_manual_init() explicitly so the fork
        // happens here, then initialize CUDA in the child. This init runs before the
        // first __afl_persistent_loop() call inside fuzz!, so it is not counted against
        // AFL's per-test-case timeout. The second __afl_manual_init() call inside fuzz!
        // is a no-op because the C-level init_done flag is already set.
        unsafe { __afl_manual_init() };
        let ctx = GpuFuzzContext::load();
        set_server_key(ctx.cuda_server_key.clone());
        let ctx = std::panic::AssertUnwindSafe(ctx);
        fuzz!(|input: &[u8]| {
            handle_input(input, &*ctx);
        });
    }

    #[cfg(not(fuzzing))]
    {
        use std::io::Read;
        let ctx = GpuFuzzContext::load();
        set_server_key(ctx.cuda_server_key.clone());
        let mut input = Vec::new();
        std::io::stdin().read_to_end(&mut input).unwrap();
        let res = handle_input(&input, &ctx);
        println!("{res}");
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
