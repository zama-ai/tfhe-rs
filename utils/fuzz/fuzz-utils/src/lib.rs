use std::fmt::Display;
use std::fs::File;
use std::ops::{Add, Mul, Sub};
use std::path::PathBuf;

use tfhe::core_crypto::commons::math::random::DynamicDistribution;
use tfhe::core_crypto::commons::parameters::*;
use tfhe::integer::ciphertext::IntegerProvenCompactCiphertextListConformanceParams;
use tfhe::prelude::{CiphertextList, Tagged};
use tfhe::safe_serialization::safe_deserialize;
use tfhe::shortint::parameters::*;
use tfhe::shortint::{CarryModulus, MessageModulus};
use tfhe::zk::CompactPkeCrs;
use tfhe::{
    CompactCiphertextListExpander, CompactPublicKey, FheInt8, FheInt16, FheInt32, FheInt64,
    FheTypes, FheUint8, FheUint16, FheUint32, FheUint64, HlCompressible, HlExpandable, ServerKey,
    set_server_key,
};

#[cfg(fuzzing)]
use afl::fuzz;

const MEGA: u64 = 1024 * 1024;
pub const INPUT_MAX_SIZE: u64 = 64 * MEGA;
pub const AUX_MAX_SIZE: u64 = 64 * MEGA;

pub const INSECURE_FUZZ_PARAMS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(10),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(256),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(0),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(0),
    pbs_base_log: DecompositionBaseLog(24),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(37),
    ks_level: DecompositionLevelCount(1),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: f64::NEG_INFINITY,
    ciphertext_modulus: tfhe::shortint::CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
};

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
pub fn aux_data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../aux_data")
}

pub fn load_server_key() -> ServerKey {
    let f = File::open(aux_data_dir().join("server_key.bin")).unwrap();

    safe_deserialize(f, AUX_MAX_SIZE).unwrap()
}

pub fn load_crs() -> CompactPkeCrs {
    let f = File::open(aux_data_dir().join("crs.bin")).unwrap();

    safe_deserialize(f, AUX_MAX_SIZE).unwrap()
}

pub fn load_public_key() -> CompactPublicKey {
    let f = File::open(aux_data_dir().join("pubkey.bin")).unwrap();

    safe_deserialize(f, AUX_MAX_SIZE).unwrap()
}

fn test_integer<FheType>(exp: &CompactCiphertextListExpander, i: usize) -> ExecEndCause
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
    let mut compressed = Vec::new();
    res.compress_into(&mut compressed);

    ExecEndCause::ExecSuccess
}

pub fn use_list(exp: &CompactCiphertextListExpander) -> ExecEndCause {
    for i in 0..exp.len() {
        let Some(kind) = exp.get_kind_of(i) else {
            return ExecEndCause::ExpanderGetFailed;
        };

        let res = match kind {
            FheTypes::Uint8 => test_integer::<FheUint8>(exp, i),
            FheTypes::Uint16 => test_integer::<FheUint16>(exp, i),
            FheTypes::Uint32 => test_integer::<FheUint32>(exp, i),
            FheTypes::Uint64 => test_integer::<FheUint64>(exp, i),
            FheTypes::Int8 => test_integer::<FheInt8>(exp, i),
            FheTypes::Int16 => test_integer::<FheInt16>(exp, i),
            FheTypes::Int32 => test_integer::<FheInt32>(exp, i),
            FheTypes::Int64 => test_integer::<FheInt64>(exp, i),
            _ => ExecEndCause::UnsupportedType,
        };
        if !matches!(res, ExecEndCause::ExecSuccess) {
            return res;
        }
    }
    ExecEndCause::ExecSuccess
}

/// The reason why the execution of a sample ended (without crash)
///
/// All this cases are considered "successes" from the point of view of the fuzzer, meaning that no
/// crash occured and potential error were correctly caught.
/// This type is only used for debug and statistics purpose
pub enum ExecEndCause {
    SafeDeserializationFailed,
    ZkVerificationFailed,
    ExpandFailed,
    ExpanderGetFailed,
    UnsupportedType,
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
            ExecEndCause::ExecSuccess => write!(f, "Sample executed without error"),
        }
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
    let server_key = load_server_key();
    let pubkey = load_public_key();
    let crs = load_crs();

    let conformance_params =
        IntegerProvenCompactCiphertextListConformanceParams::from_public_key_encryption_parameters_and_crs_parameters(
            INSECURE_FUZZ_PKE_PARAMS,
            &crs,
        )
        .allow_unpacked();

    set_server_key(server_key);

    #[cfg(fuzzing)]
    fuzz!(|input: &[u8]| {
        handle_input(input, &conformance_params, &crs, &pubkey);
    });

    #[cfg(not(fuzzing))]
    {
        use std::io::Read;

        let mut input: Vec<u8> = Vec::new();

        std::io::stdin().read_to_end(&mut input).unwrap();
        let res = handle_input(&input, &conformance_params, &crs, &pubkey);
        println!("{res}");
    }
}
