use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
use crate::shortint::parameters::meta::DedicatedCompactPublicKeyParameters;
use crate::shortint::parameters::{
    Backend, CarryModulus, CompactCiphertextListExpansionKind,
    CompactPublicKeyEncryptionParameters, DecompositionBaseLog, DecompositionLevelCount,
    DynamicDistribution, EncryptionKeyChoice, GlweDimension, LweDimension, MaxNoiseLevel,
    MessageModulus, MetaNoiseSquashingParameters, MetaParameters, ModulusSwitchType,
    NoiseSquashingClassicParameters, NoiseSquashingParameters, PolynomialSize,
    ReRandomizationConfiguration, ShortintKeySwitchingParameters, SupportedCompactPkeZkScheme,
};
use crate::shortint::{AtomicPatternParameters, ClassicPBSParameters, PBSParameters};

// p-fail = 2^-128
pub const NIST_PARAM_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(886),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(16),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -128.0,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
    };

// Parameters for the PKE operation
pub const NIST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    CompactPublicKeyEncryptionParameters = CompactPublicKeyEncryptionParameters {
    encryption_lwe_dimension: LweDimension(2048),
    encryption_noise_distribution: DynamicDistribution::new_t_uniform(16),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    expansion_kind: CompactCiphertextListExpansionKind::RequiresCasting,
    zk_scheme: SupportedCompactPkeZkScheme::V2,
};

// Parameters to keyswitch from input PKE 2_2 TUniform parameters to 2_2 KS_PBS compute parameters
// arriving under the destination key
pub const NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    ShortintKeySwitchingParameters = ShortintKeySwitchingParameters {
    ks_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(19),
    destination_key: EncryptionKeyChoice::Big,
};

// Parameters for SwitchSquash
pub const NIST_PARAMS_NOISE_SQUASHING_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    NoiseSquashingParameters = NoiseSquashingParameters::Classic(NoiseSquashingClassicParameters {
    glwe_dimension: GlweDimension(2),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(27),
    polynomial_size: PolynomialSize(2048),
    decomp_base_log: DecompositionBaseLog(24),
    decomp_level_count: DecompositionLevelCount(3),
    ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
    modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
});

pub const NIST_META_PARAMS_2_2: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        NIST_PARAM_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M128,
    )),
    dedicated_compact_public_key_parameters: Some(DedicatedCompactPublicKeyParameters {
        pke_params: NIST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        ksk_params: NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        re_randomization_parameters: Some(
            NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        ),
    }),
    compression_parameters: None,
    noise_squashing_parameters: Some(MetaNoiseSquashingParameters {
        parameters: NIST_PARAMS_NOISE_SQUASHING_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        compression_parameters: None,
    }),
    rerand_configuration: Some(
        ReRandomizationConfiguration::LegacyDedicatedCompactPublicKeyWithKeySwitch,
    ),
};
