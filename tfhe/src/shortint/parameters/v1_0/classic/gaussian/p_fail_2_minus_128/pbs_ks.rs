use crate::shortint::parameters::{
    CarryModulus, CiphertextModulus, ClassicPBSParameters, DecompositionBaseLog,
    DecompositionLevelCount, DynamicDistribution, EncryptionKeyChoice, GlweDimension,
    LweCiphertextCount, LweDimension, MaxNoiseLevel, MessageModulus,
    ModulusSwitchNoiseReductionParams, ModulusSwitchType, NoiseEstimationMeasureBound,
    PolynomialSize, RSigmaFactor, StandardDev, Variance,
};

// p-fail = 2^-128.181, algorithmic cost ~ 70, 2-norm = 3
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(0.0000226994502138943)
pub const V1_0_PARAM_MESSAGE_1_CARRY_1_PBS_KS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(914),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            8.938614855855138e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(3),
        log2_p_fail: -128.181,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1450),
                ms_bound: NoiseEstimationMeasureBound(1152921504606846976f64),
                ms_r_sigma_factor: RSigmaFactor(13.118142614422709f64),
                ms_input_variance: Variance(0.00000450016534247506f64),
            },
        ),
    };
// p-fail = 2^-128.163, algorithmic cost ~ 128, 2-norm = 5
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(0.00000141892645707080)
pub const V1_0_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(979),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.9121942871268e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -128.163,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1454),
                ms_bound: NoiseEstimationMeasureBound(288230376151711744f64),
                ms_r_sigma_factor: RSigmaFactor(13.11716805632582f64),
                ms_input_variance: Variance(2.00756529473751E-7f64),
            },
        ),
    };
// p-fail = 2^-128.674, algorithmic cost ~ 2030, 2-norm = 9
// Average number of encryptions of 0s ~ 34, peak noise ~ Variance(8.83211431719384E-8)
pub const V1_0_PARAM_MESSAGE_3_CARRY_3_PBS_KS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1106),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.255365915886752e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(9),
        log2_p_fail: -128.674,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(2962),
                ms_bound: NoiseEstimationMeasureBound(72057594037927936f64),
                ms_r_sigma_factor: RSigmaFactor(13.1440043411319f64),
                ms_input_variance: Variance(6.68231137412311E-8f64),
            },
        ),
    };
// p-fail = 2^-129.799, algorithmic cost ~ 13785, 2-norm = 17
// Average number of encryptions of 0s ~ 34, peak noise ~ Variance(5.47094548750703E-9)
pub const V1_0_PARAM_MESSAGE_4_CARRY_4_PBS_KS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1267),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.0240196581361536e-09,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(9),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(17),
        log2_p_fail: -129.799,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(2977),
                ms_bound: NoiseEstimationMeasureBound(18014398509481984f64),
                ms_r_sigma_factor: RSigmaFactor(13.20288527712688f64),
                ms_input_variance: Variance(3.93208045210723E-9f64),
            },
        ),
    };
