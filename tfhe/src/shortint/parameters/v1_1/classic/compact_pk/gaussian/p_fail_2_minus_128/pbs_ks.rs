use crate::shortint::parameters::{
    CarryModulus, CiphertextModulus, ClassicPBSParameters, DecompositionBaseLog,
    DecompositionLevelCount, DynamicDistribution, EncryptionKeyChoice, GlweDimension,
    LweCiphertextCount, LweDimension, MaxNoiseLevel, MessageModulus,
    ModulusSwitchNoiseReductionParams, ModulusSwitchType, NoiseEstimationMeasureBound,
    PolynomialSize, RSigmaFactor, StandardDev, Variance,
};

/// p-fail = 2^-139.952, algorithmic cost ~ 78, 2-norm = 3
/// Average number of encryptions of 0s ~ 16, peak noise ~ Variance(0.0000207432665142053)
pub const V1_1_PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_PBS_KS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1024),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.339775301998614e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(6),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(3),
        log2_p_fail: -139.952,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1449),
                ms_bound: NoiseEstimationMeasureBound(1152921504606846976f64),
                ms_r_sigma_factor: RSigmaFactor(13.722759233694832f64),
                ms_input_variance: Variance(3.58478001021692E-7f64),
            },
        ),
    };

/// p-fail = 2^-129.632, algorithmic cost ~ 130, 2-norm = 5
/// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(0.00000140242017242477)
pub const V1_1_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1024),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.339775301998614e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -129.632,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1455),
                ms_bound: NoiseEstimationMeasureBound(288230376151711744f64),
                ms_r_sigma_factor: RSigmaFactor(13.194135838905868f64),
                ms_input_variance: Variance(1.28370890350793E-7f64),
            },
        ),
    };

/// p-fail = 2^-276.943, algorithmic cost ~ 3355, 2-norm = 9
/// Average number of encryptions of 0s ~ 16, peak noise ~ Variance(4.04169957228641E-8)
pub const V1_1_PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_PBS_KS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(2048),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(24),
        ks_level: DecompositionLevelCount(1),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(9),
        log2_p_fail: -276.943,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(2921),
                ms_bound: NoiseEstimationMeasureBound(72057594037927936f64),
                ms_r_sigma_factor: RSigmaFactor(19.430233535388318f64),
                ms_input_variance: Variance(6.41760765328034E-10f64),
            },
        ),
    };

/// p-fail = 2^-273.01, algorithmic cost ~ 20401, 2-norm = 17
/// Average number of encryptions of 0s ~ 16, peak noise ~ Variance(2.56297356349261E-9)
pub const V1_1_PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_PBS_KS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(2048),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(16),
        ks_level: DecompositionLevelCount(2),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(17),
        log2_p_fail: -273.01,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(2923),
                ms_bound: NoiseEstimationMeasureBound(18014398509481984f64),
                ms_r_sigma_factor: RSigmaFactor(19.289811337553306f64),
                ms_input_variance: Variance(7.70213786466074E-11f64),
            },
        ),
    };
