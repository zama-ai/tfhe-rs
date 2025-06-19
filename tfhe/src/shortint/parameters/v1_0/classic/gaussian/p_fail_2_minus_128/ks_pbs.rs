use crate::shortint::parameters::{
    CarryModulus, CiphertextModulus, ClassicPBSParameters, DecompositionBaseLog,
    DecompositionLevelCount, DynamicDistribution, EncryptionKeyChoice, GlweDimension,
    LweCiphertextCount, LweDimension, MaxNoiseLevel, MessageModulus,
    ModulusSwitchNoiseReductionParams, ModulusSwitchType, NoiseEstimationMeasureBound,
    PolynomialSize, RSigmaFactor, StandardDev, Variance,
};

// p-fail = 2^-128.384, algorithmic cost ~ 40, 2-norm = 1
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(0.0000906507473628086)
pub const V1_0_PARAM_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(747),
        glwe_dimension: GlweDimension(6),
        polynomial_size: PolynomialSize(256),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.5944604865450687e-05,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.9524392655548086e-11,
        )),
        pbs_base_log: DecompositionBaseLog(17),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -128.384,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1436),
                ms_bound: NoiseEstimationMeasureBound(2305843009213693952f64),
                ms_r_sigma_factor: RSigmaFactor(13.128778417474985f64),
                ms_input_variance: Variance(0.0000311255754471185f64),
            },
        ),
    };
// p-fail = 2^-128.979, algorithmic cost ~ 64, 2-norm = 3
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(0.0000225552987883164)
pub const V1_0_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(838),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.3169882267274578e-06,
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
        log2_p_fail: -128.979,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1444),
                ms_bound: NoiseEstimationMeasureBound(1152921504606846976f64),
                ms_r_sigma_factor: RSigmaFactor(13.159995024328786f64),
                ms_input_variance: Variance(0.00000586599825120700f64),
            },
        ),
    };
// p-fail = 2^-128.316, algorithmic cost ~ 79, 2-norm = 7
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(0.00000566871520497113)
pub const V1_0_PARAM_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(885),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.4742441118914234e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(7),
        log2_p_fail: -128.316,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1447),
                ms_bound: NoiseEstimationMeasureBound(576460752303423488f64),
                ms_r_sigma_factor: RSigmaFactor(13.12525356819331f64),
                ms_input_variance: Variance(0.00000126293854532351f64),
            },
        ),
    };
// p-fail = 2^-128.07, algorithmic cost ~ 119, 2-norm = 15
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(0.00000141997526567708)
pub const V1_0_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(906),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.0261593945208966e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(15),
        log2_p_fail: -128.07,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1449),
                ms_bound: NoiseEstimationMeasureBound(288230376151711744f64),
                ms_r_sigma_factor: RSigmaFactor(13.112322922625795f64),
                ms_input_variance: Variance(2.92454068675944E-7f64),
            },
        ),
    };
// p-fail = 2^-128.387, algorithmic cost ~ 373, 2-norm = 31
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(3.54094258729146E-7)
pub const V1_0_PARAM_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(930),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.782362904013915e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(31),
        log2_p_fail: -128.387,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1450),
                ms_bound: NoiseEstimationMeasureBound(144115188075855872f64),
                ms_r_sigma_factor: RSigmaFactor(13.128967938469232f64),
                ms_input_variance: Variance(6.47633788819369E-8f64),
            },
        ),
    };
// p-fail = 2^-128.161, algorithmic cost ~ 879, 2-norm = 63
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(8.86838394271893E-8)
pub const V1_0_PARAM_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1012),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.647968356631524e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(32),
        max_noise_level: MaxNoiseLevel::new(63),
        log2_p_fail: -128.161,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1456),
                ms_bound: NoiseEstimationMeasureBound(72057594037927936f64),
                ms_r_sigma_factor: RSigmaFactor(13.117098844906744f64),
                ms_input_variance: Variance(9.98708187218139E-9f64),
            },
        ),
    };
// p-fail = 2^-128.086, algorithmic cost ~ 2678, 2-norm = 127
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(2.21842617086314E-8)
pub const V1_0_PARAM_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1061),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            7.07600596055958e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(2),
        ks_level: DecompositionLevelCount(11),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(64),
        max_noise_level: MaxNoiseLevel::new(127),
        log2_p_fail: -128.086,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1458),
                ms_bound: NoiseEstimationMeasureBound(36028797018963968f64),
                ms_r_sigma_factor: RSigmaFactor(13.113165699179302f64),
                ms_input_variance: Variance(1.55934719162614E-9f64),
            },
        ),
    };
// p-fail = 2^-128.732, algorithmic cost ~ 14472, 2-norm = 255
// Average number of encryptions of 0s ~ 34, peak noise ~ Variance(5.51751832878040E-9)
pub const V1_0_PARAM_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1104),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.369659065698222e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(128),
        max_noise_level: MaxNoiseLevel::new(255),
        log2_p_fail: -128.732,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(2962),
                ms_bound: NoiseEstimationMeasureBound(18014398509481984f64),
                ms_r_sigma_factor: RSigmaFactor(13.147045049847707f64),
                ms_input_variance: Variance(4.17631680856592E-9f64),
            },
        ),
    };
// p-fail = 2^-128.066, algorithmic cost ~ 49, 2-norm = 1
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(0.0000227203724588775)
pub const V1_0_PARAM_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(846),
        glwe_dimension: GlweDimension(3),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.889344520786227e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.9524392655548086e-11,
        )),
        pbs_base_log: DecompositionBaseLog(17),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -128.066,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1445),
                ms_bound: NoiseEstimationMeasureBound(1152921504606846976f64),
                ms_r_sigma_factor: RSigmaFactor(13.112101247626573f64),
                ms_input_variance: Variance(0.00000587212620236712f64),
            },
        ),
    };
// p-fail = 2^-128.388, algorithmic cost ~ 79, 2-norm = 2
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(0.00000566548251955660)
pub const V1_0_PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(884),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.4999005934396873e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -128.388,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1447),
                ms_bound: NoiseEstimationMeasureBound(576460752303423488f64),
                ms_r_sigma_factor: RSigmaFactor(13.128997623956547f64),
                ms_input_variance: Variance(0.00000126467291364026f64),
            },
        ),
    };
// p-fail = 2^-128.377, algorithmic cost ~ 110, 2-norm = 5
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(0.00000141649065433221)
pub const V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(866),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.046151696979124e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -128.377,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1446),
                ms_bound: NoiseEstimationMeasureBound(288230376151711744f64),
                ms_r_sigma_factor: RSigmaFactor(13.128441378136914f64),
                ms_input_variance: Variance(3.38639994643900E-7f64),
            },
        ),
    };
// p-fail = 2^-128.419, algorithmic cost ~ 373, 2-norm = 10
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(3.54002900977798E-7)
pub const V1_0_PARAM_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(930),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.782362904013915e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(10),
        log2_p_fail: -128.419,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1450),
                ms_bound: NoiseEstimationMeasureBound(144115188075855872f64),
                ms_r_sigma_factor: RSigmaFactor(13.130661929691387f64),
                ms_input_variance: Variance(6.46720211305897E-8f64),
            },
        ),
    };
// p-fail = 2^-128.12, algorithmic cost ~ 875, 2-norm = 21
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(8.87133101929087E-8)
pub const V1_0_PARAM_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1007),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.796446316728823e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(21),
        log2_p_fail: -128.12,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1455),
                ms_bound: NoiseEstimationMeasureBound(72057594037927936f64),
                ms_r_sigma_factor: RSigmaFactor(13.114919898723763f64),
                ms_input_variance: Variance(1.04046037106572E-8f64),
            },
        ),
    };
// p-fail = 2^-128.035, algorithmic cost ~ 2665, 2-norm = 42
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(2.21933451675456E-8)
pub const V1_0_PARAM_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1056),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            7.713536970443607e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(2),
        ks_level: DecompositionLevelCount(11),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(32),
        max_noise_level: MaxNoiseLevel::new(42),
        log2_p_fail: -128.035,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1458),
                ms_bound: NoiseEstimationMeasureBound(36028797018963968f64),
                ms_r_sigma_factor: RSigmaFactor(13.110481897090999f64),
                ms_input_variance: Variance(1.66544341872946E-9f64),
            },
        ),
    };
// p-fail = 2^-129.081, algorithmic cost ~ 11765, 2-norm = 85
// Average number of encryptions of 0s ~ 34, peak noise ~ Variance(5.50217479220037E-9)
pub const V1_0_PARAM_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1108),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.144949396867639e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(64),
        max_noise_level: MaxNoiseLevel::new(85),
        log2_p_fail: -129.081,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(2962),
                ms_bound: NoiseEstimationMeasureBound(18014398509481984f64),
                ms_r_sigma_factor: RSigmaFactor(13.16536341829425f64),
                ms_input_variance: Variance(4.15612263357644E-9f64),
            },
        ),
    };
// p-fail = 2^-128.444, algorithmic cost ~ 79, 2-norm = 1
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(0.00000566292898921224)
pub const V1_0_PARAM_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(884),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.4999005934396873e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -128.444,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1447),
                ms_bound: NoiseEstimationMeasureBound(576460752303423488f64),
                ms_r_sigma_factor: RSigmaFactor(13.1319573569348f64),
                ms_input_variance: Variance(0.00000126211938329590f64),
            },
        ),
    };
// p-fail = 2^-128.17, algorithmic cost ~ 110, 2-norm = 2
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(0.00000141883958441919)
pub const V1_0_PARAM_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(863),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.154850045818961e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -128.17,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1446),
                ms_bound: NoiseEstimationMeasureBound(288230376151711744f64),
                ms_r_sigma_factor: RSigmaFactor(13.117569618891837f64),
                ms_input_variance: Variance(3.44714215029333E-7f64),
            },
        ),
    };
// p-fail = 2^-128.024, algorithmic cost ~ 282, 2-norm = 4
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(3.55124805211991E-7)
pub const V1_0_PARAM_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(929),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.900397337590325e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(2),
        ks_level: DecompositionLevelCount(9),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -128.024,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1451),
                ms_bound: NoiseEstimationMeasureBound(144115188075855872f64),
                ms_r_sigma_factor: RSigmaFactor(13.109904440819118f64),
                ms_input_variance: Variance(6.61043662229878E-8f64),
            },
        ),
    };
// p-fail = 2^-128.291, algorithmic cost ~ 875, 2-norm = 9
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(8.85920026139855E-8)
pub const V1_0_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1007),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.796446316728823e-07,
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
        log2_p_fail: -128.291,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1455),
                ms_bound: NoiseEstimationMeasureBound(72057594037927936f64),
                ms_r_sigma_factor: RSigmaFactor(13.123895849681867f64),
                ms_input_variance: Variance(1.02832961317340E-8f64),
            },
        ),
    };
// p-fail = 2^-128.019, algorithmic cost ~ 2110, 2-norm = 18
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(2.21962954961614E-8)
pub const V1_0_PARAM_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1073),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            5.752694209572395e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(2),
        ks_level: DecompositionLevelCount(11),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(18),
        log2_p_fail: -128.019,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1459),
                ms_bound: NoiseEstimationMeasureBound(36028797018963968f64),
                ms_r_sigma_factor: RSigmaFactor(13.109610546388755f64),
                ms_input_variance: Variance(1.33855033550224E-9f64),
            },
        ),
    };
// p-fail = 2^-128.101, algorithmic cost ~ 11669, 2-norm = 36
// Average number of encryptions of 0s ~ 34, peak noise ~ Variance(5.54542171626785E-9)
pub const V1_0_PARAM_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1099),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.673257191405497e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(32),
        max_noise_level: MaxNoiseLevel::new(36),
        log2_p_fail: -128.101,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(2962),
                ms_bound: NoiseEstimationMeasureBound(18014398509481984f64),
                ms_r_sigma_factor: RSigmaFactor(13.113926763265077f64),
                ms_input_variance: Variance(4.21028349406520E-9f64),
            },
        ),
    };
// p-fail = 2^-128.417, algorithmic cost ~ 110, 2-norm = 1
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(0.00000141604488505394)
pub const V1_0_PARAM_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(863),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.154850045818961e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -128.417,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1446),
                ms_bound: NoiseEstimationMeasureBound(288230376151711744f64),
                ms_r_sigma_factor: RSigmaFactor(13.130507624553754f64),
                ms_input_variance: Variance(3.41919515664087E-7f64),
            },
        ),
    };
// p-fail = 2^-128.042, algorithmic cost ~ 260, 2-norm = 2
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(3.55074180343316E-7)
pub const V1_0_PARAM_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(935),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.221794297398788e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -128.042,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1451),
                ms_bound: NoiseEstimationMeasureBound(144115188075855872f64),
                ms_r_sigma_factor: RSigmaFactor(13.11083898291302f64),
                ms_input_variance: Variance(6.41910962050811E-8f64),
            },
        ),
    };
// p-fail = 2^-128.322, algorithmic cost ~ 875, 2-norm = 4
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(8.85700998566799E-8)
pub const V1_0_PARAM_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1007),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.796446316728823e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -128.322,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1455),
                ms_bound: NoiseEstimationMeasureBound(72057594037927936f64),
                ms_r_sigma_factor: RSigmaFactor(13.125518472538255f64),
                ms_input_variance: Variance(1.02613933744284E-8f64),
            },
        ),
    };
// p-fail = 2^-128.079, algorithmic cost ~ 2081, 2-norm = 8
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(2.21856153883081E-8)
pub const V1_0_PARAM_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1058),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            7.451906811620241e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(2),
        ks_level: DecompositionLevelCount(11),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(8),
        log2_p_fail: -128.079,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1458),
                ms_bound: NoiseEstimationMeasureBound(36028797018963968f64),
                ms_r_sigma_factor: RSigmaFactor(13.11276563597672f64),
                ms_input_variance: Variance(1.61890853221631E-9f64),
            },
        ),
    };
// p-fail = 2^-128.676, algorithmic cost ~ 11659, 2-norm = 17
// Average number of encryptions of 0s ~ 34, peak noise ~ Variance(5.51996713858843E-9)
pub const V1_0_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1098),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.73718341270979e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(17),
        log2_p_fail: -128.676,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(2961),
                ms_bound: NoiseEstimationMeasureBound(18014398509481984f64),
                ms_r_sigma_factor: RSigmaFactor(13.144128530287597f64),
                ms_input_variance: Variance(4.18604157598814E-9f64),
            },
        ),
    };
// p-fail = 2^-128.234, algorithmic cost ~ 259, 2-norm = 1
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(3.54529491312476E-7)
pub const V1_0_PARAM_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(931),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.666347503085657e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -128.234,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1451),
                ms_bound: NoiseEstimationMeasureBound(144115188075855872f64),
                ms_r_sigma_factor: RSigmaFactor(13.120906677596983f64),
                ms_input_variance: Variance(6.48881706070626E-8f64),
            },
        ),
    };
// p-fail = 2^-128.327, algorithmic cost ~ 875, 2-norm = 2
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(8.85660562707158E-8)
pub const V1_0_PARAM_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1007),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.796446316728823e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -128.327,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1455),
                ms_bound: NoiseEstimationMeasureBound(72057594037927936f64),
                ms_r_sigma_factor: RSigmaFactor(13.125818099498767f64),
                ms_input_variance: Variance(1.02573497884643E-8f64),
            },
        ),
    };
// p-fail = 2^-128.027, algorithmic cost ~ 2077, 2-norm = 4
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(2.21948580616001E-8)
pub const V1_0_PARAM_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1056),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            7.713536970443607e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(2),
        ks_level: DecompositionLevelCount(11),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -128.027,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1458),
                ms_bound: NoiseEstimationMeasureBound(36028797018963968f64),
                ms_r_sigma_factor: RSigmaFactor(13.110035056924806f64),
                ms_input_variance: Variance(1.66695631278390E-9f64),
            },
        ),
    };
// p-fail = 2^-129.1, algorithmic cost ~ 9046, 2-norm = 8
// Average number of encryptions of 0s ~ 34, peak noise ~ Variance(5.50136439949245E-9)
pub const V1_0_PARAM_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1113),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.8850164020946995e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(8),
        log2_p_fail: -129.1,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(2962),
                ms_bound: NoiseEstimationMeasureBound(18014398509481984f64),
                ms_r_sigma_factor: RSigmaFactor(13.166333061536834f64),
                ms_input_variance: Variance(4.14924894285670E-9f64),
            },
        ),
    };
// p-fail = 2^-128.329, algorithmic cost ~ 875, 2-norm = 1
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(8.85650453742248E-8)
pub const V1_0_PARAM_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1007),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.796446316728823e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(64),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -128.329,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1455),
                ms_bound: NoiseEstimationMeasureBound(72057594037927936f64),
                ms_r_sigma_factor: RSigmaFactor(13.125893009445125f64),
                ms_input_variance: Variance(1.02563388919733E-8f64),
            },
        ),
    };
// p-fail = 2^-128.11, algorithmic cost ~ 2077, 2-norm = 2
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(2.21800917385509E-8)
pub const V1_0_PARAM_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1056),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            7.713536970443607e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(2),
        ks_level: DecompositionLevelCount(11),
        message_modulus: MessageModulus(64),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -128.11,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1458),
                ms_bound: NoiseEstimationMeasureBound(36028797018963968f64),
                ms_r_sigma_factor: RSigmaFactor(13.114398312177766f64),
                ms_input_variance: Variance(1.65218998973470E-9f64),
            },
        ),
    };
// p-fail = 2^-129.382, algorithmic cost ~ 8949, 2-norm = 4
// Average number of encryptions of 0s ~ 34, peak noise ~ Variance(5.48905930129094E-9)
pub const V1_0_PARAM_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1101),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.5486665054375844e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(64),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -129.382,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(2961),
                ms_bound: NoiseEstimationMeasureBound(18014398509481984f64),
                ms_r_sigma_factor: RSigmaFactor(13.181082612949039f64),
                ms_input_variance: Variance(4.15149575988355E-9f64),
            },
        ),
    };
// p-fail = 2^-128.131, algorithmic cost ~ 2077, 2-norm = 1
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(2.21764001577886E-8)
pub const V1_0_PARAM_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1056),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            7.713536970443607e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(2),
        ks_level: DecompositionLevelCount(11),
        message_modulus: MessageModulus(128),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -128.131,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1458),
                ms_bound: NoiseEstimationMeasureBound(36028797018963968f64),
                ms_r_sigma_factor: RSigmaFactor(13.115489806865527f64),
                ms_input_variance: Variance(1.64849840897239E-9f64),
            },
        ),
    };
// p-fail = 2^-130.318, algorithmic cost ~ 8932, 2-norm = 2
// Average number of encryptions of 0s ~ 33, peak noise ~ Variance(5.44858619003947E-9)
pub const V1_0_PARAM_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1099),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.673257191405497e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(128),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -130.318,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(2959),
                ms_bound: NoiseEstimationMeasureBound(18014398509481984f64),
                ms_r_sigma_factor: RSigmaFactor(13.229947802091102f64),
                ms_input_variance: Variance(4.11344796783681E-9f64),
            },
        ),
    };
// p-fail = 2^-129.114, algorithmic cost ~ 8924, 2-norm = 1
// Average number of encryptions of 0s ~ 34, peak noise ~ Variance(5.50077134664127E-9)
pub const V1_0_PARAM_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1098),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.73718341270979e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(256),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -129.114,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(2961),
                ms_bound: NoiseEstimationMeasureBound(18014398509481984f64),
                ms_r_sigma_factor: RSigmaFactor(13.167042791174891f64),
                ms_input_variance: Variance(4.16684578404098E-9f64),
            },
        ),
    };
