use crate::shortint::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, EncryptionKeyChoice,
    ShortintKeySwitchingParameters,
};

pub const V1_2_PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS_GAUSSIAN_2M128:
    ShortintKeySwitchingParameters = ShortintKeySwitchingParameters {
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    destination_key: EncryptionKeyChoice::Small,
};

/// Parameter set to keyswitch between keys under the same 2_2 parameter set
pub const V1_2_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    ShortintKeySwitchingParameters = ShortintKeySwitchingParameters {
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    destination_key: EncryptionKeyChoice::Small,
};

/// Parameters to keyswitch from input PKE 2_2 TUniform parameters to 2_2 KS_PBS compute parameters
/// arriving under the small key, requires a PBS to get to the big key
pub const V1_2_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    ShortintKeySwitchingParameters =
    V1_2_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2;

pub const V1_2_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2:
    ShortintKeySwitchingParameters = ShortintKeySwitchingParameters {
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(4),
    destination_key: EncryptionKeyChoice::Small,
};

/// Parameters to keyswitch from input PKE 2_2 TUniform parameters to 2_2 KS_PBS compute parameters
/// arriving under the big key, requires a KS + PBS to get to the big key
pub const V1_2_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    ShortintKeySwitchingParameters =
    V1_2_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2;

pub const V1_2_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2:
    ShortintKeySwitchingParameters = ShortintKeySwitchingParameters {
    ks_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(24),
    destination_key: EncryptionKeyChoice::Big,
};

pub const V1_2_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1:
    ShortintKeySwitchingParameters =
    V1_2_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1;

/// Parameters to keyswitch from input PKE 2_2 TUniform parameters to 2_2 KS_PBS compute parameters
/// arriving under the small key, requires a PBS to get to the big key
pub const V1_2_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1:
    ShortintKeySwitchingParameters = ShortintKeySwitchingParameters {
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(4),
    destination_key: EncryptionKeyChoice::Small,
};

/// Parameters to keyswitch from input PKE 2_2 TUniform parameters to 2_2 KS_PBS compute parameters
/// arriving under the big key, requires a KS + PBS to get to the big key
pub const V1_2_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1:
    ShortintKeySwitchingParameters = ShortintKeySwitchingParameters {
    ks_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(24),
    destination_key: EncryptionKeyChoice::Big,
};
