use crate::shortint::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, EncryptionKeyChoice,
    ShortintKeySwitchingParameters,
};

pub const V0_10_PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(15),
        ks_base_log: DecompositionBaseLog(1),
        destination_key: EncryptionKeyChoice::Big,
    };

pub const V0_10_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64:
    ShortintKeySwitchingParameters =
    V0_10_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

pub const V0_10_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64:
    ShortintKeySwitchingParameters = ShortintKeySwitchingParameters {
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    destination_key: EncryptionKeyChoice::Small,
};

pub const V0_10_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64:
    ShortintKeySwitchingParameters = ShortintKeySwitchingParameters {
    ks_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(27),
    destination_key: EncryptionKeyChoice::Big,
};
