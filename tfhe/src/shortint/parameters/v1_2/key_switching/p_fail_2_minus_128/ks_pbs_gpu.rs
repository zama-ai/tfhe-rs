use crate::shortint::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, ShortintKeySwitchingParameters,
};
use crate::shortint::EncryptionKeyChoice;

pub const V1_2_PARAM_MULTI_BIT_GROUP_4_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    ShortintKeySwitchingParameters = ShortintKeySwitchingParameters {
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(4),
    destination_key: EncryptionKeyChoice::Small,
};

pub const V1_2_PARAM_MULTI_BIT_GROUP_4_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    ShortintKeySwitchingParameters = ShortintKeySwitchingParameters {
    ks_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(24),
    destination_key: EncryptionKeyChoice::Big,
};
