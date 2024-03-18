use super::security_weights::SecurityWeights;
pub const SECURITY_WEIGHTS_ARRAY: [(u64, SecurityWeights); 4] = [
    (80, SecurityWeights { slope: -0.04045822621883835, bias: 1.7183812000404686, minimal_lwe_dimension: 450 }),
    (112, SecurityWeights { slope: -0.029881371645803536, bias: 2.6539316216894946, minimal_lwe_dimension: 450 }),
    (128, SecurityWeights { slope: -0.026599462343105267, bias: 2.981543184145991, minimal_lwe_dimension: 450 }),
    (192, SecurityWeights { slope: -0.018894148763647572, bias: 4.2700349965659115, minimal_lwe_dimension: 532 }),
];
