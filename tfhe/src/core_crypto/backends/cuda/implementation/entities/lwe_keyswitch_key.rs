use crate::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount, LweDimension};

use crate::core_crypto::backends::cuda::private::crypto::keyswitch::CudaLweKeyswitchKey;
use crate::core_crypto::specification::entities::markers::LweKeyswitchKeyKind;
use crate::core_crypto::specification::entities::{AbstractEntity, LweKeyswitchKeyEntity};

/// A structure representing a keyswitch key for 32 bits precision ciphertexts on the GPU.
#[derive(Debug)]
pub struct CudaLweKeyswitchKey32(pub(crate) CudaLweKeyswitchKey<u32>);

impl AbstractEntity for CudaLweKeyswitchKey32 {
    type Kind = LweKeyswitchKeyKind;
}

impl LweKeyswitchKeyEntity for CudaLweKeyswitchKey32 {
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_dimension
    }

    fn output_lwe_dimension(&self) -> LweDimension {
        self.0.output_lwe_dimension
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomp_level
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomp_base_log
    }
}

/// A structure representing a  keyswitch key for 64 bits precision ciphertexts on the GPU.
#[derive(Debug)]
pub struct CudaLweKeyswitchKey64(pub(crate) CudaLweKeyswitchKey<u64>);

impl AbstractEntity for CudaLweKeyswitchKey64 {
    type Kind = LweKeyswitchKeyKind;
}

impl LweKeyswitchKeyEntity for CudaLweKeyswitchKey64 {
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_dimension
    }

    fn output_lwe_dimension(&self) -> LweDimension {
        self.0.output_lwe_dimension
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomp_level
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomp_base_log
    }
}
