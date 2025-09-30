use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::{
    AllocateCenteredBinaryShiftedStandardModSwitchResult,
    AllocateDriftTechniqueStandardModSwitchResult, AllocateLweKeyswitchResult,
    AllocateStandardModSwitchResult, CenteredBinaryShiftedStandardModSwitch,
    DriftTechniqueStandardModSwitch, LweKeyswitch, ScalarMul, StandardModSwitch,
};
use crate::core_crypto::gpu::algorithms::lwe_keyswitch::cuda_keyswitch_lwe_ciphertext;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_keyswitch_key::CudaLweKeyswitchKey;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{cuda_modulus_switch_ciphertext, CudaStreams};
use crate::core_crypto::prelude::*;
use crate::integer::gpu::ciphertext::{CudaRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::radix::{CudaBlockInfo, CudaRadixCiphertextInfo};
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};
use crate::integer::gpu::{
    cuda_centered_modulus_switch_64, unchecked_small_scalar_mul_integer_async,
};
use crate::shortint::atomic_pattern::AtomicPatternServerKey;
use crate::shortint::client_key::ClientKey;
use crate::shortint::encoding::{PaddingBit, ShortintEncoding};
use crate::shortint::parameters::{AtomicPatternParameters, CarryModulus, MessageModulus};
//I will wrap the CudaBlockInfo in the resources for simplicity cause the
//CudaLweCiphertextList doesn't contain this info
pub struct CudaSideResources {
    pub streams: CudaStreams,
    pub block_info: CudaBlockInfo,
}

impl CudaSideResources {
    pub fn new(streams: &CudaStreams, block_info: CudaBlockInfo) -> Self {
        Self {
            streams: streams.clone(),
            block_info,
        }
    }
}

/// GPU version of DynLwe for CUDA operations
#[derive(Clone)]
pub enum CudaDynLwe {
    U32(CudaLweCiphertextList<u32>),
    U64(CudaLweCiphertextList<u64>),
    U128(CudaLweCiphertextList<u128>),
}

impl CudaDynLwe {
    pub fn lwe_dimension(&self) -> LweDimension {
        match self {
            Self::U32(cuda_lwe) => cuda_lwe.lwe_dimension(),
            Self::U64(cuda_lwe) => cuda_lwe.lwe_dimension(),
            Self::U128(cuda_lwe) => cuda_lwe.lwe_dimension(),
        }
    }

    pub fn raw_modulus_float(&self) -> f64 {
        match self {
            Self::U32(cuda_lwe) => cuda_lwe.ciphertext_modulus().raw_modulus_float(),
            Self::U64(cuda_lwe) => cuda_lwe.ciphertext_modulus().raw_modulus_float(),
            Self::U128(cuda_lwe) => cuda_lwe.ciphertext_modulus().raw_modulus_float(),
        }
    }

    pub fn as_lwe_32(&self) -> &CudaLweCiphertextList<u32> {
        match self {
            Self::U32(cuda_lwe) => cuda_lwe,
            Self::U64(_) => panic!("Tried getting a u64 CudaLweCiphertextList as u32."),
            Self::U128(_) => panic!("Tried getting a u128 CudaLweCiphertextList as u32."),
        }
    }

    pub fn as_lwe_64(&self) -> &CudaLweCiphertextList<u64> {
        match self {
            Self::U32(_) => panic!("Tried getting a u32 CudaLweCiphertextList as u64."),
            Self::U64(cuda_lwe) => cuda_lwe,
            Self::U128(_) => panic!("Tried getting a u128 CudaLweCiphertextList as u64."),
        }
    }

    pub fn as_lwe_128(&self) -> &CudaLweCiphertextList<u128> {
        match self {
            Self::U32(_) => panic!("Tried getting a u32 CudaLweCiphertextList as u128."),
            Self::U64(_) => panic!("Tried getting a u64 CudaLweCiphertextList as u128."),
            Self::U128(cuda_lwe) => cuda_lwe,
        }
    }

    pub fn into_lwe_32(self) -> CudaLweCiphertextList<u32> {
        match self {
            Self::U32(cuda_lwe) => cuda_lwe,
            Self::U64(_) => panic!("Tried converting a u64 CudaLweCiphertextList to u32."),
            Self::U128(_) => panic!("Tried converting a u128 CudaLweCiphertextList to u32."),
        }
    }

    pub fn into_lwe_64(self) -> CudaLweCiphertextList<u64> {
        match self {
            Self::U32(_) => panic!("Tried converting a u32 CudaLweCiphertextList to u64."),
            Self::U64(cuda_lwe) => cuda_lwe,
            Self::U128(_) => panic!("Tried converting a u128 CudaLweCiphertextList to u64."),
        }
    }

    pub fn into_lwe_128(self) -> CudaLweCiphertextList<u128> {
        match self {
            Self::U32(_) => panic!("Tried converting a u32 CudaLweCiphertextList to u128."),
            Self::U64(_) => panic!("Tried converting a u64 CudaLweCiphertextList to u128."),
            Self::U128(cuda_lwe) => cuda_lwe,
        }
    }

    pub fn from_lwe_32(cuda_lwe: CudaLweCiphertextList<u32>) -> Self {
        Self::U32(cuda_lwe)
    }

    pub fn from_lwe_64(cuda_lwe: CudaLweCiphertextList<u64>) -> Self {
        Self::U64(cuda_lwe)
    }

    pub fn from_lwe_128(cuda_lwe: CudaLweCiphertextList<u128>) -> Self {
        Self::U128(cuda_lwe)
    }
}

impl ScalarMul<u64> for CudaDynLwe {
    type Output = Self;
    type SideResources = CudaSideResources;

    fn scalar_mul(&self, scalar: u64, side_resources: &mut Self::SideResources) -> Self::Output {
        match self {
            Self::U32(cuda_lwe) => {
                panic!("U32 scalar mul not implemented for CudaDynLwe - only U64 is supported")
            }
            Self::U64(cuda_lwe) => {
                // Use the block info from side_resources for proper modulus values
                let mut cuda_radix = CudaRadixCiphertext::new(
                    cuda_lwe.clone(),
                    CudaRadixCiphertextInfo {
                        blocks: vec![side_resources.block_info],
                    },
                );
                unsafe {
                    unchecked_small_scalar_mul_integer_async(
                        &side_resources.streams,
                        &mut cuda_radix,
                        scalar,
                        side_resources.block_info.message_modulus,
                        side_resources.block_info.carry_modulus,
                    );
                    side_resources.streams.synchronize();
                }

                Self::U64(cuda_radix.d_blocks)
            }
            Self::U128(cuda_lwe) => {
                panic!("U128 scalar mul not implemented for CudaDynLwe - only U64 is supported")
            }
        }
    }
}

impl AllocateStandardModSwitchResult for CudaDynLwe {
    type Output = Self;
    type SideResources = CudaSideResources;

    fn allocate_standard_mod_switch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        match self {
            Self::U32(cuda_lwe) => {
                let new_cuda_lwe = CudaLweCiphertextList::new(
                    cuda_lwe.lwe_dimension(),
                    cuda_lwe.lwe_ciphertext_count(),
                    cuda_lwe.ciphertext_modulus(),
                    &side_resources.streams,
                );
                Self::U32(new_cuda_lwe)
            }
            Self::U64(cuda_lwe) => {
                let new_cuda_lwe = CudaLweCiphertextList::new(
                    cuda_lwe.lwe_dimension(),
                    cuda_lwe.lwe_ciphertext_count(),
                    cuda_lwe.ciphertext_modulus(),
                    &side_resources.streams,
                );
                Self::U64(new_cuda_lwe)
            }
            Self::U128(cuda_lwe) => {
                let new_cuda_lwe = CudaLweCiphertextList::new(
                    cuda_lwe.lwe_dimension(),
                    cuda_lwe.lwe_ciphertext_count(),
                    cuda_lwe.ciphertext_modulus(),
                    &side_resources.streams,
                );
                Self::U128(new_cuda_lwe)
            }
        }
    }
}

impl StandardModSwitch<Self> for CudaDynLwe {
    type SideResources = CudaSideResources;

    fn standard_mod_switch(
        &self,
        output_modulus_log: CiphertextModulusLog,
        output: &mut Self,
        side_resources: &mut Self::SideResources,
    ) {
        match (self, output) {
            (Self::U32(input), Self::U32(output_cuda_lwe)) => {
                panic!("U32 modulus switch not implemented for CudaDynLwe - only U64 is supported");
            }
            (Self::U64(input), Self::U64(output_cuda_lwe)) => {
                output_cuda_lwe.0.d_vec.clone_from(&input.0.d_vec);
                cuda_modulus_switch_ciphertext(
                    output_cuda_lwe,
                    output_modulus_log.0 as u32,
                    &side_resources.streams,
                );
            }
            (Self::U128(input), Self::U128(output_cuda_lwe)) => {
                panic!("U128 modulus switch not implemented for CudaDynLwe - only U64 is supported")
            }
            _ => panic!("Inconsistent inputs/outputs for CudaDynLwe StandardModSwitch"),
        }
    }
}

impl AllocateCenteredBinaryShiftedStandardModSwitchResult for CudaDynLwe {
    type Output = Self;
    type SideResources = CudaSideResources;

    fn allocate_centered_binary_shifted_standard_mod_switch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        self.allocate_standard_mod_switch_result(side_resources)
    }
}

impl CenteredBinaryShiftedStandardModSwitch<Self> for CudaDynLwe {
    type SideResources = CudaSideResources;

    fn centered_binary_shifted_and_standard_mod_switch(
        &self,
        output_modulus_log: CiphertextModulusLog,
        output: &mut Self,
        side_resources: &mut Self::SideResources,
    ) {
        match (self, output) {
            (Self::U32(input), Self::U32(output_cuda_lwe)) => {
                output_cuda_lwe.0.d_vec.clone_from(&input.0.d_vec);
                cuda_modulus_switch_ciphertext(
                    output_cuda_lwe,
                    output_modulus_log.0 as u32,
                    &side_resources.streams,
                );
            }
            (Self::U64(input), Self::U64(output_cuda_lwe)) => unsafe {
                cuda_centered_modulus_switch_64(
                    side_resources.streams.ptr[0],
                    0u32,
                    output_cuda_lwe.0.d_vec.as_mut_c_ptr(0),
                    input.0.d_vec.as_c_ptr(0),
                    input.lwe_dimension().0 as u32,
                    output_modulus_log.0 as u32,
                );
                side_resources.streams.synchronize();
            },
            (Self::U128(input), Self::U128(output_cuda_lwe)) => {
                output_cuda_lwe.0.d_vec.clone_from(&input.0.d_vec);
                cuda_modulus_switch_ciphertext(
                    output_cuda_lwe,
                    output_modulus_log.0 as u32,
                    &side_resources.streams,
                );
            }
            _ => panic!("Inconsistent inputs/outputs for CudaDynLwe StandardModSwitch"),
        }
    }
}

impl AllocateDriftTechniqueStandardModSwitchResult for CudaDynLwe {
    type AfterDriftOutput = Self;
    type AfterMsOutput = Self;
    type SideResources = CudaSideResources;

    fn allocate_drift_technique_standard_mod_switch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> (Self::AfterDriftOutput, Self::AfterMsOutput) {
        let after_drift = self.allocate_standard_mod_switch_result(side_resources);
        let after_ms = self.allocate_standard_mod_switch_result(side_resources);
        (after_drift, after_ms)
    }
}

//This one is going to be deprecated soon
impl DriftTechniqueStandardModSwitch<Self, Self, Self> for CudaDynLwe {
    type SideResources = CudaSideResources;

    fn drift_technique_and_standard_mod_switch(
        &self,
        output_modulus_log: CiphertextModulusLog,
        input: &Self,
        after_drift_technique: &mut Self,
        after_mod_switch: &mut Self,
        side_resources: &mut Self::SideResources,
    ) {
        panic!("Drift technique is being deprecated, use other flavors of mod switch instead")
    }
}

impl AllocateLweKeyswitchResult for CudaServerKey {
    type Output = CudaDynLwe;
    type SideResources = CudaSideResources;

    fn allocate_lwe_keyswitch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        let output_lwe_dimension = self
            .key_switching_key
            .output_key_lwe_size()
            .to_lwe_dimension();
        let lwe_ciphertext_count = LweCiphertextCount(1);
        let ciphertext_modulus = self.ciphertext_modulus;

        let cuda_lwe = CudaLweCiphertextList::new(
            output_lwe_dimension,
            lwe_ciphertext_count,
            ciphertext_modulus,
            &side_resources.streams,
        );
        CudaDynLwe::U64(cuda_lwe)
    }
}

impl LweKeyswitch<CudaDynLwe, CudaDynLwe> for CudaServerKey {
    type SideResources = CudaSideResources;

    fn lwe_keyswitch(
        &self,
        input: &CudaDynLwe,
        output: &mut CudaDynLwe,
        side_resources: &mut Self::SideResources,
    ) {
        match (input, output) {
            (CudaDynLwe::U64(input_cuda_lwe), CudaDynLwe::U64(output_cuda_lwe)) => {
                let input_indexes = CudaVec::new(1, &side_resources.streams, 0);
                let output_indexes = CudaVec::new(1, &side_resources.streams, 0);

                cuda_keyswitch_lwe_ciphertext(
                    &self.key_switching_key,
                    input_cuda_lwe,
                    output_cuda_lwe,
                    &input_indexes,
                    &output_indexes,
                    &side_resources.streams,
                );
            }
            (CudaDynLwe::U32(_), CudaDynLwe::U32(_)) => {
                panic!("U32 keyswitch not implemented for CudaServerKey - only U64 is supported");
            }
            (CudaDynLwe::U128(_), CudaDynLwe::U128(_)) => {
                panic!("U128 keyswitch not implemented for CudaServerKey - only U64 is supported");
            }
            _ => panic!("Inconsistent input/output types for CudaDynLwe keyswitch"),
        }
    }
}

impl AllocateDriftTechniqueStandardModSwitchResult for CudaServerKey {
    type AfterDriftOutput = CudaDynLwe;
    type AfterMsOutput = CudaDynLwe;
    type SideResources = CudaSideResources;

    fn allocate_drift_technique_standard_mod_switch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> (Self::AfterDriftOutput, Self::AfterMsOutput) {
        let output_lwe_dimension = self
            .key_switching_key
            .output_key_lwe_size()
            .to_lwe_dimension();
        let lwe_ciphertext_count = LweCiphertextCount(1);
        let ciphertext_modulus = self.ciphertext_modulus;

        let cuda_lwe_after_drift = CudaLweCiphertextList::new(
            output_lwe_dimension,
            lwe_ciphertext_count,
            ciphertext_modulus,
            &side_resources.streams,
        );
        let after_drift = CudaDynLwe::U64(cuda_lwe_after_drift);

        let cuda_lwe_after_ms = CudaLweCiphertextList::new(
            output_lwe_dimension,
            lwe_ciphertext_count,
            ciphertext_modulus,
            &side_resources.streams,
        );
        let after_ms = CudaDynLwe::U64(cuda_lwe_after_ms);

        (after_drift, after_ms)
    }
}

//We won't support this flavor anymore, so just applying a ms
impl DriftTechniqueStandardModSwitch<CudaDynLwe, CudaDynLwe, CudaDynLwe> for CudaServerKey {
    type SideResources = CudaSideResources;

    fn drift_technique_and_standard_mod_switch(
        &self,
        output_modulus_log: CiphertextModulusLog,
        input: &CudaDynLwe,
        after_drift_technique: &mut CudaDynLwe,
        after_mod_switch: &mut CudaDynLwe,
        side_resources: &mut Self::SideResources,
    ) {
        panic!("Drift technique is being deprecated, use other flavors of mod switch instead")
    }
}
