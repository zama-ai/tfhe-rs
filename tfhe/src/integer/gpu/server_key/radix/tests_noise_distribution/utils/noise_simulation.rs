use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::{
    AllocateCenteredBinaryShiftedStandardModSwitchResult,
    AllocateDriftTechniqueStandardModSwitchResult, AllocateLweBootstrapResult,
    AllocateLweKeyswitchResult, AllocateLwePackingKeyswitchResult, AllocateMultiBitModSwitchResult,
    AllocateStandardModSwitchResult, CenteredBinaryShiftedStandardModSwitch,
    DriftTechniqueStandardModSwitch, LweClassicFft128Bootstrap, LweClassicFftBootstrap,
    LweKeyswitch, MultiBitModSwitch, ScalarMul, StandardModSwitch,
};
use crate::core_crypto::commons::noise_formulas::noise_simulation::{
    NoiseSimulationLweFourier128Bsk, NoiseSimulationLweFourierBsk,
};
use crate::core_crypto::gpu::algorithms::lwe_keyswitch::cuda_keyswitch_lwe_ciphertext;
use crate::core_crypto::gpu::cuda_modulus_switch_ciphertext;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_bootstrap_key::CudaModulusSwitchNoiseReductionConfiguration;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_packing_keyswitch_key::CudaLwePackingKeyswitchKey;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::prelude::*;
use crate::integer::gpu::ciphertext::info::CudaBlockInfo;
use crate::integer::gpu::ciphertext::CudaRadixCiphertext;
use crate::integer::gpu::key_switching_key::CudaKeySwitchingKey;
use crate::integer::gpu::server_key::radix::{CudaNoiseSquashingKey, CudaRadixCiphertextInfo};
use crate::integer::gpu::server_key::{
    CudaBootstrappingKey, CudaDynamicKeyswitchingKey, CudaServerKey,
};
use crate::integer::gpu::{
    cuda_centered_modulus_switch_64, unchecked_small_scalar_mul_integer, CudaStreams,
};
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::{
    NoiseSimulationGenericBootstrapKey, NoiseSimulationModulusSwitchConfig,
};
use crate::shortint::server_key::tests::noise_distribution::utils::traits::{
    LweGenericBlindRotate128, LweGenericBootstrap, LwePackingKeyswitch,
};
/// Side resources for CUDA operations in noise simulation
#[derive(Clone)]
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
    pub fn as_ct_64_cpu(&self, streams: &CudaStreams) -> LweCiphertext<Vec<u64>> {
        match self {
            Self::U32(_) => panic!("Tried getting a u32 CudaLweCiphertextList as u64."),
            Self::U64(_cuda_lwe) => {
                let cpu_lwe_list = self.as_lwe_64().to_lwe_ciphertext_list(streams);
                LweCiphertext::from_container(
                    cpu_lwe_list.clone().into_container(),
                    cpu_lwe_list.ciphertext_modulus(),
                )
            }
            Self::U128(_) => panic!("Tried getting a u128 CudaLweCiphertextList as u64."),
        }
    }

    pub fn as_ct_128_cpu(&self, streams: &CudaStreams) -> LweCiphertext<Vec<u128>> {
        match self {
            Self::U32(_) => panic!("Tried getting a u32 CudaLweCiphertextList as u128."),
            Self::U64(_) => panic!("Tried getting a u64 CudaLweCiphertextList as u128."),
            Self::U128(_cuda_lwe) => {
                let cpu_lwe_list = self.as_lwe_128().to_lwe_ciphertext_list(streams);
                LweCiphertext::from_container(
                    cpu_lwe_list.clone().into_container(),
                    cpu_lwe_list.ciphertext_modulus(),
                )
            }
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

/// Converts a CudaGlweCiphertextList<u64> to a GlweCiphertext<Vec<u64>>
pub fn cuda_glwe_list_to_glwe_ciphertext(
    cuda_glwe_list: &CudaGlweCiphertextList<u64>,
    streams: &CudaStreams,
) -> GlweCiphertext<Vec<u64>> {
    let cpu_glwe_list = cuda_glwe_list.to_glwe_ciphertext_list(streams);
    GlweCiphertext::from_container(
        cpu_glwe_list.clone().into_container(),
        cpu_glwe_list.polynomial_size(),
        cpu_glwe_list.ciphertext_modulus(),
    )
}

impl ScalarMul<u64> for CudaDynLwe {
    type Output = Self;
    type SideResources = CudaSideResources;

    fn scalar_mul(&self, scalar: u64, side_resources: &mut Self::SideResources) -> Self::Output {
        match self {
            Self::U32(_cuda_lwe) => {
                panic!("U32 scalar mul not implemented for CudaDynLwe - only U64 is supported")
            }
            Self::U64(cuda_lwe) => {
                // Use the block info from side_resources for proper modulus values
                let mut cuda_radix = CudaRadixCiphertext::new(
                    cuda_lwe.duplicate(&side_resources.streams),
                    CudaRadixCiphertextInfo {
                        blocks: vec![side_resources.block_info],
                    },
                );
                unchecked_small_scalar_mul_integer(
                    &side_resources.streams,
                    &mut cuda_radix,
                    scalar,
                    side_resources.block_info.message_modulus,
                    side_resources.block_info.carry_modulus,
                );
                side_resources.streams.synchronize();

                Self::U64(cuda_radix.d_blocks)
            }
            Self::U128(_cuda_lwe) => {
                panic!("U128 scalar mul not implemented for CudaDynLwe - only U64 is supported")
            }
        }
    }
}

// Extensions for NoiseSimulationLweFourierBsk to support GPU operations
impl NoiseSimulationLweFourierBsk {
    pub fn matches_actual_bsk_gpu(&self, lwe_bsk: &CudaBootstrappingKey<u64>) -> bool {
        let input_lwe_dimension = self.input_lwe_dimension();
        let glwe_size = self.output_glwe_size();
        let polynomial_size = self.output_polynomial_size();
        let decomp_base_log = self.decomp_base_log();
        let decomp_level_count = self.decomp_level_count();

        match lwe_bsk {
            CudaBootstrappingKey::Classic(cuda_bsk) => {
                let bsk_input_lwe_dimension = cuda_bsk.input_lwe_dimension();
                let bsk_glwe_size = cuda_bsk.glwe_dimension().to_glwe_size();
                let bsk_polynomial_size = cuda_bsk.polynomial_size();
                let bsk_decomp_base_log = cuda_bsk.decomp_base_log();
                let bsk_decomp_level_count = cuda_bsk.decomp_level_count();

                input_lwe_dimension == bsk_input_lwe_dimension
                    && glwe_size == bsk_glwe_size
                    && polynomial_size == bsk_polynomial_size
                    && decomp_base_log == bsk_decomp_base_log
                    && decomp_level_count == bsk_decomp_level_count
            }
            // MultiBit key cannot match classic key
            CudaBootstrappingKey::MultiBit(_) => false,
        }
    }
}

// Extensions for NoiseSimulationGenericBootstrapKey to support GPU operations
impl NoiseSimulationGenericBootstrapKey {
    pub fn matches_actual_bsk_gpu(&self, lwe_bsk: &CudaBootstrappingKey<u64>) -> bool {
        match self {
            Self::Classic(noise_simulation_lwe_fourier_bsk) => {
                noise_simulation_lwe_fourier_bsk.matches_actual_bsk_gpu(lwe_bsk)
            }
            Self::MultiBit(_) => todo!(
                "Implement the matching for NoiseSimulationLweMultiBitFourierBsk and forward here"
            ),
        }
    }
}

// Extensions for NoiseSimulationLweFourier128Bsk to support GPU operations (for u128 noise
// squashing)
impl NoiseSimulationLweFourier128Bsk {
    pub fn matches_actual_bsk_gpu(&self, lwe_bsk: &CudaBootstrappingKey<u128>) -> bool {
        let input_lwe_dimension = self.input_lwe_dimension();
        let glwe_size = self.output_glwe_size();
        let polynomial_size = self.output_polynomial_size();
        let decomp_base_log = self.decomp_base_log();
        let decomp_level_count = self.decomp_level_count();

        match lwe_bsk {
            CudaBootstrappingKey::Classic(cuda_bsk) => {
                let bsk_input_lwe_dimension = cuda_bsk.input_lwe_dimension();
                let bsk_glwe_size = cuda_bsk.glwe_dimension().to_glwe_size();
                let bsk_polynomial_size = cuda_bsk.polynomial_size();
                let bsk_decomp_base_log = cuda_bsk.decomp_base_log();
                let bsk_decomp_level_count = cuda_bsk.decomp_level_count();

                input_lwe_dimension == bsk_input_lwe_dimension
                    && glwe_size == bsk_glwe_size
                    && polynomial_size == bsk_polynomial_size
                    && decomp_base_log == bsk_decomp_base_log
                    && decomp_level_count == bsk_decomp_level_count
            }
            CudaBootstrappingKey::MultiBit(cuda_mb_bsk) => {
                let bsk_input_lwe_dimension = cuda_mb_bsk.input_lwe_dimension();
                let bsk_glwe_size = cuda_mb_bsk.glwe_dimension().to_glwe_size();
                let bsk_polynomial_size = cuda_mb_bsk.polynomial_size();
                let bsk_decomp_base_log = cuda_mb_bsk.decomp_base_log();
                let bsk_decomp_level_count = cuda_mb_bsk.decomp_level_count();

                input_lwe_dimension == bsk_input_lwe_dimension
                    && glwe_size == bsk_glwe_size
                    && polynomial_size == bsk_polynomial_size
                    && decomp_base_log == bsk_decomp_base_log
                    && decomp_level_count == bsk_decomp_level_count
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
            (Self::U32(_input), Self::U32(_output_cuda_lwe)) => {
                panic!("U32 modulus switch not implemented for CudaDynLwe - only U64 is supported");
            }
            (Self::U64(input), Self::U64(output_cuda_lwe)) => {
                let mut internal_output = input.duplicate(&side_resources.streams);
                cuda_modulus_switch_ciphertext(
                    &mut internal_output.0.d_vec,
                    output_modulus_log.0 as u32,
                    &side_resources.streams,
                );
                let mut cpu_lwe = internal_output.to_lwe_ciphertext_list(&side_resources.streams);

                let shift_to_map_to_native = u64::BITS - output_modulus_log.0 as u32;
                for val in cpu_lwe.as_mut_view().into_container().iter_mut() {
                    *val <<= shift_to_map_to_native;
                }
                let d_after_ms = CudaLweCiphertextList::from_lwe_ciphertext_list(
                    &cpu_lwe,
                    &side_resources.streams,
                );

                *output_cuda_lwe = d_after_ms;
            }
            (Self::U128(_input), Self::U128(_output_cuda_lwe)) => {
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
            (Self::U32(_input), Self::U32(_output_cuda_lwe)) => {
                panic!("U32 centered binary shifted modulus switch not implemented for CudaDynLwe - only U64 is supported")
            }
            (Self::U64(input), Self::U64(output_cuda_lwe)) => unsafe {
                let mut internal_output = output_cuda_lwe.duplicate(&side_resources.streams);
                cuda_centered_modulus_switch_64(
                    side_resources.streams.ptr[0],
                    0u32,
                    internal_output.0.d_vec.as_mut_c_ptr(0),
                    input.0.d_vec.as_c_ptr(0),
                    input.lwe_dimension().0 as u32,
                    output_modulus_log.0 as u32,
                );
                side_resources.streams.synchronize();
                let cpu_lwe = internal_output.into_lwe_ciphertext(&side_resources.streams);
                let mut cpu_ct = LweCiphertext::from_container(
                    cpu_lwe.clone().into_container(),
                    cpu_lwe.ciphertext_modulus(),
                );
                let shift_to_map_to_native = u64::BITS - output_modulus_log.0 as u32;
                for val in cpu_ct.as_mut() {
                    *val <<= shift_to_map_to_native;
                }
                let d_after_ms =
                    CudaLweCiphertextList::from_lwe_ciphertext(&cpu_ct, &side_resources.streams);
                *output_cuda_lwe = d_after_ms;
            },
            (Self::U128(_input), Self::U128(_output_cuda_lwe)) => {
                panic!("U128 centered binary shifted modulus switch not implemented for CudaDynLwe - only U64 is supported")
            }
            _ => panic!("Inconsistent inputs/outputs for CudaDynLwe StandardModSwitch"),
        }
    }
}

impl DriftTechniqueStandardModSwitch<Self, Self, Self> for CudaDynLwe {
    type SideResources = CudaSideResources;

    fn drift_technique_and_standard_mod_switch(
        &self,
        _output_modulus_log: CiphertextModulusLog,
        _input: &Self,
        _after_drift_technique: &mut Self,
        _after_mod_switch: &mut Self,
        _side_resources: &mut Self::SideResources,
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
        let output_lwe_dimension = match &self.key_switching_key {
            CudaDynamicKeyswitchingKey::Standard(std_key) => {
                std_key.output_key_lwe_size().to_lwe_dimension()
            }
            CudaDynamicKeyswitchingKey::KeySwitch32(ks32_key) => {
                ks32_key.output_key_lwe_size().to_lwe_dimension()
            }
        };
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
            (CudaDynLwe::U64(input_cuda_lwe), CudaDynLwe::U32(output_cuda_lwe)) => {
                let CudaDynamicKeyswitchingKey::KeySwitch32(computing_ks_key) =
                    &self.key_switching_key
                else {
                    panic!("Expecting 32b KSK in Cuda noise simulation tests when LWE is 32b");
                };

                let input_indexes = CudaVec::new(1, &side_resources.streams, 0);
                let output_indexes = CudaVec::new(1, &side_resources.streams, 0);

                cuda_keyswitch_lwe_ciphertext(
                    computing_ks_key,
                    input_cuda_lwe,
                    output_cuda_lwe,
                    &input_indexes,
                    &output_indexes,
                    false,
                    &side_resources.streams,
                    false,
                );
            }
            (CudaDynLwe::U64(input_cuda_lwe), CudaDynLwe::U64(output_cuda_lwe)) => {
                let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) =
                    &self.key_switching_key
                else {
                    panic!("Expecting 64b KSK in Cuda noise simulation tests when LWE is 64b");
                };

                let input_indexes = CudaVec::new(1, &side_resources.streams, 0);
                let output_indexes = CudaVec::new(1, &side_resources.streams, 0);

                cuda_keyswitch_lwe_ciphertext(
                    computing_ks_key,
                    input_cuda_lwe,
                    output_cuda_lwe,
                    &input_indexes,
                    &output_indexes,
                    false,
                    &side_resources.streams,
                    false,
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
        _side_resources: &mut Self::SideResources,
    ) -> (Self::AfterDriftOutput, Self::AfterMsOutput) {
        panic!("Drift technique is being deprecated, use other flavors of mod switch instead")
    }
}

impl DriftTechniqueStandardModSwitch<CudaDynLwe, CudaDynLwe, CudaDynLwe> for CudaServerKey {
    type SideResources = CudaSideResources;

    fn drift_technique_and_standard_mod_switch(
        &self,
        _output_modulus_log: CiphertextModulusLog,
        _input: &CudaDynLwe,
        _after_drift_technique: &mut CudaDynLwe,
        _after_mod_switch: &mut CudaDynLwe,
        _side_resources: &mut Self::SideResources,
    ) {
        panic!("Drift technique is being deprecated, use other flavors of mod switch instead")
    }
}

impl CudaServerKey {
    pub fn br_input_modulus_log(&self) -> CiphertextModulusLog {
        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(bsk) => {
                bsk.polynomial_size().to_blind_rotation_input_modulus_log()
            }
            CudaBootstrappingKey::MultiBit(mb_bsk) => mb_bsk
                .polynomial_size()
                .to_blind_rotation_input_modulus_log(),
        }
    }
    pub fn noise_simulation_modulus_switch_config(
        &self,
    ) -> NoiseSimulationModulusSwitchConfig<&Self> {
        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(bsk) => match &bsk.ms_noise_reduction_configuration {
                None => NoiseSimulationModulusSwitchConfig::Standard,
                Some(CudaModulusSwitchNoiseReductionConfiguration::Centered) => {
                    NoiseSimulationModulusSwitchConfig::CenteredMeanNoiseReduction
                }
            },
            CudaBootstrappingKey::MultiBit(_) => {
                todo!()
            }
        }
    }
}

impl CudaNoiseSquashingKey {
    pub fn noise_simulation_modulus_switch_config(
        &self,
    ) -> NoiseSimulationModulusSwitchConfig<&Self> {
        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(bsk) => match &bsk.ms_noise_reduction_configuration {
                None => NoiseSimulationModulusSwitchConfig::Standard,
                Some(CudaModulusSwitchNoiseReductionConfiguration::Centered) => {
                    NoiseSimulationModulusSwitchConfig::CenteredMeanNoiseReduction
                }
            },
            CudaBootstrappingKey::MultiBit(_) => {
                todo!()
            }
        }
    }
}

impl AllocateDriftTechniqueStandardModSwitchResult for CudaNoiseSquashingKey {
    type AfterDriftOutput = CudaDynLwe;
    type AfterMsOutput = CudaDynLwe;
    type SideResources = CudaSideResources;

    fn allocate_drift_technique_standard_mod_switch_result(
        &self,
        _side_resources: &mut Self::SideResources,
    ) -> (Self::AfterDriftOutput, Self::AfterMsOutput) {
        panic!("Drift technique is being deprecated, use other flavors of mod switch instead")
    }
}

impl DriftTechniqueStandardModSwitch<CudaDynLwe, CudaDynLwe, CudaDynLwe> for CudaNoiseSquashingKey {
    type SideResources = CudaSideResources;

    fn drift_technique_and_standard_mod_switch(
        &self,
        _output_modulus_log: CiphertextModulusLog,
        _input: &CudaDynLwe,
        _after_drift_technique: &mut CudaDynLwe,
        _after_mod_switch: &mut CudaDynLwe,
        _side_resources: &mut Self::SideResources,
    ) {
        panic!("Drift technique is being deprecated, use other flavors of mod switch instead")
    }
}

/// Implementation for CudaGlweCiphertextList<u64> to return CudaDynLwe (for test compatibility)
impl AllocateLweBootstrapResult for CudaGlweCiphertextList<u64> {
    type Output = CudaDynLwe;
    type SideResources = CudaSideResources;

    fn allocate_lwe_bootstrap_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        // For PBS result, we allocate LWE ciphertexts wrapped in CudaDynLwe
        let lwe_dimension = self
            .glwe_dimension()
            .to_equivalent_lwe_dimension(self.polynomial_size());

        let cuda_lwe = CudaLweCiphertextList::new(
            lwe_dimension,
            LweCiphertextCount(1),
            self.ciphertext_modulus(),
            &side_resources.streams,
        );
        CudaDynLwe::U64(cuda_lwe)
    }
}

// Implement LweClassicFftBootstrap for CudaServerKey
impl LweClassicFftBootstrap<CudaDynLwe, CudaDynLwe, CudaGlweCiphertextList<u64>> for CudaServerKey {
    type SideResources = CudaSideResources;

    fn lwe_classic_fft_pbs(
        &self,
        input: &CudaDynLwe,
        output: &mut CudaDynLwe,
        accumulator: &crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList<u64>,
        side_resources: &mut Self::SideResources,
    ) {
        use crate::core_crypto::gpu::algorithms::lwe_programmable_bootstrapping::cuda_programmable_bootstrap_lwe_ciphertext;
        use crate::core_crypto::gpu::vec::CudaVec;
        use crate::integer::gpu::server_key::CudaBootstrappingKey;
        use crate::integer::gpu::CastInto;

        match (input, output) {
            (CudaDynLwe::U64(input_cuda_lwe), CudaDynLwe::U64(output_cuda_lwe)) => {
                // Create indexes for PBS
                let num_ct_blocks = 1;
                let lwe_indexes: Vec<u64> = (0..num_ct_blocks)
                    .map(<usize as CastInto<u64>>::cast_into)
                    .collect();
                let mut d_lut_vector_indexes =
                    unsafe { CudaVec::<u64>::new_async(num_ct_blocks, &side_resources.streams, 0) };
                let mut d_input_indexes =
                    unsafe { CudaVec::<u64>::new_async(num_ct_blocks, &side_resources.streams, 0) };
                let mut d_output_indexes =
                    unsafe { CudaVec::<u64>::new_async(num_ct_blocks, &side_resources.streams, 0) };

                unsafe {
                    d_lut_vector_indexes.copy_from_cpu_async(
                        &lwe_indexes,
                        &side_resources.streams,
                        0,
                    );
                    d_input_indexes.copy_from_cpu_async(&lwe_indexes, &side_resources.streams, 0);
                    d_output_indexes.copy_from_cpu_async(&lwe_indexes, &side_resources.streams, 0);
                }

                match &self.bootstrapping_key {
                    CudaBootstrappingKey::Classic(d_bsk) => {
                        cuda_programmable_bootstrap_lwe_ciphertext(
                            input_cuda_lwe,
                            output_cuda_lwe,
                            accumulator,
                            &d_lut_vector_indexes,
                            &d_output_indexes,
                            &d_input_indexes,
                            d_bsk,
                            &side_resources.streams,
                        );
                    }
                    CudaBootstrappingKey::MultiBit(_d_multibit_bsk) => {
                        panic!("Can not execute MultiBit PBS from classic FFT PBS implementation");
                    }
                }
            }
            _ => panic!("Only U64 PBS is supported for CudaServerKey"),
        }
    }
}

impl AllocateLweBootstrapResult for CudaGlweCiphertextList<u128> {
    type Output = CudaDynLwe;
    type SideResources = CudaSideResources;

    fn allocate_lwe_bootstrap_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        let lwe_dimension = self
            .glwe_dimension()
            .to_equivalent_lwe_dimension(self.polynomial_size());

        let cuda_lwe = CudaLweCiphertextList::<u128>::new(
            lwe_dimension,
            LweCiphertextCount(1),
            self.ciphertext_modulus(),
            &side_resources.streams,
        );
        CudaDynLwe::U128(cuda_lwe)
    }
}

// Implement LweClassicFft128Bootstrap for CudaNoiseSquashingKey using 128-bit PBS CUDA function
impl LweClassicFft128Bootstrap<CudaDynLwe, CudaDynLwe, CudaGlweCiphertextList<u128>>
    for CudaNoiseSquashingKey
{
    type SideResources = CudaSideResources;

    fn lwe_classic_fft_128_pbs(
        &self,
        input: &CudaDynLwe,
        output: &mut CudaDynLwe,
        accumulator: &CudaGlweCiphertextList<u128>,
        side_resources: &mut Self::SideResources,
    ) {
        use crate::core_crypto::gpu::algorithms::lwe_programmable_bootstrapping::cuda_programmable_bootstrap_128_lwe_ciphertext;
        use crate::integer::gpu::server_key::CudaBootstrappingKey;

        match (input, output) {
            (CudaDynLwe::U64(input_cuda_lwe), CudaDynLwe::U128(output_cuda_lwe)) => {
                // Get the bootstrap key from self - it's already u128 type
                let bsk = match &self.bootstrapping_key {
                    CudaBootstrappingKey::Classic(d_bsk) => d_bsk,
                    CudaBootstrappingKey::MultiBit(_) => {
                        panic!("MultiBit bootstrapping keys are not supported for 128-bit PBS");
                    }
                };

                cuda_programmable_bootstrap_128_lwe_ciphertext(
                    input_cuda_lwe,
                    output_cuda_lwe,
                    accumulator,
                    bsk,
                    &side_resources.streams,
                );
            }
            _ => panic!("128-bit PBS expects U64 input and U128 output for CudaDynLwe"),
        }
    }
}

impl AllocateLwePackingKeyswitchResult for CudaLwePackingKeyswitchKey<u64> {
    type Output = CudaGlweCiphertextList<u64>;
    type SideResources = CudaSideResources;

    fn allocate_lwe_packing_keyswitch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        let glwe_dimension = self.output_glwe_size().to_glwe_dimension();
        let polynomial_size = self.output_polynomial_size();
        let ciphertext_modulus = self.ciphertext_modulus();

        CudaGlweCiphertextList::new(
            glwe_dimension,
            polynomial_size,
            GlweCiphertextCount(1),
            ciphertext_modulus,
            &side_resources.streams,
        )
    }
}

impl LwePackingKeyswitch<[&CudaDynLwe], CudaGlweCiphertextList<u64>>
    for CudaLwePackingKeyswitchKey<u64>
{
    type SideResources = CudaSideResources;

    fn keyswitch_lwes_and_pack_in_glwe(
        &self,
        input: &[&CudaDynLwe],
        output: &mut CudaGlweCiphertextList<u64>,
        side_resources: &mut CudaSideResources,
    ) {
        use crate::core_crypto::gpu::algorithms::lwe_packing_keyswitch::cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_64;
        let input_lwe_ciphertext_list = CudaLweCiphertextList::from_vec_cuda_lwe_ciphertexts_list(
            input.iter().map(|ciphertext| ciphertext.as_lwe_64()),
            &side_resources.streams,
        );

        cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_64(
            self,
            &input_lwe_ciphertext_list,
            output,
            &side_resources.streams,
        );
    }
}

// Implement StandardModSwitch traits for CudaGlweCiphertextList<u64>
impl AllocateStandardModSwitchResult for CudaGlweCiphertextList<u64> {
    type Output = Self;
    type SideResources = CudaSideResources;

    fn allocate_standard_mod_switch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        Self::new(
            self.glwe_dimension(),
            self.polynomial_size(),
            self.glwe_ciphertext_count(),
            self.ciphertext_modulus(),
            &side_resources.streams,
        )
    }
}

impl StandardModSwitch<Self> for CudaGlweCiphertextList<u64> {
    type SideResources = CudaSideResources;

    fn standard_mod_switch(
        &self,
        storage_log_modulus: CiphertextModulusLog,
        output: &mut Self,
        side_resources: &mut CudaSideResources,
    ) {
        let mut internal_output = self.duplicate(&side_resources.streams);

        cuda_modulus_switch_ciphertext(
            &mut internal_output.0.d_vec,
            storage_log_modulus.0 as u32,
            &side_resources.streams,
        );
        side_resources.streams.synchronize();
        let mut cpu_glwe = internal_output.to_glwe_ciphertext_list(&side_resources.streams);

        let shift_to_map_to_native = u64::BITS - storage_log_modulus.0 as u32;
        for val in cpu_glwe.as_mut_view().into_container().iter_mut() {
            *val <<= shift_to_map_to_native;
        }
        let d_after_ms = Self::from_glwe_ciphertext_list(&cpu_glwe, &side_resources.streams);

        *output = d_after_ms;
    }
}

impl AllocateLwePackingKeyswitchResult for CudaLwePackingKeyswitchKey<u128> {
    type Output = CudaGlweCiphertextList<u128>;
    type SideResources = CudaSideResources;

    fn allocate_lwe_packing_keyswitch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        let glwe_dimension = self.output_glwe_size().to_glwe_dimension();
        let polynomial_size = self.output_polynomial_size();
        let ciphertext_modulus = self.ciphertext_modulus();

        CudaGlweCiphertextList::new(
            glwe_dimension,
            polynomial_size,
            GlweCiphertextCount(1),
            ciphertext_modulus,
            &side_resources.streams,
        )
    }
}

impl LwePackingKeyswitch<[&CudaDynLwe], CudaGlweCiphertextList<u128>>
    for CudaLwePackingKeyswitchKey<u128>
{
    type SideResources = CudaSideResources;

    fn keyswitch_lwes_and_pack_in_glwe(
        &self,
        input: &[&CudaDynLwe],
        output: &mut CudaGlweCiphertextList<u128>,
        side_resources: &mut CudaSideResources,
    ) {
        use crate::core_crypto::gpu::algorithms::lwe_packing_keyswitch::cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_128;
        let input_lwe_ciphertext_list = CudaLweCiphertextList::from_vec_cuda_lwe_ciphertexts_list(
            input.iter().map(|ciphertext| ciphertext.as_lwe_128()),
            &side_resources.streams,
        );

        cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_128(
            self,
            &input_lwe_ciphertext_list,
            output,
            &side_resources.streams,
        );
    }
}

// Multi bit and generic extensions
impl LweGenericBootstrap<CudaDynLwe, CudaDynLwe, CudaGlweCiphertextList<u64>> for CudaServerKey {
    type SideResources = CudaSideResources;

    fn lwe_generic_bootstrap(
        &self,
        input: &CudaDynLwe,
        output: &mut CudaDynLwe,
        accumulator: &CudaGlweCiphertextList<u64>,
        side_resources: &mut Self::SideResources,
    ) {
        match self.bootstrapping_key {
            CudaBootstrappingKey::Classic(_) => {
                self.lwe_classic_fft_pbs(input, output, accumulator, side_resources);
            }
            CudaBootstrappingKey::MultiBit(_) => {
                todo!("TODO: this currently only manages classic PBS")
            }
        }
    }
}

impl AllocateMultiBitModSwitchResult for CudaDynLwe {
    type Output = Self;
    type SideResources = CudaSideResources;

    fn allocate_multi_bit_mod_switch_result(
        &self,
        _side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        todo!(
            "TODO: the output type likely needs to be a specialized enum CudaDynModSwitchedLwe\n\
            See shortint CPU impls, the standard mod switch results likely \
            need an update for the output type"
        )
    }
}

impl MultiBitModSwitch<Self> for CudaDynLwe {
    type SideResources = CudaSideResources;

    fn multi_bit_mod_switch(
        &self,
        _grouping_factor: LweBskGroupingFactor,
        _output_modulus_log: CiphertextModulusLog,
        _output: &mut Self,
        _side_resources: &mut Self::SideResources,
    ) {
        todo!(
            "TODO: the output type likely needs to be a specialized enum CudaDynModSwitchedLwe\n\
            See shortint CPU impls, the standard mod switch results likely \
            need an update for the output type"
        )
    }
}

impl LweGenericBlindRotate128<CudaDynLwe, CudaDynLwe, CudaGlweCiphertextList<u128>>
    for CudaNoiseSquashingKey
{
    type SideResources = CudaSideResources;

    fn lwe_generic_blind_rotate_128(
        &self,
        input: &CudaDynLwe,
        output: &mut CudaDynLwe,
        accumulator: &CudaGlweCiphertextList<u128>,
        side_resources: &mut Self::SideResources,
    ) {
        match self.bootstrapping_key {
            CudaBootstrappingKey::Classic(_) => {
                self.lwe_classic_fft_128_pbs(input, output, accumulator, side_resources)
            }
            CudaBootstrappingKey::MultiBit(_) => todo!(
                "CPU manages this by taking a modswitched type to be able to apply \
                the blind rotate correctly without redoing the modswitch, to adapt for the GPU case"
            ),
        }
    }
}

// Trait implementations for CudaKeySwitchingKey to enable noise distribution tests
impl AllocateLweKeyswitchResult for CudaKeySwitchingKey<'_> {
    type Output = CudaDynLwe;
    type SideResources = CudaSideResources;

    fn allocate_lwe_keyswitch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        let output_lwe_dimension = self
            .key_switching_key_material
            .lwe_keyswitch_key
            .output_key_lwe_size()
            .to_lwe_dimension();
        let lwe_ciphertext_count = LweCiphertextCount(1);
        let ciphertext_modulus = self.dest_server_key.ciphertext_modulus;

        let cuda_lwe = CudaLweCiphertextList::new(
            output_lwe_dimension,
            lwe_ciphertext_count,
            ciphertext_modulus,
            &side_resources.streams,
        );
        CudaDynLwe::U64(cuda_lwe)
    }
}

impl LweKeyswitch<CudaDynLwe, CudaDynLwe> for CudaKeySwitchingKey<'_> {
    type SideResources = CudaSideResources;

    fn lwe_keyswitch(
        &self,
        input: &CudaDynLwe,
        output: &mut CudaDynLwe,
        side_resources: &mut Self::SideResources,
    ) {
        match (input, output) {
            (CudaDynLwe::U64(input_cuda_lwe), CudaDynLwe::U64(output_cuda_lwe)) => {
                let d_input_indexes = CudaVec::<u64>::new(1, &side_resources.streams, 0);
                let d_output_indexes = CudaVec::<u64>::new(1, &side_resources.streams, 0);

                cuda_keyswitch_lwe_ciphertext(
                    &self.key_switching_key_material.lwe_keyswitch_key,
                    input_cuda_lwe,
                    output_cuda_lwe,
                    &d_input_indexes,
                    &d_output_indexes,
                    false,
                    &side_resources.streams,
                    false,
                );
            }
            (CudaDynLwe::U32(_), CudaDynLwe::U32(_)) => {
                panic!(
                    "U32 keyswitch not implemented for CudaKeySwitchingKey - only U64 is supported"
                );
            }
            (CudaDynLwe::U128(_), CudaDynLwe::U128(_)) => {
                panic!("U128 keyswitch not implemented for CudaKeySwitchingKey - only U64 is supported");
            }
            _ => panic!("Inconsistent input/output types for CudaDynLwe keyswitch"),
        }
    }
}
