use super::keys::CudaNoiseSquashingKey;
use crate::core_crypto::gpu::lwe_bootstrap_key::{
    CudaHalfhalfBootstrapKey, CudaModulusSwitchNoiseReductionConfiguration,
};
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{
    par_allocate_and_generate_new_half_product_half_rotate_lwe_bootstrap_key, DecompositionBaseLog,
    DecompositionLevelCount, DynamicDistribution, GlweDimension, LweDimension,
    LweHalfProductHalfRotateBootstrapKeyOwned, PolynomialSize,
};
use crate::high_level_api::keys::expanded::{
    ExpandedAtomicPatternNoiseSquashingKey, ExpandedNoiseSquashingKey,
};
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaNoiseSquashingBootstrappingKey};
use crate::integer::noise_squashing::{CompressedNoiseSquashingKey, NoiseSquashingPrivateKey};
use crate::integer::ClientKey;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{
    ModulusSwitchType, NoiseSquashingClassicParameters, NoiseSquashingParameters,
};

/// Decomposition shape of the halfhalf noise squashing key, matching the CPU reference
/// implementation in `zama-ai/tfhe-rs#3947`: the 918 input LWE mask elements are split at 286,
/// and the mask and body GLev ciphertexts of each section carry their own decomposition
/// parameters.
///
/// The shape is fixed rather than derived from [`NoiseSquashingParameters`], which has a single
/// base log and level count and cannot describe it. It is checked against the compute key's LWE
/// dimension at key generation time.
pub(crate) const HALFHALF_INPUT_LWE_DIMENSION: LweDimension = LweDimension(918);
pub(crate) const HALFHALF_SPLIT_INDEX: LweDimension = LweDimension(286);
pub(crate) const HALFHALF_SECTION_1_MASK_BASE_LOG: DecompositionBaseLog = DecompositionBaseLog(32);
pub(crate) const HALFHALF_SECTION_1_MASK_LEVEL: DecompositionLevelCount =
    DecompositionLevelCount(2);
pub(crate) const HALFHALF_SECTION_1_BODY_BASE_LOG: DecompositionBaseLog = DecompositionBaseLog(31);
pub(crate) const HALFHALF_SECTION_1_BODY_LEVEL: DecompositionLevelCount =
    DecompositionLevelCount(2);
pub(crate) const HALFHALF_SECTION_2_MASK_BASE_LOG: DecompositionBaseLog = DecompositionBaseLog(24);
pub(crate) const HALFHALF_SECTION_2_MASK_LEVEL: DecompositionLevelCount =
    DecompositionLevelCount(3);
pub(crate) const HALFHALF_SECTION_2_BODY_BASE_LOG: DecompositionBaseLog = DecompositionBaseLog(31);
pub(crate) const HALFHALF_SECTION_2_BODY_LEVEL: DecompositionLevelCount =
    DecompositionLevelCount(2);

/// Output GLWE shape and noise the decomposition shape above was derived for. They are the ones
/// of `NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128`, the Classic noise squashing
/// parameters the reference implementation uses. The base logs and level counts above only make
/// sense against this output ring and noise, so a different Classic parameter set with the same
/// LWE dimension must not silently reuse them.
pub(crate) const HALFHALF_OUTPUT_GLWE_DIMENSION: GlweDimension = GlweDimension(2);
pub(crate) const HALFHALF_OUTPUT_POLYNOMIAL_SIZE: PolynomialSize = PolynomialSize(2048);
pub(crate) const HALFHALF_GLWE_NOISE_DISTRIBUTION: DynamicDistribution<u128> =
    DynamicDistribution::new_t_uniform(30);

/// Returns the Classic noise squashing parameters a halfhalf key is to be generated from,
/// rejecting anything the reference shape was not derived for.
///
/// Called both when the configuration opts into halfhalf, so the error surfaces at
/// `ConfigBuilder` time, and again at key generation, which can also be reached directly through
/// [`CudaNoiseSquashingKey::new_halfhalf`].
pub(crate) fn halfhalf_classic_parameters(
    compute_lwe_dimension: LweDimension,
    noise_squashing_parameters: NoiseSquashingParameters,
) -> NoiseSquashingClassicParameters {
    let NoiseSquashingParameters::Classic(params) = noise_squashing_parameters else {
        panic!(
            "halfhalf noise squashing requires Classic noise squashing parameters, got {noise_squashing_parameters:?}"
        )
    };

    assert_eq!(
        compute_lwe_dimension, HALFHALF_INPUT_LWE_DIMENSION,
        "halfhalf noise squashing is only defined for a compute LWE dimension of \
         {HALFHALF_INPUT_LWE_DIMENSION:?}",
    );
    assert_eq!(
        params.glwe_dimension, HALFHALF_OUTPUT_GLWE_DIMENSION,
        "halfhalf noise squashing is only defined for an output GLWE dimension of \
         {HALFHALF_OUTPUT_GLWE_DIMENSION:?}",
    );
    assert_eq!(
        params.polynomial_size, HALFHALF_OUTPUT_POLYNOMIAL_SIZE,
        "halfhalf noise squashing is only defined for an output polynomial size of \
         {HALFHALF_OUTPUT_POLYNOMIAL_SIZE:?}",
    );
    assert_eq!(
        params.glwe_noise_distribution, HALFHALF_GLWE_NOISE_DISTRIBUTION,
        "halfhalf noise squashing is only defined for an output GLWE noise distribution of \
         {HALFHALF_GLWE_NOISE_DISTRIBUTION:?}",
    );

    params
}

/// Rejects a halfhalf key whose shape is not the reference one.
///
/// The kernel is only exercised, and its noise only validated, at the reference shape. A key
/// assembled from other parameters (through
/// [`CudaHalfhalfBootstrapKey::from_lwe_half_product_half_rotate_bootstrap_key`], which accepts
/// any shape the CUDA backend can run) would still bootstrap, so nothing downstream would notice.
/// The noise distribution is not part of the key's shape and so cannot be checked here; it is
/// checked by [`halfhalf_classic_parameters`] at generation time.
pub(crate) fn assert_halfhalf_key_has_reference_shape(bsk: &CudaHalfhalfBootstrapKey) {
    let params = bsk.params_ffi();
    let actual = [
        params.input_lwe_dimension as usize,
        params.split_index as usize,
        params.glwe_dimension as usize,
        params.polynomial_size as usize,
        params.base_log_1_mask as usize,
        params.level_count_1_mask as usize,
        params.base_log_1_body as usize,
        params.level_count_1_body as usize,
        params.base_log_2_mask as usize,
        params.level_count_2_mask as usize,
        params.base_log_2_body as usize,
        params.level_count_2_body as usize,
    ];
    let expected = [
        HALFHALF_INPUT_LWE_DIMENSION.0,
        HALFHALF_SPLIT_INDEX.0,
        HALFHALF_OUTPUT_GLWE_DIMENSION.0,
        HALFHALF_OUTPUT_POLYNOMIAL_SIZE.0,
        HALFHALF_SECTION_1_MASK_BASE_LOG.0,
        HALFHALF_SECTION_1_MASK_LEVEL.0,
        HALFHALF_SECTION_1_BODY_BASE_LOG.0,
        HALFHALF_SECTION_1_BODY_LEVEL.0,
        HALFHALF_SECTION_2_MASK_BASE_LOG.0,
        HALFHALF_SECTION_2_MASK_LEVEL.0,
        HALFHALF_SECTION_2_BODY_BASE_LOG.0,
        HALFHALF_SECTION_2_BODY_LEVEL.0,
    ];
    assert_eq!(
        actual, expected,
        "halfhalf noise squashing only supports the reference shape [input_lwe_dimension, \
         split_index, glwe_dimension, polynomial_size, then base log and level count of each \
         section's mask and body]"
    );
}

impl CudaNoiseSquashingKey {
    /// Creates a `CudaNoiseSquashingKey` from an expanded (standard domain) noise squashing key.
    ///
    /// This method converts an already-expanded noise squashing key (in standard domain)
    /// to GPU memory. Use this when you have an `ExpandedNoiseSquashingKey`
    /// from calling `expand()` on a compressed key.
    pub(crate) fn from_expanded_noise_squashing_key(
        expanded: &ExpandedNoiseSquashingKey,
        streams: &CudaStreams,
    ) -> Self {
        let expanded_bsk = match expanded.atomic_pattern() {
            ExpandedAtomicPatternNoiseSquashingKey::Standard(bsk) => bsk,
            ExpandedAtomicPatternNoiseSquashingKey::KeySwitch32(_) => {
                panic!("GPU only supports the Standard atomic pattern")
            }
        };

        let bootstrapping_key =
            CudaBootstrappingKey::from_expanded_bootstrapping_key(expanded_bsk, streams)
                .expect("Unsupported configuration");

        Self {
            bootstrapping_key: bootstrapping_key.into(),
            message_modulus: expanded.message_modulus(),
            carry_modulus: expanded.carry_modulus(),
            output_ciphertext_modulus: expanded.output_ciphertext_modulus(),
        }
    }

    /// Generates a halfhalf (half-product plus half-rotate) noise squashing key directly into
    /// device memory.
    ///
    /// The squashed ciphertexts keep the GLWE dimension, polynomial size, noise distribution and
    /// moduli of `noise_squashing_private_key`; only the bootstrap key's decomposition shape
    /// differs, and it is the fixed reference shape declared at the top of this module. There is
    /// no CPU or seeded counterpart of this key, which is why generation happens here rather than
    /// through the usual expand-then-upload path.
    ///
    /// To put the same key on several GPUs, call
    /// [`generate_halfhalf_noise_squashing_bootstrap_key`] once and
    /// [`Self::from_halfhalf_bootstrap_key`] per GPU: generation dominates the cost.
    ///
    /// # Panics
    ///
    /// Panics if the client key does not use the standard atomic pattern, or if the compute and
    /// noise squashing parameters are not the reference ones (see
    /// [`halfhalf_classic_parameters`]).
    pub fn new_halfhalf(
        client_key: &ClientKey,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
        streams: &CudaStreams,
    ) -> Self {
        let std_bsk = generate_halfhalf_noise_squashing_bootstrap_key(
            client_key,
            noise_squashing_private_key,
        );

        Self::from_halfhalf_bootstrap_key(&std_bsk, noise_squashing_private_key, streams)
    }

    /// Uploads an already generated standard domain halfhalf bootstrap key, converting it to the
    /// Fourier domain on the device.
    ///
    /// `noise_squashing_private_key` only supplies the moduli and the modulus switch choice; the
    /// key material comes from `std_bsk`, which must have been generated from that same private
    /// key.
    pub fn from_halfhalf_bootstrap_key(
        std_bsk: &LweHalfProductHalfRotateBootstrapKeyOwned<u128>,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
        streams: &CudaStreams,
    ) -> Self {
        let NoiseSquashingParameters::Classic(params) =
            noise_squashing_private_key.noise_squashing_parameters()
        else {
            panic!("halfhalf noise squashing requires Classic noise squashing parameters")
        };

        // The halfhalf blind rotation consumes the modulus-switched input exactly like the
        // Classic noise squashing PBS does, so it honours the same modulus switch choice.
        let ms_noise_reduction_configuration = match params.modulus_switch_noise_reduction_params {
            ModulusSwitchType::Standard => None,
            ModulusSwitchType::CenteredMeanNoiseReduction => {
                Some(CudaModulusSwitchNoiseReductionConfiguration::Centered)
            }
            ModulusSwitchType::DriftTechniqueNoiseReduction(_) => {
                panic!("Drift noise reduction is not supported on GPU")
            }
        };

        let bootstrapping_key =
            CudaHalfhalfBootstrapKey::from_lwe_half_product_half_rotate_bootstrap_key(
                std_bsk,
                ms_noise_reduction_configuration,
                streams,
            );

        Self {
            bootstrapping_key: CudaNoiseSquashingBootstrappingKey::Halfhalf(bootstrapping_key),
            message_modulus: params.message_modulus,
            carry_modulus: params.carry_modulus,
            output_ciphertext_modulus: params.ciphertext_modulus,
        }
    }
}

/// Generates the standard domain halfhalf bootstrap key from the compute LWE secret key and the
/// noise squashing private key's GLWE secret key.
///
/// Split out of [`CudaNoiseSquashingKey::new_halfhalf`] because the key is several gigabytes and
/// generating it dominates the cost of putting it on a GPU: a caller needing it on several GPUs
/// generates it once here and uploads it with
/// [`CudaNoiseSquashingKey::from_halfhalf_bootstrap_key`].
pub fn generate_halfhalf_noise_squashing_bootstrap_key(
    client_key: &ClientKey,
    noise_squashing_private_key: &NoiseSquashingPrivateKey,
) -> LweHalfProductHalfRotateBootstrapKeyOwned<u128> {
    let AtomicPatternClientKey::Standard(std_cks) = &client_key.key.atomic_pattern else {
        panic!("Only the standard atomic pattern is supported on GPU")
    };

    let params = halfhalf_classic_parameters(
        std_cks.lwe_secret_key.lwe_dimension(),
        noise_squashing_private_key.noise_squashing_parameters(),
    );

    ShortintEngine::with_thread_local_mut(|engine| {
        par_allocate_and_generate_new_half_product_half_rotate_lwe_bootstrap_key(
            &std_cks.lwe_secret_key,
            noise_squashing_private_key
                .key
                .post_noise_squashing_secret_key(),
            HALFHALF_SPLIT_INDEX,
            HALFHALF_SECTION_1_MASK_BASE_LOG,
            HALFHALF_SECTION_1_MASK_LEVEL,
            HALFHALF_SECTION_1_BODY_BASE_LOG,
            HALFHALF_SECTION_1_BODY_LEVEL,
            HALFHALF_SECTION_2_MASK_BASE_LOG,
            HALFHALF_SECTION_2_MASK_LEVEL,
            HALFHALF_SECTION_2_BODY_BASE_LOG,
            HALFHALF_SECTION_2_BODY_LEVEL,
            params.glwe_noise_distribution,
            params.ciphertext_modulus,
            &mut engine.encryption_generator,
        )
    })
}

impl CompressedNoiseSquashingKey {
    pub fn decompress_to_cuda(&self, streams: &CudaStreams) -> CudaNoiseSquashingKey {
        let expanded = self.expand();

        CudaNoiseSquashingKey::from_expanded_noise_squashing_key(&expanded, streams)
    }
}
