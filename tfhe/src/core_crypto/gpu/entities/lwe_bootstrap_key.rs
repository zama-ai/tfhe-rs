use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{
    convert_lwe_programmable_bootstrap_key_128_halfhalf_async,
    convert_lwe_programmable_bootstrap_key_async, CudaStreams,
};
use crate::core_crypto::prelude::{
    lwe_bootstrap_key_size, Container, DecompositionBaseLog, DecompositionLevelCount,
    GlweDimension, LweBootstrapKey, LweDimension, LweHalfProductBootstrapKey,
    LweHalfProductHalfRotateBootstrapKey, PolynomialSize, UnsignedInteger,
};
use crate::shortint::server_key::ModulusSwitchConfiguration;
use tfhe_cuda_backend::bindings::{
    CudaHalfhalfPbsParamsFFI, CudaLweBootstrapKeyParamsFFI, PBS_TYPE_CLASSICAL,
};

pub(crate) trait CudaBskParams {
    fn params_ffi(&self) -> CudaLweBootstrapKeyParamsFFI;
}

/// The bootstrap key properties the 128-bit PBS entry points check their operands against.
///
/// Implemented by every key the 128-bit PBS accepts so that they share a single check.
pub(crate) trait CudaPbs128BootstrapKey {
    fn input_lwe_dimension(&self) -> LweDimension;
    fn output_lwe_dimension(&self) -> LweDimension;
    fn glwe_dimension(&self) -> GlweDimension;
    fn polynomial_size(&self) -> PolynomialSize;
    fn d_vec(&self) -> &CudaVec<f64>;
}

#[derive(Clone, Debug)]
pub enum CudaModulusSwitchNoiseReductionConfiguration {
    Centered,
}

impl CudaModulusSwitchNoiseReductionConfiguration {
    pub fn from_modulus_switch_configuration<Scalar>(
        modulus_switch_noise_reduction_key: &ModulusSwitchConfiguration<Scalar>,
    ) -> crate::Result<Option<Self>>
    where
        Scalar: UnsignedInteger,
    {
        match modulus_switch_noise_reduction_key {
            ModulusSwitchConfiguration::Standard => Ok(None),
            ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(_) => Err(crate::error!(
                "GPU does not support drift noise reduction technique"
            )),
            ModulusSwitchConfiguration::CenteredMeanNoiseReduction => Ok(Some(Self::Centered)),
        }
    }
}

/// A structure representing a vector of GLWE ciphertexts with 64 bits of precision on the GPU.
#[derive(Debug)]
#[allow(dead_code)]
pub struct CudaLweBootstrapKey {
    // Pointers to GPU data
    pub(crate) d_vec: CudaVec<f64>,
    // Lwe dimension
    pub(crate) input_lwe_dimension: LweDimension,
    // Glwe dimension
    pub(crate) glwe_dimension: GlweDimension,
    // Polynomial size
    pub(crate) polynomial_size: PolynomialSize,
    // Base log
    pub(crate) decomp_base_log: DecompositionBaseLog,
    // Decomposition level count
    pub(crate) decomp_level_count: DecompositionLevelCount,
    // Pointer to the noise reduction key
    pub(crate) ms_noise_reduction_configuration:
        Option<CudaModulusSwitchNoiseReductionConfiguration>,
}

#[allow(dead_code)]
impl CudaLweBootstrapKey {
    pub fn from_lwe_bootstrap_key<InputBskCont: Container>(
        bsk: &LweBootstrapKey<InputBskCont>,
        ms_noise_reduction_configuration: Option<CudaModulusSwitchNoiseReductionConfiguration>,
        streams: &CudaStreams,
    ) -> Self
    where
        InputBskCont::Element: UnsignedInteger,
    {
        let input_lwe_dimension = bsk.input_lwe_dimension();
        let polynomial_size = bsk.polynomial_size();
        let decomp_level_count = bsk.decomposition_level_count();
        let decomp_base_log = bsk.decomposition_base_log();
        let glwe_dimension = bsk.glwe_size().to_glwe_dimension();
        let double_count = if size_of::<InputBskCont::Element>() == 16 {
            2
        } else {
            1
        };

        // Allocate memory
        let mut d_vec = CudaVec::<f64>::new_multi_gpu(
            lwe_bootstrap_key_size(
                input_lwe_dimension,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                decomp_level_count,
            ) * double_count,
            streams,
        );
        // Copy to the GPU

        unsafe {
            convert_lwe_programmable_bootstrap_key_async(
                streams,
                &mut d_vec,
                bsk.as_ref(),
                input_lwe_dimension,
                glwe_dimension,
                decomp_level_count,
                polynomial_size,
            );
        }

        streams.synchronize();
        Self {
            d_vec,
            input_lwe_dimension,
            glwe_dimension,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ms_noise_reduction_configuration,
        }
    }

    pub(crate) fn input_lwe_dimension(&self) -> LweDimension {
        self.input_lwe_dimension
    }

    pub(crate) fn output_lwe_dimension(&self) -> LweDimension {
        self.glwe_dimension
            .to_equivalent_lwe_dimension(self.polynomial_size)
    }

    pub(crate) fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }

    pub(crate) fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub(crate) fn decomp_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }
    pub(crate) fn decomp_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }
}

impl CudaBskParams for CudaLweBootstrapKey {
    fn params_ffi(&self) -> CudaLweBootstrapKeyParamsFFI {
        CudaLweBootstrapKeyParamsFFI {
            input_lwe_dimension: u32::try_from(self.input_lwe_dimension.0).unwrap(),
            glwe_dimension: u32::try_from(self.glwe_dimension.0).unwrap(),
            polynomial_size: u32::try_from(self.polynomial_size.0).unwrap(),
            base_log: u32::try_from(self.decomp_base_log.0).unwrap(),
            level_count: u32::try_from(self.decomp_level_count.0).unwrap(),
            big_lwe_dimension: u32::try_from(
                self.glwe_dimension
                    .to_equivalent_lwe_dimension(self.polynomial_size)
                    .0,
            )
            .unwrap(),
            pbs_type: PBS_TYPE_CLASSICAL,
            grouping_factor: 0,
        }
    }
}

impl CudaPbs128BootstrapKey for CudaLweBootstrapKey {
    fn input_lwe_dimension(&self) -> LweDimension {
        self.input_lwe_dimension
    }

    fn output_lwe_dimension(&self) -> LweDimension {
        self.glwe_dimension
            .to_equivalent_lwe_dimension(self.polynomial_size)
    }

    fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    fn d_vec(&self) -> &CudaVec<f64> {
        &self.d_vec
    }
}

/// A "halfhalf" (half-product plus half-rotate) bootstrap key on the GPU, in the Fourier domain,
/// with 128 bits of precision.
///
/// It is the GPU counterpart of [`LweHalfProductHalfRotateBootstrapKey`]: the input LWE mask is
/// split in two sections, and within a section the mask and the body GLev ciphertexts use
/// different decomposition parameters.
#[derive(Debug)]
pub struct CudaHalfhalfBootstrapKey {
    pub(crate) d_vec: CudaVec<f64>,
    pub(crate) input_lwe_dimension: LweDimension,
    pub(crate) glwe_dimension: GlweDimension,
    pub(crate) polynomial_size: PolynomialSize,
    pub(crate) halfhalf_params: CudaHalfhalfPbsParamsFFI,
    pub(crate) ms_noise_reduction_configuration:
        Option<CudaModulusSwitchNoiseReductionConfiguration>,
}

impl CudaHalfhalfBootstrapKey {
    /// Upload a standard domain [`LweHalfProductHalfRotateBootstrapKey`] to the GPU, where it is
    /// converted to the Fourier domain.
    ///
    /// The two sections are copied into a single contiguous buffer, which the device side
    /// conversion splits back into its two groups. That staging copy is as large as the whole
    /// standard domain key; it is accepted rather than avoided with a zero-copy path because a
    /// key is converted once and then reused for every bootstrap.
    pub fn from_lwe_half_product_half_rotate_bootstrap_key<C>(
        bsk: &LweHalfProductHalfRotateBootstrapKey<C>,
        ms_noise_reduction_configuration: Option<CudaModulusSwitchNoiseReductionConfiguration>,
        streams: &CudaStreams,
    ) -> Self
    where
        C: Container<Element = u128>,
    {
        assert!(
            bsk.start()
                .ciphertext_modulus()
                .is_compatible_with_native_modulus(),
            "GPU halfhalf PBS only supports power of 2 moduli for the bootstrap key"
        );

        let halfhalf_params = halfhalf_pbs_params_ffi(bsk);
        let standard_bsk = [bsk.start().as_ref(), bsk.end().as_ref()].concat();

        let expected_len = Self::standard_domain_element_count(&halfhalf_params);
        assert_eq!(
            standard_bsk.len(),
            expected_len,
            "Halfhalf bootstrap key holds {} u128 elements, its parameters describe {expected_len}",
            standard_bsk.len(),
        );

        let mut d_vec =
            CudaVec::<f64>::new_multi_gpu(Self::fourier_element_count(&halfhalf_params), streams);

        // SAFETY: the conversion reads `standard_bsk` until the synchronization below, and
        // `d_vec` is sized from the parameters the conversion derives its group offsets from.
        unsafe {
            convert_lwe_programmable_bootstrap_key_128_halfhalf_async(
                streams,
                &mut d_vec,
                &standard_bsk,
                halfhalf_params,
            );
        }
        streams.synchronize();

        Self {
            d_vec,
            input_lwe_dimension: LweDimension(halfhalf_params.input_lwe_dimension as usize),
            glwe_dimension: GlweDimension(halfhalf_params.glwe_dimension as usize),
            polynomial_size: PolynomialSize(halfhalf_params.polynomial_size as usize),
            halfhalf_params,
            ms_noise_reduction_configuration,
        }
    }

    pub(crate) fn params_ffi(&self) -> CudaHalfhalfPbsParamsFFI {
        self.halfhalf_params
    }

    /// Number of polynomials of both sections together, in either domain.
    fn polynomial_count(params: &CudaHalfhalfPbsParamsFFI) -> usize {
        let glwe_dimension = params.glwe_dimension as usize;
        let glwe_size = glwe_dimension + 1;
        let split_index = params.split_index as usize;
        let input_lwe_dimension = params.input_lwe_dimension as usize;

        let start = split_index
            * glwe_size
            * (glwe_dimension * params.level_count_1_mask as usize
                + params.level_count_1_body as usize);
        let end = (input_lwe_dimension - split_index)
            * glwe_size
            * (glwe_dimension * params.level_count_2_mask as usize
                + params.level_count_2_body as usize);
        start + end
    }

    /// Number of `f64` elements of the Fourier domain key: the f128 representation stores four
    /// doubles per complex coefficient, for `polynomial_size / 2` coefficients.
    fn fourier_element_count(params: &CudaHalfhalfPbsParamsFFI) -> usize {
        Self::polynomial_count(params) * (params.polynomial_size as usize / 2) * 4
    }

    fn standard_domain_element_count(params: &CudaHalfhalfPbsParamsFFI) -> usize {
        Self::polynomial_count(params) * params.polynomial_size as usize
    }
}

impl CudaPbs128BootstrapKey for CudaHalfhalfBootstrapKey {
    fn input_lwe_dimension(&self) -> LweDimension {
        self.input_lwe_dimension
    }

    fn output_lwe_dimension(&self) -> LweDimension {
        self.glwe_dimension
            .to_equivalent_lwe_dimension(self.polynomial_size)
    }

    fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    fn d_vec(&self) -> &CudaVec<f64> {
        &self.d_vec
    }
}

fn halfhalf_pbs_params_ffi<C>(
    bsk: &LweHalfProductHalfRotateBootstrapKey<C>,
) -> CudaHalfhalfPbsParamsFFI
where
    C: Container<Element = u128>,
{
    let start = bsk.start();
    let end = bsk.end();
    assert_section_decomposition_supported(start, "start");
    assert_section_decomposition_supported(end, "end");
    // Mirrors validate_halfhalf_params in the CUDA backend, which aborts the process instead of
    // unwinding: 0 < split_index < input_lwe_dimension.
    assert!(
        start.input_lwe_dimension().0 > 0 && end.input_lwe_dimension().0 > 0,
        "GPU halfhalf PBS requires both sections to cover at least one input LWE mask element, \
        the start section covers {} and the end section covers {}",
        start.input_lwe_dimension().0,
        end.input_lwe_dimension().0,
    );

    CudaHalfhalfPbsParamsFFI {
        input_lwe_dimension: u32::try_from(bsk.input_lwe_dimension().0).unwrap(),
        glwe_dimension: u32::try_from(bsk.glwe_size().to_glwe_dimension().0).unwrap(),
        polynomial_size: u32::try_from(bsk.polynomial_size().0).unwrap(),
        base_log_1_mask: u32::try_from(start.decomposition_base_log_mask().0).unwrap(),
        level_count_1_mask: u32::try_from(start.decomposition_level_count_mask().0).unwrap(),
        base_log_1_body: u32::try_from(start.decomposition_base_log_body().0).unwrap(),
        level_count_1_body: u32::try_from(start.decomposition_level_count_body().0).unwrap(),
        base_log_2_mask: u32::try_from(end.decomposition_base_log_mask().0).unwrap(),
        level_count_2_mask: u32::try_from(end.decomposition_level_count_mask().0).unwrap(),
        base_log_2_body: u32::try_from(end.decomposition_base_log_body().0).unwrap(),
        level_count_2_body: u32::try_from(end.decomposition_level_count_body().0).unwrap(),
        split_index: u32::try_from(start.input_lwe_dimension().0).unwrap(),
    }
}

fn assert_section_decomposition_supported<C>(section: &LweHalfProductBootstrapKey<C>, name: &str)
where
    C: Container<Element = u128>,
{
    let base_log_mask = section.decomposition_base_log_mask();
    let level_count_mask = section.decomposition_level_count_mask();
    let base_log_body = section.decomposition_base_log_body();
    let level_count_body = section.decomposition_level_count_body();

    assert!(
        level_count_mask.0 >= level_count_body.0,
        "GPU restriction: the {name} section has {} mask levels and {} body levels, but the GPU \
        halfhalf PBS requires level_count_mask >= level_count_body. Its grid has one z slice per \
        mask level and the body GLev reuses those slices, and the join buffer between the two \
        kernel steps is strided by the mask level count. \
        LweHalfProductHalfRotateBootstrapKey itself allows more body levels than mask levels.",
        level_count_mask.0,
        level_count_body.0,
    );

    // LweHalfProductBootstrapKey::from_container only checks that the container length is a
    // multiple of the GGSW size, so a key built through it reaches us with its decomposition
    // parameters unvalidated. The checks below mirror validate_halfhalf_params in the CUDA
    // backend, which aborts the process instead of unwinding.
    assert!(
        level_count_body.0 > 0,
        "The {name} section has no body level, the GPU halfhalf PBS requires at least one"
    );
    assert!(
        base_log_mask.0 * level_count_mask.0 <= 128,
        "The {name} section decomposes the mask over {} levels of base log {}, which exceeds the \
        128 bits of the ciphertext modulus",
        level_count_mask.0,
        base_log_mask.0,
    );
    assert!(
        base_log_body.0 * level_count_body.0 <= 128,
        "The {name} section decomposes the body over {} levels of base log {}, which exceeds the \
        128 bits of the ciphertext modulus",
        level_count_body.0,
        base_log_body.0,
    );
}
