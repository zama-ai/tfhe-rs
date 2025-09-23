use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::noise_formulas::lwe_multi_bit_programmable_bootstrap::{
    multi_bit_pbs_variance_132_bits_security_gaussian_gf_2_fft_mul,
    multi_bit_pbs_variance_132_bits_security_gaussian_gf_3_fft_mul,
    multi_bit_pbs_variance_132_bits_security_gaussian_gf_4_fft_mul,
    multi_bit_pbs_variance_132_bits_security_tuniform_gf_2_fft_mul,
    multi_bit_pbs_variance_132_bits_security_tuniform_gf_3_fft_mul,
    multi_bit_pbs_variance_132_bits_security_tuniform_gf_4_fft_mul,
};
use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::LweMultiBitFftBlindRotate;
use crate::core_crypto::commons::noise_formulas::noise_simulation::{
    NoiseSimulationGlwe, NoiseSimulationLwe, NoiseSimulationModulus,
};
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweSize,
    LweBskGroupingFactor, LweDimension, PolynomialSize,
};
use crate::core_crypto::commons::traits::container::Container;
use crate::core_crypto::entities::lwe_multi_bit_bootstrap_key::FourierLweMultiBitBootstrapKey;
use crate::core_crypto::fft_impl::fft64::c64;

#[derive(Clone, Copy)]
pub struct NoiseSimulationLweMultiBitFourierBsk {
    input_lwe_dimension: LweDimension,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    grouping_factor: LweBskGroupingFactor,
    noise_distribution: DynamicDistribution<u64>,
    modulus: NoiseSimulationModulus,
}

impl NoiseSimulationLweMultiBitFourierBsk {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        input_lwe_dimension: LweDimension,
        output_glwe_size: GlweSize,
        output_polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        grouping_factor: LweBskGroupingFactor,
        noise_distribution: DynamicDistribution<u64>,
        modulus: NoiseSimulationModulus,
    ) -> Self {
        Self {
            input_lwe_dimension,
            output_glwe_size,
            output_polynomial_size,
            decomp_base_log,
            decomp_level_count,
            grouping_factor,
            noise_distribution,
            modulus,
        }
    }

    pub fn matches_actual_bsk<C: Container<Element = c64>>(
        &self,
        lwe_bsk: &FourierLweMultiBitBootstrapKey<C>,
    ) -> bool {
        let Self {
            input_lwe_dimension,
            output_glwe_size: glwe_size,
            output_polynomial_size: polynomial_size,
            decomp_base_log,
            decomp_level_count,
            grouping_factor,
            noise_distribution: _,
            modulus: _,
        } = *self;

        let bsk_input_lwe_dimension = lwe_bsk.input_lwe_dimension();
        let bsk_glwe_size = lwe_bsk.glwe_size();
        let bsk_polynomial_size = lwe_bsk.polynomial_size();
        let bsk_decomp_base_log = lwe_bsk.decomposition_base_log();
        let bsk_decomp_level_count = lwe_bsk.decomposition_level_count();
        let bsk_grouping_factor = lwe_bsk.grouping_factor();

        input_lwe_dimension == bsk_input_lwe_dimension
            && glwe_size == bsk_glwe_size
            && polynomial_size == bsk_polynomial_size
            && decomp_base_log == bsk_decomp_base_log
            && decomp_level_count == bsk_decomp_level_count
            && grouping_factor == bsk_grouping_factor
    }

    pub fn input_lwe_dimension(&self) -> LweDimension {
        self.input_lwe_dimension
    }

    pub fn output_glwe_size(&self) -> GlweSize {
        self.output_glwe_size
    }

    pub fn output_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }

    pub fn decomp_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomp_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    pub fn grouping_factor(&self) -> LweBskGroupingFactor {
        self.grouping_factor
    }

    pub fn noise_distribution(&self) -> DynamicDistribution<u64> {
        self.noise_distribution
    }

    pub fn modulus(&self) -> NoiseSimulationModulus {
        self.modulus
    }
}

impl LweMultiBitFftBlindRotate<NoiseSimulationLwe, NoiseSimulationLwe, NoiseSimulationGlwe>
    for NoiseSimulationLweMultiBitFourierBsk
{
    type SideResources = ();

    fn lwe_multi_bit_fft_blind_rotate(
        &self,
        input: &NoiseSimulationLwe,
        output: &mut NoiseSimulationLwe,
        accumulator: &NoiseSimulationGlwe,
        _side_resources: &mut Self::SideResources,
    ) {
        assert_eq!(self.input_lwe_dimension(), input.lwe_dimension());
        assert_eq!(
            self.output_glwe_size(),
            accumulator.glwe_dimension().to_glwe_size()
        );
        assert_eq!(self.output_polynomial_size(), accumulator.polynomial_size());
        assert_eq!(self.modulus(), accumulator.modulus());
        let grouping_factor = self.grouping_factor();

        let br_additive_variance = match self.noise_distribution() {
            DynamicDistribution::Gaussian(_) => match grouping_factor.0 {
                2 => multi_bit_pbs_variance_132_bits_security_gaussian_gf_2_fft_mul(
                    self.input_lwe_dimension(),
                    self.output_glwe_size().to_glwe_dimension(),
                    self.output_polynomial_size(),
                    self.decomp_base_log(),
                    self.decomp_level_count(),
                    self.modulus().as_f64(),
                ),
                3 => multi_bit_pbs_variance_132_bits_security_gaussian_gf_3_fft_mul(
                    self.input_lwe_dimension(),
                    self.output_glwe_size().to_glwe_dimension(),
                    self.output_polynomial_size(),
                    self.decomp_base_log(),
                    self.decomp_level_count(),
                    self.modulus().as_f64(),
                ),
                4 => multi_bit_pbs_variance_132_bits_security_gaussian_gf_4_fft_mul(
                    self.input_lwe_dimension(),
                    self.output_glwe_size().to_glwe_dimension(),
                    self.output_polynomial_size(),
                    self.decomp_base_log(),
                    self.decomp_level_count(),
                    self.modulus().as_f64(),
                ),
                gf => panic!("Unsupported grouping factor: {gf}"),
            },
            DynamicDistribution::TUniform(_) => match grouping_factor.0 {
                2 => multi_bit_pbs_variance_132_bits_security_tuniform_gf_2_fft_mul(
                    self.input_lwe_dimension(),
                    self.output_glwe_size().to_glwe_dimension(),
                    self.output_polynomial_size(),
                    self.decomp_base_log(),
                    self.decomp_level_count(),
                    self.modulus().as_f64(),
                ),
                3 => multi_bit_pbs_variance_132_bits_security_tuniform_gf_3_fft_mul(
                    self.input_lwe_dimension(),
                    self.output_glwe_size().to_glwe_dimension(),
                    self.output_polynomial_size(),
                    self.decomp_base_log(),
                    self.decomp_level_count(),
                    self.modulus().as_f64(),
                ),
                4 => multi_bit_pbs_variance_132_bits_security_tuniform_gf_4_fft_mul(
                    self.input_lwe_dimension(),
                    self.output_glwe_size().to_glwe_dimension(),
                    self.output_polynomial_size(),
                    self.decomp_base_log(),
                    self.decomp_level_count(),
                    self.modulus().as_f64(),
                ),
                gf => panic!("Unsupported grouping factor: {gf}"),
            },
        };

        let output_lwe_dimension = self
            .output_glwe_size()
            .to_glwe_dimension()
            .to_equivalent_lwe_dimension(self.output_polynomial_size());

        *output = NoiseSimulationLwe::new(
            output_lwe_dimension,
            Variance(accumulator.variance_per_occupied_slot().0 + br_additive_variance.0),
            accumulator.modulus(),
        );
    }
}
