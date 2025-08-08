use super::{lwe_multi_bit_bootstrap_key_size, MultiBitBootstrapKeyConformanceParams};
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::backward_compatibility::entities::lwe_multi_bit_bootstrap_key::FourierLweMultiBitBootstrapKeyVersions;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::math::fft::FourierPolynomialList;

use aligned_vec::{avec, ABox};
use tfhe_fft::c64;
use tfhe_versionable::Versionize;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[serde(bound(deserialize = "C: IntoContainerOwned"))]
#[versionize(FourierLweMultiBitBootstrapKeyVersions)]
pub struct FourierLweMultiBitBootstrapKey<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    input_lwe_dimension: LweDimension,
    glwe_size: GlweSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
    grouping_factor: LweBskGroupingFactor,
}

pub type FourierLweMultiBitBootstrapKeyOwned = FourierLweMultiBitBootstrapKey<ABox<[c64]>>;
pub type FourierLweMultiBitBootstrapKeyView<'a> = FourierLweMultiBitBootstrapKey<&'a [c64]>;
pub type FourierLweMultiBitBootstrapKeyMutView<'a> = FourierLweMultiBitBootstrapKey<&'a mut [c64]>;

impl<C: Container<Element = c64>> FourierLweMultiBitBootstrapKey<C> {
    pub fn from_container(
        data: C,
        input_lwe_dimension: LweDimension,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        grouping_factor: LweBskGroupingFactor,
    ) -> Self {
        assert!(
            input_lwe_dimension.0 % grouping_factor.0 == 0,
            "Multi Bit BSK requires input LWE dimension to be a multiple of {}",
            grouping_factor.0
        );
        let equivalent_multi_bit_dimension = input_lwe_dimension.0 / grouping_factor.0;
        let ggsw_count =
            equivalent_multi_bit_dimension * grouping_factor.ggsw_per_multi_bit_element().0;
        let expected_container_size = ggsw_count
            * fourier_ggsw_ciphertext_size(
                glwe_size,
                polynomial_size.to_fourier_polynomial_size(),
                decomposition_level_count,
            );
        assert_eq!(data.container_len(), expected_container_size);
        Self {
            fourier: FourierPolynomialList {
                data,
                polynomial_size,
            },
            input_lwe_dimension,
            glwe_size,
            decomposition_base_log,
            decomposition_level_count,
            grouping_factor,
        }
    }

    /// Return an iterator over the GGSW ciphertexts composing the key.
    pub fn ggsw_iter(
        &self,
    ) -> impl DoubleEndedIterator<Item = FourierGgswCiphertext<&'_ [C::Element]>> {
        self.fourier
            .data
            .as_ref()
            .chunks_exact(fourier_ggsw_ciphertext_size(
                self.glwe_size,
                self.fourier.polynomial_size.to_fourier_polynomial_size(),
                self.decomposition_level_count,
            ))
            .map(move |slice| {
                FourierGgswCiphertext::from_container(
                    slice,
                    self.glwe_size,
                    self.fourier.polynomial_size,
                    self.decomposition_base_log,
                    self.decomposition_level_count,
                )
            })
    }

    pub fn input_lwe_dimension(&self) -> LweDimension {
        self.input_lwe_dimension
    }

    pub fn multi_bit_input_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.input_lwe_dimension().0 / self.grouping_factor.0)
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.fourier.polynomial_size
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomposition_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomposition_level_count
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        LweDimension((self.glwe_size.0 - 1) * self.polynomial_size().0)
    }

    pub fn grouping_factor(&self) -> LweBskGroupingFactor {
        self.grouping_factor
    }

    pub fn data(self) -> C {
        self.fourier.data
    }

    pub fn as_view(&self) -> FourierLweMultiBitBootstrapKeyView<'_> {
        FourierLweMultiBitBootstrapKeyView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_ref(),
                polynomial_size: self.fourier.polynomial_size,
            },
            input_lwe_dimension: self.input_lwe_dimension,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
            grouping_factor: self.grouping_factor,
        }
    }

    pub fn as_mut_view(&mut self) -> FourierLweMultiBitBootstrapKeyMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        FourierLweMultiBitBootstrapKeyMutView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_mut(),
                polynomial_size: self.fourier.polynomial_size,
            },
            input_lwe_dimension: self.input_lwe_dimension,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
            grouping_factor: self.grouping_factor,
        }
    }

    pub fn as_polynomial_list(&self) -> FourierPolynomialList<&'_ [c64]> {
        FourierPolynomialList {
            data: self.fourier.data.as_ref(),
            polynomial_size: self.fourier.polynomial_size,
        }
    }

    pub fn as_mut_polynomial_list(&mut self) -> FourierPolynomialList<&'_ mut [c64]>
    where
        C: AsMut<[c64]>,
    {
        FourierPolynomialList {
            data: self.fourier.data.as_mut(),
            polynomial_size: self.fourier.polynomial_size,
        }
    }
}

impl FourierLweMultiBitBootstrapKeyOwned {
    pub fn new(
        input_lwe_dimension: LweDimension,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        grouping_factor: LweBskGroupingFactor,
    ) -> Self {
        assert!(
            input_lwe_dimension.0 % grouping_factor.0 == 0,
            "Multi Bit BSK requires input LWE dimension ({}) to be a multiple of {}",
            input_lwe_dimension.0,
            grouping_factor.0
        );
        let equivalent_multi_bit_dimension = input_lwe_dimension.0 / grouping_factor.0;
        let ggsw_count =
            equivalent_multi_bit_dimension * grouping_factor.ggsw_per_multi_bit_element().0;
        let container_size = ggsw_count
            * fourier_ggsw_ciphertext_size(
                glwe_size,
                polynomial_size.to_fourier_polynomial_size(),
                decomposition_level_count,
            );

        let boxed = avec![
            c64::default();
            container_size
        ]
        .into_boxed_slice();

        Self {
            fourier: FourierPolynomialList {
                data: boxed,
                polynomial_size,
            },
            input_lwe_dimension,
            glwe_size,
            decomposition_base_log,
            decomposition_level_count,
            grouping_factor,
        }
    }
}

impl<C: Container<Element = c64>> ParameterSetConformant for FourierLweMultiBitBootstrapKey<C> {
    type ParameterSet = MultiBitBootstrapKeyConformanceParams<u64>;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            fourier:
                FourierPolynomialList {
                    data,
                    polynomial_size,
                },
            input_lwe_dimension,
            glwe_size,
            decomposition_base_log,
            decomposition_level_count,
            grouping_factor,
        } = self;

        let MultiBitBootstrapKeyConformanceParams {
            decomp_base_log: expected_decomp_base_log,
            decomp_level_count: expected_decomp_level_count,
            input_lwe_dimension: expected_input_lwe_dimension,
            output_glwe_size: expected_output_glwe_size,
            polynomial_size: expected_polynomial_size,
            grouping_factor: expected_grouping_factor,
            ciphertext_modulus: _expected_ciphertext_modulus,
        } = parameter_set;

        if input_lwe_dimension.0 % grouping_factor.0 != 0 {
            return false;
        }

        data.container_len()
            == lwe_multi_bit_bootstrap_key_size(
                *input_lwe_dimension,
                *glwe_size,
                *polynomial_size,
                *decomposition_level_count,
                *grouping_factor,
            )
            .unwrap()
            && grouping_factor == expected_grouping_factor
            && decomposition_base_log == expected_decomp_base_log
            && decomposition_level_count == expected_decomp_level_count
            && input_lwe_dimension == expected_input_lwe_dimension
            && glwe_size == expected_output_glwe_size
            && polynomial_size == expected_polynomial_size
    }
}
