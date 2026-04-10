use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use crate::core_crypto::commons::traits::{Container, IntoContainerOwned, Split};
use crate::core_crypto::experimental::prelude::*;
use crate::core_crypto::fft_impl::fft64::math::fft::{
    par_convert_polynomials_list_to_fourier, FftView, FourierPolynomialList,
};
use crate::core_crypto::prelude::{ContiguousEntityContainer, UnsignedTorus};
use aligned_vec::{avec, ABox};
use dyn_stack::PodStack;
use itertools::izip;
use tfhe_fft::c64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(bound(deserialize = "C: IntoContainerOwned"))]
pub struct FourierCmLweBootstrapKey<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    input_lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
}

pub type FourierCmLweBootstrapKeyView<'a> = FourierCmLweBootstrapKey<&'a [c64]>;
pub type FourierCmLweBootstrapKeyMutView<'a> = FourierCmLweBootstrapKey<&'a mut [c64]>;

impl<C: Container<Element = c64>> FourierCmLweBootstrapKey<C> {
    pub fn from_container(
        data: C,
        input_lwe_dimension: LweDimension,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            input_lwe_dimension.0
                * polynomial_size.to_fourier_polynomial_size().0
                * decomposition_level_count.0
                * (glwe_dimension.0 + cm_dimension.0)
                * (glwe_dimension.0 + cm_dimension.0)
        );
        Self {
            fourier: FourierPolynomialList {
                data,
                polynomial_size,
            },
            input_lwe_dimension,
            glwe_dimension,
            cm_dimension,
            decomposition_base_log,
            decomposition_level_count,
        }
    }

    pub fn into_cm_ggsw_iter(self) -> impl DoubleEndedIterator<Item = FourierCmGgswCiphertext<C>>
    where
        C: Split,
    {
        self.fourier
            .data
            .split_into(self.input_lwe_dimension.0)
            .map(move |slice| {
                FourierCmGgswCiphertext::from_container(
                    slice,
                    self.glwe_dimension,
                    self.cm_dimension,
                    self.fourier.polynomial_size,
                    self.decomposition_base_log,
                    self.decomposition_level_count,
                )
            })
    }

    pub fn input_lwe_dimension(&self) -> LweDimension {
        self.input_lwe_dimension
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.fourier.polynomial_size
    }

    pub fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }

    pub fn cm_dimension(&self) -> CmDimension {
        self.cm_dimension
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomposition_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomposition_level_count
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        self.glwe_dimension
            .to_equivalent_lwe_dimension(self.polynomial_size())
    }

    pub fn data(self) -> C {
        self.fourier.data
    }

    pub fn as_view(&self) -> FourierCmLweBootstrapKeyView<'_> {
        FourierCmLweBootstrapKeyView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_ref(),
                polynomial_size: self.fourier.polynomial_size,
            },
            input_lwe_dimension: self.input_lwe_dimension,
            glwe_dimension: self.glwe_dimension,
            cm_dimension: self.cm_dimension,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }

    pub fn as_mut_view(&mut self) -> FourierCmLweBootstrapKeyMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        FourierCmLweBootstrapKeyMutView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_mut(),
                polynomial_size: self.fourier.polynomial_size,
            },
            input_lwe_dimension: self.input_lwe_dimension,
            glwe_dimension: self.glwe_dimension,
            cm_dimension: self.cm_dimension,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }
}

pub type FourierCmLweBootstrapKeyOwned = FourierCmLweBootstrapKey<ABox<[c64]>>;

impl FourierCmLweBootstrapKey<ABox<[c64]>> {
    pub fn new(
        input_lwe_dimension: LweDimension,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        let boxed = avec![
            c64::default();
            polynomial_size.to_fourier_polynomial_size().0
                * input_lwe_dimension.0
                * decomposition_level_count.0
                * (glwe_dimension.0 + cm_dimension.0)
                * (glwe_dimension.0 + cm_dimension.0)
        ]
        .into_boxed_slice();

        FourierCmLweBootstrapKey::from_container(
            boxed,
            input_lwe_dimension,
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            decomposition_base_log,
            decomposition_level_count,
        )
    }
}

impl FourierCmLweBootstrapKeyMutView<'_> {
    pub fn fill_with_forward_fourier<Scalar: UnsignedTorus>(
        mut self,
        coef_bsk: CmLweBootstrapKey<&'_ [Scalar]>,
        fft: FftView<'_>,
        stack: &mut PodStack,
    ) {
        for (fourier_ggsw, standard_ggsw) in
            izip!(self.as_mut_view().into_cm_ggsw_iter(), coef_bsk.iter())
        {
            fourier_ggsw.fill_with_forward_fourier(standard_ggsw, fft, stack);
        }
    }

    pub fn par_fill_with_forward_fourier<Scalar: UnsignedTorus>(
        self,
        coef_bsk: CmLweBootstrapKey<&'_ [Scalar]>,
        fft: FftView<'_>,
    ) {
        let polynomial_size = self.polynomial_size();
        par_convert_polynomials_list_to_fourier(
            self.data(),
            coef_bsk.into_container(),
            polynomial_size,
            fft,
        );
    }
}
