use super::super::math::fft::FftView;
use super::ggsw::{cmux, *};
use crate::core_crypto::backends::fft::private::math::fft::FourierPolynomialList;
use crate::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey;
use crate::core_crypto::commons::crypto::glwe::GlweCiphertext;
use crate::core_crypto::commons::crypto::lwe::LweCiphertext;
#[cfg(feature = "backend_fft_serialization")]
use crate::core_crypto::commons::math::tensor::ContainerOwned;
use crate::core_crypto::commons::math::tensor::{Container, Split};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::CastInto;
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, LutCountLog, LweDimension,
    ModulusSwitchOffset, MonomialDegree, PolynomialSize,
};
use aligned_vec::CACHELINE_ALIGN;
use concrete_fft::c64;
use dyn_stack::{DynStack, ReborrowMut, SizeOverflow, StackReq};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "backend_fft_serialization",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(deserialize = "C: ContainerOwned"))
)]
pub struct FourierLweBootstrapKey<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    key_size: LweDimension,
    glwe_size: GlweSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
}

pub type FourierLweBootstrapKeyView<'a> = FourierLweBootstrapKey<&'a [c64]>;
pub type FourierLweBootstrapKeyMutView<'a> = FourierLweBootstrapKey<&'a mut [c64]>;

impl<C: Container<Element = c64>> FourierLweBootstrapKey<C> {
    pub fn new(
        data: C,
        key_size: LweDimension,
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        assert_eq!(polynomial_size.0 % 2, 0);
        assert_eq!(
            data.container_len(),
            key_size.0 * polynomial_size.0 / 2
                * decomposition_level_count.0
                * glwe_size.0
                * glwe_size.0
        );
        Self {
            fourier: FourierPolynomialList {
                data,
                polynomial_size,
            },
            key_size,
            glwe_size,
            decomposition_base_log,
            decomposition_level_count,
        }
    }

    /// Returns an iterator over the GGSW ciphertexts composing the key.
    pub fn into_ggsw_iter(self) -> impl DoubleEndedIterator<Item = FourierGgswCiphertext<C>>
    where
        C: Split,
    {
        self.fourier
            .data
            .split_into(self.key_size.0)
            .map(move |slice| {
                FourierGgswCiphertext::new(
                    slice,
                    self.fourier.polynomial_size,
                    self.glwe_size,
                    self.decomposition_base_log,
                    self.decomposition_level_count,
                )
            })
    }

    pub fn key_size(&self) -> LweDimension {
        self.key_size
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

    pub fn data(self) -> C {
        self.fourier.data
    }

    pub fn as_view(&self) -> FourierLweBootstrapKeyView<'_> {
        FourierLweBootstrapKeyView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_ref(),
                polynomial_size: self.fourier.polynomial_size,
            },
            key_size: self.key_size,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }

    pub fn as_mut_view(&mut self) -> FourierLweBootstrapKeyMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        FourierLweBootstrapKeyMutView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_mut(),
                polynomial_size: self.fourier.polynomial_size,
            },
            key_size: self.key_size,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }
}

/// Returns the required memory for [`FourierLweBootstrapKeyMutView::fill_with_forward_fourier`].
pub fn fill_with_forward_fourier_scratch(fft: FftView<'_>) -> Result<StackReq, SizeOverflow> {
    fft.forward_scratch()
}

impl<'a> FourierLweBootstrapKeyMutView<'a> {
    /// Fills a bootstrapping key with the Fourier transform of a bootstrapping key in the standard
    /// domain.
    pub fn fill_with_forward_fourier<Scalar: UnsignedTorus + CastInto<usize>>(
        mut self,
        coef_bsk: StandardBootstrapKey<&'_ [Scalar]>,
        fft: FftView<'_>,
        mut stack: DynStack<'_>,
    ) {
        for (fourier_ggsw, standard_ggsw) in
            izip!(self.as_mut_view().into_ggsw_iter(), coef_bsk.ggsw_iter())
        {
            fourier_ggsw.fill_with_forward_fourier(standard_ggsw, fft, stack.rb_mut());
        }
    }
}

/// Returns the required memory for [`FourierLweBootstrapKeyView::blind_rotate`].
pub fn blind_rotate_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    StackReq::try_new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN)?
        .try_and(cmux_scratch::<Scalar>(glwe_size, polynomial_size, fft)?)
}

/// Returns the required memory for [`FourierLweBootstrapKeyView::bootstrap`].
pub fn bootstrap_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    blind_rotate_scratch::<Scalar>(glwe_size, polynomial_size, fft)?.try_and(
        StackReq::try_new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN)?,
    )
}

impl<'a> FourierLweBootstrapKeyView<'a> {
    pub fn blind_rotate<Scalar: UnsignedTorus + CastInto<usize>>(
        self,
        mut lut: GlweCiphertext<&'_ mut [Scalar]>,
        lwe: &[Scalar],
        fft: FftView<'_>,
        mut stack: DynStack<'_>,
    ) {
        let (lwe_body, lwe_mask) = lwe.split_last().unwrap();

        let lut_poly_size = lut.polynomial_size();
        let monomial_degree = pbs_modulus_switch(
            *lwe_body,
            lut_poly_size,
            ModulusSwitchOffset(0),
            LutCountLog(0),
        );
        lut.as_mut_view()
            .into_polynomial_list()
            .into_polynomial_iter()
            .for_each(|mut poly| {
                poly.update_with_wrapping_unit_monomial_div(MonomialDegree(monomial_degree));
            });

        // We initialize the ct_0 used for the successive cmuxes
        let mut ct0 = lut;

        for (lwe_mask_element, bootstrap_key_ggsw) in izip!(lwe_mask.iter(), self.into_ggsw_iter())
        {
            if *lwe_mask_element != Scalar::ZERO {
                let stack = stack.rb_mut();
                // We copy ct_0 to ct_1
                let (mut ct1, stack) = stack.collect_aligned(
                    CACHELINE_ALIGN,
                    ct0.as_view().into_container().iter().copied(),
                );
                let mut ct1 = GlweCiphertext::from_container(&mut *ct1, ct0.polynomial_size());

                // We rotate ct_1 by performing ct_1 <- ct_1 * X^{a_hat}
                for mut poly in ct1
                    .as_mut_view()
                    .into_polynomial_list()
                    .into_polynomial_iter()
                {
                    poly.update_with_wrapping_monic_monomial_mul(MonomialDegree(
                        pbs_modulus_switch(
                            *lwe_mask_element,
                            lut_poly_size,
                            ModulusSwitchOffset(0),
                            LutCountLog(0),
                        ),
                    ));
                }

                cmux(
                    ct0.as_mut_view(),
                    ct1.as_mut_view(),
                    bootstrap_key_ggsw,
                    fft,
                    stack,
                );
            }
        }
    }

    pub fn bootstrap<Scalar: UnsignedTorus + CastInto<usize>>(
        self,
        lwe_out: &mut [Scalar],
        lwe_in: &[Scalar],
        accumulator: GlweCiphertext<&'_ [Scalar]>,
        fft: FftView<'_>,
        stack: DynStack<'_>,
    ) {
        let (mut local_accumulator_data, stack) = stack.collect_aligned(
            CACHELINE_ALIGN,
            accumulator.as_view().into_container().iter().copied(),
        );
        let mut local_accumulator = GlweCiphertext::from_container(
            &mut *local_accumulator_data,
            accumulator.polynomial_size(),
        );
        self.blind_rotate(local_accumulator.as_mut_view(), lwe_in, fft, stack);
        local_accumulator.as_view().fill_lwe_with_sample_extraction(
            &mut LweCiphertext::from_container(&mut *lwe_out),
            MonomialDegree(0),
        );
    }
}

/// This function switches modulus for a single coefficient of a ciphertext,
/// only in the context of a PBS
///
/// offset: the number of msb discarded
/// lut_count_log: the right padding
pub fn pbs_modulus_switch<Scalar: UnsignedTorus + CastInto<usize>>(
    input: Scalar,
    poly_size: PolynomialSize,
    offset: ModulusSwitchOffset,
    lut_count_log: LutCountLog,
) -> usize {
    // First, do the left shift (we discard the offset msb)
    let mut output = input << offset.0;
    // Start doing the right shift
    output >>= Scalar::BITS - poly_size.log2().0 - 2 + lut_count_log.0;
    // Do the rounding
    output += output & Scalar::ONE;
    // Finish the right shift
    output >>= 1;
    // Apply the lsb padding
    output <<= lut_count_log.0;
    <Scalar as CastInto<usize>>::cast_into(output)
}
